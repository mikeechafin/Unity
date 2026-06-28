#!/usr/bin/env python3
"""
maintain_em_agents.py
Version: 2026-04-13 v1.0.101
Changes: Added safe_cleanup_agent_inst_temp_files() - deletes only orphaned 10-char temp response files ("Response From Agent: running") inside every agent_inst directory. Called after every host processing cycle.
"""
import sys
import os
import argparse
import subprocess
import time
import paramiko
import io
import logging
import threading
import fcntl
import atexit
import glob
import shlex
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from maa_libraries import (
    logger, get_db_connection_standalone, get_em_agent_targets,
    get_current_agent_home, is_host_reachable,
    AGENT_PORT, EMCLI_PATH, decrypt_data
)

emcli_lock = threading.Lock()

# =============================================================================
# LOGGING SETUP - Automatic rotation to prevent massive log growth
# =============================================================================
os.makedirs("output", exist_ok=True)
file_handler = RotatingFileHandler(
    "output/maintain_em_agents.log",
    maxBytes=1_000_000,      # 1 MB per file
    backupCount=5            # Keep 5 rotated files
)
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s'))
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

# =============================================================================
# SAFE TEMP FILE CLEANUP (Oracle EM Agent leaves these after emctl status agent)
# =============================================================================
def cleanup_agent_inst_temp_files(hostname, agent_inst_path):
    """Safe, targeted cleanup: only deletes exactly 10-character alphanumeric files containing 'Response From Agent: running' inside agent_inst directories."""
    if not agent_inst_path or not agent_inst_path.endswith("agent_inst"):
        return
    logger.info(f" → [TEMP CLEANUP] Scanning {agent_inst_path} on {hostname} for orphaned EM response files...")
    cmd = f"""
find {shlex.quote(agent_inst_path)} -type f -name '[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]' -print0 2>/dev/null |
xargs -0 grep -l 'Response From Agent: running' 2>/dev/null |
xargs -0 rm -f 2>/dev/null || true
"""
    out, err = run_as_oracle(hostname, cmd)
    if out or err:
        logger.info(f"   Cleaned temp response files in {agent_inst_path} on {hostname}")
    else:
        logger.debug(f"   No temp response files found in {agent_inst_path} on {hostname}")

# =============================================================================
# PASSWORD RESET FOR EXPIRED ACCOUNTS
# =============================================================================
def reset_expired_password(hostname, username):
    logger.warning(f" → Password expired detected for {username} on {hostname} - resetting to default")
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM ACCESS_CREDENTIALS
            WHERE USERNAME = :1
              AND COMPONENT_NAME IN (:2, 'default')
            ORDER BY NVL(LAST_UPDATED_DATE, CREATED_DATE) DESC NULLS LAST
        """, (username, hostname))
        row = cursor.fetchone()
        if row and row[0]:
            decrypted = decrypt_data(row[0].read())
            if decrypted:
                cmd = f"echo '{decrypted}' | passwd --stdin {username}"
                out, err = run_as_root(hostname, cmd)
                if not err:
                    logger.info(f" ✓ {username} password reset successfully on {hostname}")
                    return True
                logger.error(f" ✗ Reset failed: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

# =============================================================================
# DYNAMIC AGENT BASE DIRECTORY SELECTION
# =============================================================================
def determine_agent_base_dir(hostname):
    candidates = ["/u01", "/u02", "/x"]
    for base in candidates:
        base_dir = f"{base}/app/oracle/em/agent_vm04"
        out, err = run_as_oracle(hostname, f"mkdir -p {base_dir} 2>&1 && echo OK || echo FAIL")
        if "OK" not in out:
            continue
        df_out, _ = run_as_root(hostname, f"df -P {base} 2>/dev/null | tail -1 | awk '{{print $6}}'")
        if df_out.strip() != base:
            continue
        test_file = f"{base_dir}/.write_test_{int(time.time())}"
        out, err = run_as_oracle(hostname, f"touch {test_file} 2>&1 && rm -f {test_file} 2>&1 && echo OK || echo FAIL")
        if "OK" in out:
            logger.info(f" ✓ Using agent base directory: {base_dir} on {hostname}")
            return base_dir, f"Selected {base} (writable, separate mount)"
    logger.error(f" ✗ No suitable agent base directory found on {hostname}")
    return None, "No writable separate /u01 /u02 or /x found"

# =============================================================================
# ULTRA-AGGRESSIVE CLEANUP
# =============================================================================
def aggressive_cleanup_adatmp(hostname, agent_base_dir):
    logger.info(f" → [ULTRA CLEANUP] direct root rm -rf entire {agent_base_dir} + ADATMP on {hostname}")
    cmds = [
        f"rm -rf {agent_base_dir}/ADATMP_* 2>/dev/null || true",
        f"rm -rf {agent_base_dir}/* 2>/dev/null || true",
        f"rm -rf {agent_base_dir} 2>/dev/null || true",
        f"mkdir -p {agent_base_dir} && chown oracle:oinstall {agent_base_dir} && chmod 755 {agent_base_dir}"
    ]
    for cmd in cmds:
        run_as_root(hostname, cmd)
    time.sleep(3)
    ls_out, _ = run_as_oracle(hostname, f"ls {agent_base_dir} 2>/dev/null | wc -l || echo 0")
    logger.info(f"Post-cleanup dir empty check: {ls_out.strip()} items")
    return int(ls_out.strip()) == 0

def remove_agent_directory(hostname, agent_base_dir):
    logger.info(f" → Full ultra-cleanup of {agent_base_dir} on {hostname}")
    aggressive_cleanup_adatmp(hostname, agent_base_dir)
    return True

# =============================================================================
# PRE-FLIGHT CREDENTIAL VALIDATION
# =============================================================================
def validate_credentials(host):
    result = {
        "host": host,
        "oracle_ok": False,
        "root_ok": False,
        "oracle_method": "N/A",
        "root_method": "N/A"
    }
    subprocess.run(['ssh-keygen', '-R', host], capture_output=True, check=False, timeout=10)
    ssh_key_oracle = get_ssh_private_key_for_user(host, 'oracle')
    oracle_method = "key" if ssh_key_oracle else "password"
    output, err = run_as_oracle(host, "echo 'ORACLE_CRED_OK'")
    if "password has expired" in err.lower():
        reset_expired_password(host, 'oracle')
        output, err = run_as_oracle(host, "echo 'ORACLE_CRED_OK'")
    if not err and "ORACLE_CRED_OK" in output:
        result["oracle_ok"] = True
        result["oracle_method"] = oracle_method
        logger.info(f" ✓ oracle login OK on {host} ({oracle_method})")
    else:
        logger.warning(f" ✗ oracle login FAILED on {host}")
    ssh_key_root = get_ssh_private_key_for_user(host, 'root')
    root_method = "key" if ssh_key_root else "password"
    output, err = run_as_root(host, "echo 'ROOT_CRED_OK'")
    if "password has expired" in err.lower():
        reset_expired_password(host, 'root')
        output, err = run_as_root(host, "echo 'ROOT_CRED_OK'")
    if not err and "ROOT_CRED_OK" in output:
        result["root_ok"] = True
        result["root_method"] = root_method
        logger.info(f" ✓ root login OK on {host} ({root_method})")
    else:
        logger.warning(f" ✗ root login FAILED on {host}")
    return result

# =============================================================================
# SMART EMCLI LOGIN
# =============================================================================
def is_emcli_logged_in():
    try:
        result = subprocess.run(f"{EMCLI_PATH} list_emcli_instances", shell=True, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return False
        output = result.stdout + result.stderr
        return "Last logged in user : SYSMAN" in output or "Last logged in user: SYSMAN" in output
    except Exception:
        return False

def safe_emcli_login():
    with emcli_lock:
        if is_emcli_logged_in():
            logger.info(" ✓ EMCLI session already active")
            return True
        logger.info(" → EMCLI login required...")
        sysman_pass = get_sysman_password()
        if not sysman_pass:
            logger.error(" ✗ sysman credential not found")
            return False
        login_cmd = f"{EMCLI_PATH} login -username=sysman -password={sysman_pass}"
        try:
            result = subprocess.run(login_cmd, shell=True, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and "Login successful" in result.stdout:
                logger.info(" → EMCLI login successful")
                return True
            logger.error(f" ✗ EMCLI login failed: {result.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f" ✗ EMCLI login exception: {e}")
            return False

# =============================================================================
# CREDENTIAL HELPERS
# =============================================================================
def get_sysman_password():
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM ACCESS_CREDENTIALS
            WHERE USERNAME = 'sysman'
            ORDER BY CASE WHEN COMPONENT_TYPE = 'OMS' THEN 0 ELSE 1 END
        """)
        row = cursor.fetchone()
        if not row or not row[0]:
            logger.error("sysman credential not found")
            return None
        decrypted = decrypt_data(row[0].read())
        if decrypted:
            logger.info("sysman password decrypted successfully")
            return decrypted
        logger.error("Failed to decrypt sysman password")
        return None
    finally:
        cursor.close()
        conn.close()

def format_openssh_key(raw_key):
    if not raw_key:
        return None
    if isinstance(raw_key, bytes):
        raw_key = raw_key.decode('utf-8', errors='ignore')
    lines = [line.strip() for line in raw_key.replace('\r\n', '\n').replace('\r', '\n').split('\n') if line.strip()]
    if not lines or not lines[0].startswith('-----BEGIN'):
        return None
    header = lines[0]
    footer = lines[-1] if lines[-1].startswith('-----END') else '-----END OPENSSH PRIVATE KEY-----'
    b64_content = ''.join(line for line in lines[1:-1] if not line.startswith('-----'))
    wrapped = '\n'.join(b64_content[i:i+70] for i in range(0, len(b64_content), 70))
    return f"{header}\n{wrapped}\n{footer}\n"

def get_ssh_private_key_for_user(hostname, username):
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        for comp_type in ['PHYSICAL_HOST', 'GUEST']:
            cursor.execute("""
                SELECT ENCRYPTED_KEY
                FROM ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = :1
                  AND COMPONENT_NAME = :2
                  AND USERNAME = :3
                ORDER BY NVL(LAST_UPDATED_DATE, CREATED_DATE) DESC NULLS LAST
            """, (comp_type, hostname, username))
            row = cursor.fetchone()
            if row and row[0]:
                key = decrypt_data(row[0].read())
                if key:
                    cleaned = format_openssh_key(key)
                    if cleaned and cleaned.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
                        return cleaned
        for comp_type in ['PHYSICAL_HOST', 'GUEST']:
            cursor.execute("""
                SELECT ENCRYPTED_KEY
                FROM ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = :1
                  AND COMPONENT_NAME = 'default'
                  AND USERNAME = :2
                ORDER BY NVL(LAST_UPDATED_DATE, CREATED_DATE) DESC NULLS LAST
            """, (comp_type, username))
            row = cursor.fetchone()
            if row and row[0]:
                key = decrypt_data(row[0].read())
                if key:
                    cleaned = format_openssh_key(key)
                    if cleaned and cleaned.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
                        return cleaned
        return None
    finally:
        cursor.close()
        conn.close()

# =============================================================================
# RUN AS USER
# =============================================================================
def run_as_user(hostname, command, username):
    subprocess.run(['ssh-keygen', '-R', hostname], capture_output=True, check=False, timeout=10)
    ssh_key = get_ssh_private_key_for_user(hostname, username)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if ssh_key:
            for key_class in [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey]:
                try:
                    pkey = key_class.from_private_key(io.StringIO(ssh_key))
                    ssh.connect(hostname, username=username, pkey=pkey, timeout=10)
                    logger.info(f" ✓ Connected as {username} using SSH key")
                    break
                except Exception:
                    continue
            else:
                logger.warning(f" SSH key could not be parsed for {username} - falling back to password")
                ssh.connect(hostname, username=username, timeout=10)
        else:
            ssh.connect(hostname, username=username, timeout=10)
        logger.info(f" Executing as {username}: {command}")
        _, stdout, stderr = ssh.exec_command(command, timeout=60)
        output = stdout.read().decode('utf-8', errors='ignore').strip()
        err = stderr.read().decode('utf-8', errors='ignore').strip()
        ssh.close()
        logger.info(f" Full output:\n{output}")
        if err:
            logger.info(f" Error:\n{err}")
            if "password has expired" in err.lower():
                reset_expired_password(hostname, username)
        return output, err
    except Exception as e:
        logger.error(f" SSH as {username} failed for {hostname}: {str(e)}")
        return "", str(e)

def run_as_oracle(hostname, command):
    return run_as_user(hostname, command, 'oracle')

def run_as_root(hostname, command):
    return run_as_user(hostname, command, 'root')

# =============================================================================
# NODE TYPE, SKIP, HYPERVISOR, GUESTS
# =============================================================================
def get_node_type(hostname):
    if not is_host_reachable(hostname):
        return "UNREACHABLE"
    full_output, _ = run_as_root(hostname, "imageinfo 2>&1")
    for line in full_output.splitlines():
        line_upper = line.upper()
        if "NODE TYPE" in line_upper or "ACTIVE NODE TYPE" in line_upper:
            if "NODE TYPE" in line_upper:
                node_type = line.split("Node type", 1)[-1].strip(": \t").upper()
            else:
                node_type = line.split("Active node type", 1)[-1].strip(": \t").upper()
            if any(x in node_type for x in ["STORAGE", "CELL"]):
                return "STORAGE"
            if node_type in ("KVMHOST", "DOM0"):
                return "KVMHOST"
    return "STANDALONE"

def should_skip_host(hostname):
    node_type = get_node_type(hostname)
    if node_type in ("STORAGE", "KVMHOST"):
        logger.info(f" Skipping {node_type} host: {hostname}")
        return True
    if "CEL" in hostname.upper():
        logger.info(f" Skipping storage server (cel in hostname): {hostname}")
        return True
    return False

def is_hypervisor(hostname):
    node_type = get_node_type(hostname)
    if node_type == "KVMHOST":
        logger.info(f" ✓ Real hypervisor detected: {hostname}")
        return True
    lower = hostname.lower()
    if "adm" in lower and "vm" not in lower:
        logger.info(f" ✓ Real hypervisor detected (name pattern): {hostname}")
        return True
    return False

def get_guests(hostname):
    guests = set()
    output, _ = run_as_oracle(hostname, "virsh list --all --name 2>/dev/null || echo ''")
    for line in output.splitlines():
        line = line.strip()
        if line and line != "Domain-0":
            guests.add(line)
    output, _ = run_as_oracle(hostname, "xl list 2>/dev/null | tail -n +2 | awk '{print $1}' || echo ''")
    for line in output.splitlines():
        line = line.strip()
        if line and line != "Domain-0":
            guests.add(line)
    return list(guests)

def process_host_parallel(host, agent_base_dir):
    result = {"host": host, "skip": False, "is_hypervisor": False, "guests": [], "healthy": False, "status": "", "action": None, "emctl_path": None}
    if not is_host_reachable(host):
        result["status"] = "Unreachable"
        return result
    if should_skip_host(host):
        result["skip"] = True
        return result
    if is_hypervisor(host):
        result["is_hypervisor"] = True
        result["guests"] = get_guests(host)
    healthy, status, emctl_path = check_em_agent_status(host, agent_base_dir)
    result["healthy"] = healthy
    result["status"] = status
    result["emctl_path"] = emctl_path
    if healthy:
        result["action"] = "ok"
    elif "No agent home found" in status:
        result["action"] = "deploy"
    elif "Not running" in status or "EM Configuration issue" in status:
        result["action"] = "restart"
    else:
        result["action"] = "failed"
    return result

# =============================================================================
# CLEANUP, RESTART, DEPLOY
# =============================================================================
def cleanup_old_agent(hostname):
    logger.info(f" → Cleaning EM repository entries for {hostname}")
    run_as_oracle(hostname, "pkill -9 -f emagent 2>/dev/null || true")
    discover_cmd = f'{EMCLI_PATH} get_targets -targets="oracle_emd" -format="name:csv" | grep "{hostname}" | awk -F, \'{{print $4}}\' | head -1'
    discover_result = subprocess.run(discover_cmd, shell=True, capture_output=True, text=True)
    target_name = discover_result.stdout.strip()
    if target_name:
        delete_cmd = f'{EMCLI_PATH} delete_target -name="{target_name}" -type=oracle_emd -delete_monitored_targets'
        subprocess.run(delete_cmd, shell=True, capture_output=True)
    subprocess.run(f"{EMCLI_PATH} sync", shell=True, capture_output=True)
    return True

def restart_agent(hostname, emctl_path):
    logger.info(f" → Starting restart attempt for {hostname}")
    if not emctl_path:
        logger.error(f" → No emctl_path - cannot restart")
        return False
    find_cmd = f"find {emctl_path} -name emctl -type f | head -1"
    output, _ = run_as_oracle(hostname, find_cmd)
    emctl_full = output.strip()
    if not emctl_full:
        emctl_full = emctl_path.rstrip('/') + '/core/bin/emctl'
    command = f"{emctl_full} start agent 2>&1"
    output, err = run_as_oracle(hostname, command)
    logger.info(f" emctl start output:\n{output}")
    if err:
        logger.info(f" emctl start error:\n{err}")
    logger.info(f" → Waiting 60 seconds for agent to become ready...")
    time.sleep(60)
    status_cmd = f"{emctl_full} status agent"
    for _ in range(3):
        status_output, _ = run_as_oracle(hostname, status_cmd)
        logger.info(f" emctl status poll:\n{status_output}")
        if "Agent is Running and Ready" in status_output or "Running and Ready" in status_output:
            logger.info(f" ✓ Agent started successfully on {hostname}")
            return True
        time.sleep(20)
    logger.warning(f" → Restart attempt failed with EM Configuration issue - falling back to full deploy")
    return False

def deploy_new_agent(hostname, agent_base_dir):
    logger.info(f" → Deploying new agent to {hostname} using base dir {agent_base_dir} (VM_ROOT_CRED)")
    try:
        subprocess.run(f"{EMCLI_PATH} logout", shell=True, capture_output=True, timeout=10)
    except subprocess.TimeoutExpired:
        logger.warning("emcli logout timed out - killing")
        subprocess.run("pkill -9 -f emcli", shell=True)
    if not safe_emcli_login():
        return False
    cleanup_old_agent(hostname)
    remove_agent_directory(hostname, agent_base_dir)
    logger.info(" → Using VM_ROOT_CRED for deployment")
    cmd_submit = f'{EMCLI_PATH} submit_add_host -host_names="{hostname}" -platform=226 -credential_name=AGENT_HOST_CRED -installation_base_directory="{agent_base_dir}" -port={AGENT_PORT} -root_credential_name=VM_ROOT_CRED'
    for attempt in range(2):
        try:
            result = subprocess.run(cmd_submit, shell=True, capture_output=True, text=True, timeout=300)
            stdout = result.stdout.strip()
            if result.returncode != 0:
                logger.error(f" ✗ Submit failed (exit {result.returncode})")
                if attempt == 0:
                    logger.info(" → Retrying after extra cleanup")
                    aggressive_cleanup_adatmp(hostname, agent_base_dir)
                    continue
                return False
            session_name = None
            for line in stdout.splitlines():
                line = line.strip()
                if 'session with the name "' in line:
                    start = line.find('"') + 1
                    end = line.rfind('"')
                    if start > 0 and end > start:
                        session_name = line[start:end]
                        break
            if not session_name:
                logger.error(" ✗ Could not extract session name")
                return False
            logger.info(f" → Session submitted: {session_name}")
            logger.info(f" → Starting long poll for {session_name} (up to 60 minutes)...")
            max_attempts = 120
            start_time = time.time()
            root_sh_done = False
            for poll in range(max_attempts):
                time.sleep(30)
                if time.time() - start_time > 1800:
                    logger.warning(" → Deploy timeout reached - aborting poll")
                    return False
                status_cmd = f"{EMCLI_PATH} get_add_host_status -session_name={session_name} -details"
                status_result = subprocess.run(status_cmd, shell=True, capture_output=True, text=True)
                status_out = status_result.stdout.strip()
                logger.info(f"\n[Attempt {poll+1:02d}/{max_attempts}] {datetime.now().strftime('%H:%M:%S')}")
                for line in status_out.splitlines():
                    if line.strip():
                        logger.info(line.strip())
                # === OMS PLUGIN ZIP MISSING DETECTION (v1.0.97+) ===
                if "PROV-16011" in status_out or ("No such file or directory" in status_out and "zip" in status_out.lower()):
                    logger.error(" ✗ OMS PLUGIN ZIP MISSING - This is an OMS-side staging issue. Run 'emcli setup_agentpush' on the OMS host or manually copy the missing 24.1.0.0.0_Plugins_226.zip and AgentCore_226.zip files to the agentpush directory.")
                    return False
                warning_detected = (
                    "completed with warnings" in status_out.lower() or
                    "Privilege Delegation" in status_out or
                    "null" in status_out.lower() or
                    "does not have the privileges to run commands as user" in status_out.lower() or
                    "prerequisite" in status_out.lower() or
                    "warning" in status_out.lower()
                )
                if warning_detected:
                    logger.warning(" → Detected prereq warning state - AGGRESSIVE BYPASS ACTIVATED")
                    if not root_sh_done:
                        root_sh_path = f"{agent_base_dir}/root.sh"
                        check_cmd = f"[ -f {root_sh_path} ] && echo EXISTS || echo MISSING"
                        out, _ = run_as_root(hostname, check_cmd)
                        if "EXISTS" in out:
                            root_out, root_err = run_as_root(hostname, root_sh_path)
                            if root_err:
                                logger.warning(f" root.sh had warnings: {root_err}")
                            else:
                                logger.info(" ✓ root.sh executed successfully (first time)")
                        else:
                            logger.info(" → root.sh not yet present - skipping for now")
                        root_sh_done = True
                    continue_cmd = f"{EMCLI_PATH} continue_add_host -session_name={session_name} -continue_ignoring_failed_hosts"
                    for bypass in range(5):
                        cont_result = subprocess.run(continue_cmd, shell=True, capture_output=True, text=True, timeout=30)
                        logger.info(f" → continue_add_host (ignore failed hosts) attempt {bypass+1}/5: {cont_result.stdout.strip() or cont_result.stderr.strip()}")
                        time.sleep(8)
                    logger.info(" → Aggressive bypass complete - warnings ignored, deployment should advance")
                if "Agent Deployment Succeeded" in status_out or "Succeeded Succeeded Succeeded" in status_out:
                    logger.info(f" ✓ Session {session_name} SUCCEEDED")
                    root_sh_path = f"{agent_base_dir}/root.sh"
                    check_cmd = f"[ -f {root_sh_path} ] && echo EXISTS || echo MISSING"
                    out, _ = run_as_root(hostname, check_cmd)
                    if "EXISTS" in out:
                        root_out, root_err = run_as_root(hostname, root_sh_path)
                        if root_err:
                            logger.warning(f" root.sh had warnings: {root_err}")
                        else:
                            logger.info(" ✓ root.sh executed successfully")
                    return True
                if "Failed" in status_out and "not empty" not in status_out.lower():
                    logger.error(f" ✗ Real failure detected")
                    return False
                logger.info(f" → Job still in progress - continuing poll...")
            if attempt == 0:
                logger.info(" → Retrying deploy after full cleanup")
                continue
            logger.error(f" ✗ Session {session_name} TIMED OUT")
            return False
        except Exception as e:
            logger.error(f" ✗ Exception during deploy: {str(e)}")
            if attempt == 0:
                continue
            return False
    return False

def check_em_agent_status(hostname, agent_base_dir):
    if not is_host_reachable(hostname):
        return False, "Unreachable", None
    emctl_path = get_current_agent_home(hostname)
    if not emctl_path:
        logger.info(f" → Library returned no home - doing explicit directory check on {hostname}")
        dir_check_cmd = f"[ -d {agent_base_dir} ] && echo 'exists' || echo 'not found'"
        dir_output, _ = run_as_oracle(hostname, dir_check_cmd)
        if "exists" in dir_output.lower():
            emctl_path = agent_base_dir
            logger.info(f" ✓ Explicit check found agent home at {agent_base_dir}")
        else:
            return False, "No agent home found", None
    find_cmd = f"find {emctl_path} -name emctl -type f | head -1"
    output, _ = run_as_oracle(hostname, find_cmd)
    emctl_full = output.strip()
    if not emctl_full:
        logger.info(f" → No emctl found in {emctl_path} - treating as broken install")
        return False, "No agent home found", None
    try:
        command = f"{emctl_full} status agent"
        output, err = run_as_oracle(hostname, command)
        logger.info(f" emctl status output:\n{output}")
        if "Agent is Running and Ready" in output or "Running and Ready" in output:
            return True, "Running and Ready", emctl_path
        else:
            return False, f"Not running ({output[:300]})", emctl_path
    except Exception as e:
        logger.error(f" Check error for {hostname}: {str(e)}")
        return False, "Check error", None

def main():
    parser = argparse.ArgumentParser(description="Maintain Oracle EM 24ai Agents")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without changes")
    parser.add_argument("--host", type=str, help="Test only this single hostname (for debugging)")
    parser.add_argument("--parallel", type=int, default=20, help="Number of parallel threads for status checks (default 20, max 50)")
    args = parser.parse_args()
    if args.parallel > 50:
        args.parallel = 50
        logger.warning(" Parallel limited to 50 threads for safety")

    # =============================================================================
    # SINGLETON LOCK: ensure only 1 copy runs at the same time
    # =============================================================================
    lock_path = "/tmp/maintain_em_agents.lock"
    try:
        lock_fd = open(lock_path, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()) + '\n')
        lock_fd.flush()
        def unlock_on_exit():
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
            except:
                pass
        atexit.register(unlock_on_exit)
        logger.info(" ✓ Singleton lock acquired - no other instance running")
    except BlockingIOError:
        logger.error(" ✗ Another instance of maintain_em_agents.py is already running - exiting")
        sys.exit(1)
    except Exception as e:
        logger.error(f" ✗ Lock error: {e}")
        sys.exit(1)

    logger.info(" → Logging into EMCLI at script start...")
    try:
        subprocess.run(f"{EMCLI_PATH} logout", shell=True, capture_output=True, timeout=10)
    except subprocess.TimeoutExpired:
        logger.warning("emcli logout timed out - killing")
        subprocess.run("pkill -9 -f emcli", shell=True)
    sysman_pass = get_sysman_password()
    if not sysman_pass:
        logger.error(" ✗ sysman credential not found in ACCESS_CREDENTIALS - aborting")
        return
    login_cmd = f"{EMCLI_PATH} login -username=sysman -password={sysman_pass}"
    try:
        result = subprocess.run(login_cmd, shell=True, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.error(f" ✗ EMCLI login failed: {result.stderr}")
            return
        logger.info(" → EMCLI login successful at script start")
    except Exception as e:
        logger.error(f" ✗ Login exception at script start: {e}")
        return
    logger.info(" → Running emcli sync once at start...")
    subprocess.run(f"{EMCLI_PATH} sync", shell=True, capture_output=True, timeout=30)

    # OMS pre-flight check
    logger.info(" → Checking OMS agentpush staging directory...")
    try:
        check_cmd = f"{EMCLI_PATH} get_agentpush_status"
        res = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if "failed" in res.stdout.lower() or "zip" in res.stdout.lower():
            logger.warning(" ⚠️ OMS agentpush staging appears broken (missing plugin zips). Deployments will fail until fixed.")
    except:
        pass

    logger.info(f"=== EM 24ai Agent Maintenance START {'[DRY-RUN]' if args.dry_run else ''} "
                f"{'[SINGLE HOST: ' + args.host + ']' if args.host else ''} "
                f"[PARALLEL: {args.parallel}] at {datetime.now()} ===")
    if args.host:
        targets = [args.host.strip()]
        logger.info(f"Single-host mode: only checking {args.host}")
    else:
        conn = get_db_connection_standalone()
        targets = get_em_agent_targets(conn)
        conn.close()
        logger.info(f"Found {len(targets)} targets from database")
    logger.info(" → Running pre-flight credential validation for all hosts...")
    cred_results = []
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        future_to_host = {executor.submit(validate_credentials, host): host for host in targets}
        for future in as_completed(future_to_host):
            res = future.result()
            cred_results.append(res)
    logger.info("\n=== CREDENTIAL VALIDATION SUMMARY ===")
    logger.info(f"{'Host':<50} {'Oracle':<15} {'Root':<15} {'Oracle Method':<15} {'Root Method':<15}")
    logger.info("-" * 110)
    good_hosts = []
    for r in cred_results:
        o_status = "OK" if r["oracle_ok"] else "FAIL"
        r_status = "OK" if r["root_ok"] else "FAIL"
        logger.info(f"{r['host']:<50} {o_status:<15} {r_status:<15} {r['oracle_method']:<15} {r['root_method']:<15}")
        if r["oracle_ok"]:
            good_hosts.append(r["host"])
    logger.info("=" * 110)
    if not good_hosts:
        logger.error(" ✗ No hosts passed credential validation - aborting")
        return
    logger.info(f" → Proceeding with {len(good_hosts)} hosts that have valid oracle credentials")
    targets = good_hosts
    host_to_base_dir = {}
    for host in targets:
        base_dir, reason = determine_agent_base_dir(host)
        if base_dir:
            host_to_base_dir[host] = base_dir
        else:
            logger.warning(f" ✗ Skipping {host} - {reason}")
    targets = list(host_to_base_dir.keys())
    logger.info(f" → Proceeding with {len(targets)} hosts that have valid base directory")
    logger.info(f" → Parallel processing of {len(targets)} hosts with {args.parallel} threads...")
    host_results = []
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        future_to_host = {executor.submit(process_host_parallel, host, host_to_base_dir[host]): host for host in targets}
        for future in as_completed(future_to_host):
            res = future.result()
            host_results.append(res)
    for res in host_results:
        if res["is_hypervisor"]:
            for guest in res["guests"]:
                if guest not in targets and guest in host_to_base_dir:
                    targets.append(guest)
                    logger.info(f" ✓ Added discovered guest {guest} from hypervisor {res['host']}")
    ok = unreachable = no_home = not_running = failed = oms_issue = 0
    host_reports = []
    for res in host_results:
        host = res["host"]
        base_dir = host_to_base_dir.get(host)
        if not base_dir:
            continue
        if res["skip"]:
            report = {
                "host": host,
                "base_dir": base_dir,
                "node_type": get_node_type(host),
                "oracle_cred": "Skipped",
                "root_cred": "Skipped",
                "agent_status": "Skipped",
                "action": "Skipped",
                "outcome": "Skipped",
                "reason": "Hypervisor / Storage / Cell"
            }
            host_reports.append(report)
            continue
        if res["status"] == "Unreachable":
            report = {
                "host": host,
                "base_dir": base_dir,
                "node_type": get_node_type(host),
                "oracle_cred": "N/A",
                "root_cred": "N/A",
                "agent_status": "Unreachable",
                "action": "None",
                "outcome": "Failed",
                "reason": "Host unreachable"
            }
            host_reports.append(report)
            unreachable += 1
            continue
        healthy = res["healthy"]
        status = res["status"]
        action = res["action"]
        emctl_path = res.get("emctl_path")
        outcome = "Success"
        reason = "Agent is Running and Ready"
        if healthy:
            logger.info(f"✅ {host:45} Running and Ready")
            ok += 1
        else:
            if action == "deploy":
                logger.warning(f"⚠️ {host:45} No agent home found → deploying")
                no_home += 1
                success = deploy_new_agent(host, base_dir) if not args.dry_run else False
                outcome = "Success" if success else "Failed"
                reason = "Deployed successfully" if success else "Deployment failed (OMS Plugin Missing)"
                if "OMS PLUGIN ZIP MISSING" in reason:
                    oms_issue += 1
            elif action == "restart":
                logger.warning(f"⚠️ {host:45} {status} → attempting start first")
                not_running += 1
                success = restart_agent(host, emctl_path) if not args.dry_run else False
                if not success:
                    logger.info(f" → Restart failed - switching to full deploy for {host}")
                    success = deploy_new_agent(host, base_dir) if not args.dry_run else False
                outcome = "Success" if success else "Failed"
                reason = "Agent restarted" if success else "Restart + Deploy failed"
            else:
                logger.error(f"⚠️ {host:45} {status}")
                failed += 1
                outcome = "Failed"
                reason = status
        report = {
            "host": host,
            "base_dir": base_dir,
            "node_type": get_node_type(host),
            "oracle_cred": "OK",
            "root_cred": "OK",
            "agent_status": status,
            "action": action,
            "outcome": outcome,
            "reason": reason
        }
        host_reports.append(report)

        # SAFE TEMP FILE CLEANUP after every host
        agent_inst_path = f"{base_dir}/agent_inst" if base_dir else None
        if agent_inst_path:
            cleanup_agent_inst_temp_files(host, agent_inst_path)

    # =====================================================================
    # FINAL DETAILED REPORT
    # =====================================================================
    report_file = f"output/final_report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
    with open(report_file, "w") as f:
        f.write(f"EM Agent Maintenance Final Report - {datetime.now()}\n")
        f.write("=" * 140 + "\n")
        f.write(f"{'Host':<50} {'Base Dir':<45} {'Node Type':<12} {'Agent Status':<25} {'Action':<10} {'Outcome':<10} Reason\n")
        f.write("-" * 140 + "\n")
        for r in host_reports:
            line = f"{r['host']:<50} {r['base_dir']:<45} {r['node_type']:<12} {r['agent_status']:<25} {r['action']:<10} {r['outcome']:<10} {r['reason']}"
            print(line)
            f.write(line + "\n")
    logger.info(f"\n=== DETAILED FINAL REPORT SAVED TO: {report_file} ===")
    logger.info(f"=== SUMMARY | OK: {ok} | Unreachable: {unreachable} | "
                f"No agent home: {no_home} | Not running: {not_running} | "
                f"Failed: {failed} | OMS Issue: {oms_issue} | Total: {len(host_reports)} ===")
    logger.info("=== RECOMMENDATION: Run 'emcli setup_agentpush' on ALL OMS hosts to fix the missing plugin zip files ===")

    # =============================================================================
    # KEEP ONLY LAST 2 FINAL REPORTS
    # =============================================================================
    logger.info(" → Cleaning old final reports (keeping only the newest 2)...")
    reports = sorted(
        glob.glob("output/final_report_*.txt"),
        key=os.path.getmtime,
        reverse=True
    )
    for old_report in reports[2:]:
        try:
            os.remove(old_report)
            logger.info(f"   Deleted old report: {old_report}")
        except Exception as e:
            logger.warning(f"   Could not delete {old_report}: {e}")

if __name__ == "__main__":
    main()
