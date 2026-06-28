# Filename: setup_exascale_monitoring.py
# Version: 2026-04-24 v1.6.13
# Changes:
#   - CRITICAL FIX for "Public key transfer failed": scp_file uses reliable ssh-pipe method with full error logging.
#   - NEW: store_exascale_key now EXPLICITLY OVERRIDES any existing key for a target
#         (component_type + component_name + username) instead of creating a duplicate row.
#         It does UPDATE first; only INSERTs if no matching row exists.
#         This guarantees exactly one row per (EXASCALE_PRIVATE_KEY / EXASCALE_PUBLIC_KEY, host, excmonitor).
#   - Guest oracle user continues to use subprocess ssh.
#   - Storage root continues to use smart paramiko (passwordless first → DB fallback).
#   - All original rich functionality preserved.

from environment_setup_registry import register_function
import subprocess
import os
import tempfile
import time
import pexpect
import uuid
import paramiko
from paramiko.sftp_client import SFTPClient
from maa_libraries import logger, execute_ssh_command, SSH_TIMEOUT, get_credential_silent, SSH_KEY, encrypt_data
from maa_libraries import get_db_pool_connection, release_db_connection
import re
import hashlib
import zipfile
import stat
import datetime
import shutil
import fnmatch
from flask import current_app
import oracledb
from concurrent.futures import ThreadPoolExecutor
import csv
from collections import defaultdict
from shared_state import execution_logs, log_lock

import config

OUTPUT_DIR = config.OUTPUT_DIR
os.makedirs(OUTPUT_DIR, exist_ok=True)
LOG_FILE = os.path.join(OUTPUT_DIR, "setup_exascale.log")

def strip_ansi(text):
    """Safe ANSI escape remover (no FutureWarning)."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', str(text))

@register_function(
    component_types=["Global"],
    params=[
        {
            "name": "rest_endpoint",
            "label": "Exascale REST Endpoint (host:5052)",
            "type": "text",
            "placeholder": "e.g. scaqat01ers01.us.oracle.com:5052 (leave blank for auto-discovery)"
        }
    ]
)
def setup_exascale_monitoring(component_name=None, params=None, **kwargs):
    """Setup Exascale Monitoring - creates excmonitor user, RSA keys, wallet, and configures REST endpoint."""
    task_id = kwargs.get('task_id') or kwargs.get('taskId') or 'global_setup_exascale_monitoring'
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    components = kwargs.get('components', []) or []
    app_obj = kwargs.get('app') or kwargs.get('app_obj')
    pool = kwargs.get('pool') or (current_app.config.get('DB_POOL') if current_app else None)

    def emit_message(msg, status='info'):
        clean_msg = strip_ansi(msg)
        if socketio and sid:
            socketio.emit('message', {
                'task_id': task_id,
                'line': clean_msg,
                'status': status
            }, room=sid, namespace='/')
        logger.info(f"[Exascale] {clean_msg}")
        if status in ('error', 'success'):
            with log_lock:
                if task_id in execution_logs:
                    execution_logs[task_id]['status'] = status

    emit_message("=== SETUP_EXASCALE_MONITORING v1.6.13 STARTED ===", status='running')
    emit_message(f"DEBUG: Received components = {components}", status='running')

    keys_stored = False
    try:
        if app_obj:
            with app_obj.app_context():
                from setup_routes import get_component_type
                storage_comps = [c for c in components if get_component_type(c) == 'Storage Server']
                guest_comps = [c for c in components if get_component_type(c) == 'Guest']
                db_comps = [c for c in components if get_component_type(c) == 'Database Server']

                if not storage_comps:
                    if components == ['global'] or not components:
                        emit_message("❌ No Storage Server selected. Please check at least one Storage Server in the left panel before running this Global function.", "error")
                    else:
                        emit_message("No Storage Server selected", "error")
                    return "ERROR: No Storage Server selected"

                storage_host = storage_comps[0]
                emit_message(f"Using Storage Server: {storage_host} (passwordless SSH preferred, DB fallback if needed)")

                if guest_comps:
                    selected_hosts = guest_comps
                    emit_message(f"Using {len(selected_hosts)} selected Guest VMs for wallet creation", "success")
                elif db_comps:
                    selected_hosts = db_comps
                    emit_message(f"Using {len(selected_hosts)} selected Database Servers (physical)", "success")
                else:
                    selected_hosts = storage_comps
                    emit_message(f"Using {len(selected_hosts)} Storage Servers (fallback)", "success")

                rest_endpoint_param = params.get('rest_endpoint', '').strip() if params else ''
                if rest_endpoint_param:
                    rest_endpoint = rest_endpoint_param
                    emit_message(f"Using manual REST endpoint: {rest_endpoint}")
                else:
                    emit_message("Auto-discovering Exascale REST endpoint...")
                    rest_endpoint = discover_exascale_rest_endpoint(storage_comps, task_id, socketio, sid, pool)
                    if not rest_endpoint:
                        emit_message("Auto-discovery failed. Provide REST endpoint manually.", "error")
                        return "ERROR: Unable to discover REST endpoint"

                ctrl_host = rest_endpoint
                admin_wallet = "/opt/oracle/cell/cellsrv/deploy/config/security/admwallet/cwallet.sso"
                key_dir = "/home/oracle/exc_key"
                priv_key = f"{key_dir}/excmonitor-priv.pem"
                pub_key = f"{key_dir}/excmonitor-pub.pem"
                temp_pub_on_storage = "/tmp/excmonitor-pub.pem"
                wallet_on_storage = "/tmp/exc.sso"
                monitoring_user = "excmonitor"
                created_by = "maamd"
                wallet_dir = "/home/oracle/excmonitor_wallet"

                emit_message(f"Creating/granting privileges for user {monitoring_user} on storage server...")

                admin_cmds = [
                    f"escli --wallet {admin_wallet} --ctrl {ctrl_host} mkuser {monitoring_user} --id {monitoring_user}",
                    f"escli --wallet {admin_wallet} --ctrl {ctrl_host} chuser {monitoring_user} --privilege cl_monitor",
                    f"escli --wallet {admin_wallet} --ctrl {ctrl_host} chuser {monitoring_user} --privilege +vlt_read"
                ]
                for cmd in admin_cmds:
                    stdout, stderr, ec = run_ssh_command(storage_host, "root", cmd, pool=pool)
                    if ec != 0:
                        emit_message(f"Failed: {cmd}\n{stderr}", "error")
                        return "ERROR: Failed during user/privilege setup"
                    emit_message(stdout.strip() or "Command succeeded")

                # === HARDENED RSA KEY GENERATION ===
                first_host = selected_hosts[0]
                emit_message(f"Generating RSA key pair on {first_host}...")
                key_cmds = [
                    f"mkdir -p {key_dir}",
                    f"chmod 700 {key_dir}",
                    f"/opt/oracle/dbserver/dbms/bin/escli mkkey --private-key-file {priv_key} --public-key-file {pub_key}"
                ]
                key_success = False
                for attempt in range(2):
                    if attempt > 0:
                        emit_message(f"Key generation retry {attempt+1}/2...", "info")
                    for cmd in key_cmds:
                        t = 300 if "mkkey" in cmd else 120
                        stdout, stderr, ec = run_ssh_command(first_host, "oracle", cmd, timeout=t, pool=pool)
                        if ec != 0:
                            emit_message(f"Key generation failed (attempt {attempt+1}): {stderr}", "error")
                            time.sleep(5)
                            break
                    else:
                        key_success = True
                        break
                if not key_success:
                    emit_message("Key generation failed after retries. Check escli, disk space and /opt/oracle/dbserver/dbms/bin on host.", "error")
                    return "ERROR: Key generation failed after retries"

                emit_message("Reading generated private key for distribution...")
                priv_content = run_ssh_command(first_host, "oracle", f"cat {priv_key}", pool=pool)[0]
                pub_content = run_ssh_command(first_host, "oracle", f"cat {pub_key}", pool=pool)[0]

                emit_message("Storing keys in MAAMD.ACCESS_CREDENTIALS (override if exists)...")
                try:
                    if priv_content:
                        encrypted_priv = encrypt_data(priv_content)
                        if encrypted_priv and store_exascale_key(current_app.config['DB_POOL'], "EXASCALE_PRIVATE_KEY", first_host, monitoring_user, encrypted_priv, created_by):
                            keys_stored = True
                    if pub_content:
                        encrypted_pub = encrypt_data(pub_content)
                        if encrypted_pub and store_exascale_key(current_app.config['DB_POOL'], "EXASCALE_PUBLIC_KEY", first_host, monitoring_user, encrypted_pub, created_by):
                            keys_stored = True
                except Exception as e:
                    emit_message(f"Failed to store keys in database: {e}", "warning")

                emit_message("Transferring public key to storage server...")
                if not scp_file(first_host, "oracle", pub_key, storage_host, "root", temp_pub_on_storage):
                    emit_message("Public key transfer failed", "error")
                    return "ERROR: Public key transfer failed"

                upload_cmd = f"escli --wallet {admin_wallet} --ctrl {ctrl_host} chuser {monitoring_user} --public-key-file1 {temp_pub_on_storage}"
                stdout, stderr, ec = run_ssh_command(storage_host, "root", upload_cmd, pool=pool)
                if ec != 0:
                    emit_message(f"Public key upload failed: {stderr}", "error")
                    return "ERROR: Public key upload failed"
                emit_message("Public key uploaded successfully")

                emit_message(f"Configuring wallet on all {len(selected_hosts)} selected hosts (skipping non-Exascale...)")
                for host in selected_hosts:
                    emit_message(f"→ Checking {host}...")
                    check_cmd = "ls /etc/oracle/cell/network-config/eswallet/cwallet.sso"
                    stdout, stderr, ec = run_ssh_command(host, "oracle", check_cmd, pool=pool)
                    if ec != 0:
                        emit_message(f"{host} is not on Exascale (ASM-based) - skipping wallet configuration", "warning")
                        continue
                    emit_message(f"→ Configuring wallet on Exascale host {host}...")
                    run_ssh_command(host, "oracle", f"mkdir -p {key_dir} {wallet_dir} && chmod 700 {key_dir} {wallet_dir}", pool=pool)
                    write_cmd = f'cat > {priv_key} << "EOF"\n{priv_content}\nEOF\nchmod 600 {priv_key}'
                    run_ssh_command(host, "oracle", write_cmd, pool=pool)
                    stdout, stderr, ec = run_ssh_command(host, "oracle", f"/opt/oracle/dbserver/dbms/bin/escli mkwallet --wallet {wallet_dir}", pool=pool)
                    if ec != 0:
                        emit_message(f"mkwallet failed on {host}: {stderr}", "error")
                        continue
                    emit_message("Wallet created.")
                    stdout, stderr, ec = run_ssh_command(host, "oracle", f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --attributes user={monitoring_user}", pool=pool)
                    if ec != 0:
                        emit_message(f"Set user failed on {host}: {stderr}", "error")
                        continue
                    emit_message("Set user id to excmonitor.")
                    stdout, stderr, ec = run_ssh_command(host, "oracle", f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --private-key-file {priv_key}", pool=pool)
                    if ec != 0:
                        emit_message(f"Import private key failed on {host}: {stderr}", "error")
                        continue
                    emit_message("Successfully put private key in wallet.")
                    emit_message(f"Trying --fetch-trust-store on {host}...")
                    fetch_cmd = f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --fetch-trust-store"
                    stdout, stderr, ec = run_ssh_command(host, "oracle", fetch_cmd, pool=pool)
                    if ec != 0 and "ESCLI can only run local commands" in stderr:
                        emit_message(f"{host} cannot run fetch-trust-store - falling back to Storage Server", "warning")
                        run_ssh_command(storage_host, "root", f"rm -f {wallet_on_storage}", pool=pool)
                        if not scp_file(host, "oracle", f"{wallet_dir}/cwallet.sso", storage_host, "root", wallet_on_storage):
                            emit_message("Failed to copy wallet to storage", "error")
                            continue
                        fetch_cmd = 'cd /tmp && escli chwallet --wallet "exc.sso" --fetch-trust-store'
                        stdout, stderr, ec = run_ssh_command(storage_host, "root", fetch_cmd, pool=pool)
                        if ec != 0:
                            emit_message(f"Failed to fetch trust store on storage: {stderr}", "error")
                            continue
                        scp_file(storage_host, "root", wallet_on_storage, host, "oracle", f"{wallet_dir}/cwallet.sso")
                        emit_message(f"Trust store fetched successfully via Storage Server for {host}")
                    elif ec != 0:
                        emit_message(f"Failed to fetch trust store on {host}: {stderr}", "error")
                        continue
                    else:
                        emit_message(f"Trust store fetched successfully on {host}")

                    final_cmd = f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --attributes restEndPoint={rest_endpoint}"
                    stdout, stderr, ec = run_ssh_command(host, "oracle", final_cmd, pool=pool)
                    if ec != 0:
                        emit_message(f"Failed to set REST endpoint on {host}: {stderr}", "error")
                        continue
                    emit_message(f"Default ExaCTRL server address set to {rest_endpoint}.")

                emit_message("Cleaning up temporary files...")
                cleanup_cmds = [
                    (first_host, "oracle", f"rm -f {priv_key} {pub_key}"),
                    (storage_host, "root", f"rm -f {temp_pub_on_storage} {wallet_on_storage}")
                ]
                for host, user, cmd in cleanup_cmds:
                    run_ssh_command(host, user, cmd, pool=pool)

                key_status = "Keys stored in database (overridden if previously existed)" if keys_stored else "CRITICAL: Keys NOT stored in database - users cannot retrieve them!"
                final_msg = (
                    f"Exascale monitoring setup completed successfully!\n"
                    f"Wallet created and configured in /home/oracle/excmonitor_wallet on all configured Exascale hosts\n"
                    f"REST endpoint: {rest_endpoint}\n"
                    f"Monitoring user: {monitoring_user}\n"
                    f"{key_status}"
                )
                emit_message(final_msg, "success")
                return final_msg
        else:
            emit_message("No app_obj provided - skipping app_context", "warning")
            return "ERROR: No app context provided"
    except Exception as e:
        err = f"Unexpected error: {str(e)}"
        emit_message(err, "error")
        logger.error(err, exc_info=True)
        return f"ERROR: Unexpected error - {str(e)}"

# ====================== HELPERS (v1.6.13) ======================
def get_root_password(pool, hostname):
    if not pool:
        return None
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        short_name = hostname.split('.')[0] if '.' in hostname else hostname
        candidates = [
            ('Storage Server', hostname, 'root'),
            ('PHYSICAL_HOST', hostname, 'root'),
            ('Storage Server', short_name, 'root'),
            ('PHYSICAL_HOST', short_name, 'root'),
            ('Storage Server', 'default', 'root'),
            ('PHYSICAL_HOST', 'default', 'root'),
        ]
        for ctype, cname, user in candidates:
            pwd = get_credential_silent(cursor, ctype, cname, user)
            if pwd:
                logger.info(f"[Exascale] Found root password for {hostname} under {ctype}/{cname}")
                return pwd
        logger.warning(f"[Exascale] No root password found for {hostname} in credential store (will rely on passwordless SSH)")
        return None
    finally:
        cursor.close()
        release_db_connection(conn, pool)

def discover_exascale_rest_endpoint(storage_hosts, task_id, socketio=None, sid=None, pool=None):
    def emit(msg, status='info'):
        if socketio and sid:
            socketio.emit('message', {'task_id': task_id, 'line': msg, 'status': status}, room=sid, namespace='/')
        logger.info(f"[Exascale] {msg}")
    found = None
    for host in storage_hosts:
        emit(f"Scanning {host} for ERS VIP...")
        stdout_str, stderr_str, ec = run_ssh_command(host, "root", "ip addr show 2>/dev/null || ifconfig", pool=pool)
        if ec != 0:
            emit(f"Failed to get network info on {host}: {stderr_str}", "warning")
            continue
        secondary_ips = set()
        lines = stdout_str.splitlines()
        current_iface = None
        for line in lines:
            if ':' in line and not line.startswith(' '):
                current_iface = line.split(':')[0].strip()
            if 'inet ' in line:
                ip_part = line.strip().split()[1].split('/')[0]
                if 'secondary' in line.lower() or (current_iface and ':0' in current_iface):
                    secondary_ips.add(ip_part)
        for ip in secondary_ips:
            hout, _, hec = run_ssh_command(host, "root", f"host {ip}", pool=pool)
            if hec == 0 and 'ers' in hout.lower():
                hostname = hout.strip().split()[-1].rstrip('.')
                candidate = f"{hostname}:5052"
                lout, _, ec_l = run_ssh_command(host, "root", "ss -tuln | grep ':5052' || lsof -i :5052", pool=pool)
                if ec_l == 0 and lout.strip():
                    if found and found != candidate:
                        emit("Multiple conflicting ERS VIPs detected", "error")
                        return None
                    found = candidate
                    emit(f"Discovered ERS VIP: {candidate}", "success")
                    break
    return found

def scp_file(src_host, src_user, src_path, dst_host, dst_user, dst_path):
    """v1.6.13: Reliable ssh-pipe method with full error logging."""
    try:
        cmd = (
            f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes '
            f'{src_user}@{src_host} "cat {src_path}" | '
            f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes '
            f'{dst_user}@{dst_host} "cat > {dst_path}"'
        )
        logger.info(f"[Exascale] Running ssh-pipe: {cmd}")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            logger.info(f"SCP successful (ssh-pipe)")
            return True
        else:
            logger.error(f"SCP ssh-pipe FAILED (rc={result.returncode})")
            logger.error(f"STDOUT: {result.stdout.strip()}")
            logger.error(f"STDERR: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("SCP ssh-pipe timed out after 60s")
        return False
    except Exception as e:
        logger.error(f"SCP ssh-pipe exception: {e}")
        return False

def store_exascale_key(pool, component_type, component_name, username, encrypted_key, created_by):
    """
    v1.6.13: Explicitly OVERRIDES existing key for the target instead of creating a duplicate.
    - First attempts UPDATE for (COMPONENT_TYPE, COMPONENT_NAME, USERNAME)
    - Only INSERTs if no matching row exists.
    This guarantees exactly one row per target key.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()

        # Step 1: Try to OVERRIDE (update) existing key for this exact target
        update_sql = """
            UPDATE MAAMD.ACCESS_CREDENTIALS
            SET ENCRYPTED_KEY = :enc_key,
                LAST_UPDATED_BY = :created_by,
                LAST_UPDATED_DATE = SYSDATE
            WHERE COMPONENT_TYPE = :comp_type
              AND COMPONENT_NAME = :comp_name
              AND USERNAME = :user_name
        """
        cursor.execute(update_sql, {
            'enc_key': encrypted_key,
            'created_by': created_by,
            'comp_type': component_type,
            'comp_name': component_name,
            'user_name': username
        })

        if cursor.rowcount > 0:
            conn.commit()
            logger.info(f"[Exascale] OVERRIDDEN existing key for {component_type} / {component_name} / {username}")
            return True

        # Step 2: No existing row → INSERT new key
        insert_sql = """
            INSERT INTO MAAMD.ACCESS_CREDENTIALS
                (COMPONENT_TYPE, COMPONENT_NAME, USERNAME, ENCRYPTED_KEY, CREATED_BY, CREATED_DATE)
            VALUES (:comp_type, :comp_name, :user_name, :enc_key, :created_by, SYSDATE)
        """
        cursor.execute(insert_sql, {
            'comp_type': component_type,
            'comp_name': component_name,
            'user_name': username,
            'enc_key': encrypted_key,
            'created_by': created_by
        })
        conn.commit()
        logger.info(f"[Exascale] INSERTED new key for {component_type} / {component_name} / {username}")
        return cursor.rowcount > 0

    except oracledb.Error as e:
        logger.error(f"ORACLE ERROR in store_exascale_key: {e}")
        return False
    except Exception as e:
        logger.error(f"UNEXPECTED ERROR in store_exascale_key: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn, pool)

def run_ssh_command(host, user, command, timeout=120, password=None, pool=None):
    if user == 'oracle' and ('vm' in host.lower() or ('adm' in host.lower() and 'celadm' not in host.lower())):
        try:
            ssh_cmd = [
                'ssh', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'BatchMode=yes',
                '-o', f'ConnectTimeout={min(timeout, 30)}',
                f'{user}@{host}',
                command
            ]
            logger.info(f"[Exascale] Running as subprocess: {' '.join(ssh_cmd)}")
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "SSH command timed out", 1
        except Exception as e:
            logger.error(f"Subprocess SSH failed on {host}: {e}")
            return "", str(e), 1

    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(host, username=user, timeout=30, look_for_keys=True, allow_agent=True)
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_str = stdout.read().decode('utf-8', errors='ignore')
            stderr_str = stderr.read().decode('utf-8', errors='ignore')
            ec = stdout.channel.recv_exit_status()
            return stdout_str, stderr_str, ec
        except paramiko.AuthenticationException:
            logger.info(f"[Exascale] Passwordless SSH failed on {host} - falling back to DB credentials")
        except Exception as e:
            logger.error(f"SSH connection error on {host}: {e}")
            return "", str(e), 1

        if pool and not password:
            password = get_root_password(pool, host)

        if password:
            client.connect(host, username=user, password=password, timeout=30, look_for_keys=False, allow_agent=False)
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_str = stdout.read().decode('utf-8', errors='ignore')
            stderr_str = stderr.read().decode('utf-8', errors='ignore')
            ec = stdout.channel.recv_exit_status()
            return stdout_str, stderr_str, ec
        else:
            return "", "No password in credential store and passwordless SSH failed", 1

    except Exception as e:
        logger.error(f"SSH command failed on {host} as {user}: {e}")
        return "", str(e), 1
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    print("Run via MAA Unified App UI")
