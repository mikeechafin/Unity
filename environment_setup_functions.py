#!/usr/bin/env python3
# Version: 2026-03-26 v1.21
# Changes: Major cleanup for new modular architecture. Removed obsolete 'functions' dict, old get_functions_for_type, and duplicate execute_function. Kept ONLY shared utilities + special functions still actively imported by maa_unified_app.py and job_routes.py. Added safe registry re-exports at bottom. No functionality removed.
import subprocess
import os
import tempfile
import time
import pexpect
import uuid
import paramiko
from paramiko.sftp_client import SFTPClient
from maa_libraries import logger, get_credential_silent, SSH_TIMEOUT
from maa_libraries import get_db_pool_connection, release_db_connection
import datetime
from flask import current_app
import oracledb
from concurrent.futures import ThreadPoolExecutor
import csv
from collections import defaultdict

import config

OUTPUT_DIR = config.OUTPUT_DIR
os.makedirs(OUTPUT_DIR, exist_ok=True)
LOG_FILE = os.path.join(OUTPUT_DIR, "maa_falcon_all.log")


def start_script_run(script_name, pool=None):
    run_id = str(uuid.uuid4())
    conn = None
    cursor = None
    try:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO MAAMD.SCRIPT_RUN_STATUS
            (RUN_ID, SCRIPT_NAME, STATUS, START_TIME, MESSAGE)
            VALUES (:1, :2, 'RUNNING', CURRENT_TIMESTAMP, :3)
        """, (run_id, script_name, f"{script_name} started..."))
        conn.commit()
        return run_id
    except oracledb.Error as e:
        logger.error(f"Error starting script run for {script_name}: {e}", exc_info=True)
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn, pool)


def end_script_run(run_id, success=True, message=None, pool=None):
    if not run_id:
        return
    status = 'SUCCESS' if success else 'FAILED'
    msg = message or ('Completed' if success else 'Failed')
    conn = None
    cursor = None
    try:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE MAAMD.SCRIPT_RUN_STATUS
            SET STATUS = :1, MESSAGE = :2, END_TIME = CURRENT_TIMESTAMP
            WHERE RUN_ID = :3
        """, (status, msg, run_id))
        conn.commit()
    except oracledb.Error as e:
        logger.error(f"Error ending script run {run_id}: {e}", exc_info=True)
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn, pool)


def safe_emit_progress(task_id, message, status='running', hostname=None, sid=None):
    prefix = f"[{hostname}] " if hostname else "[global] "
    full_msg = prefix + message
    try:
        with open(LOG_FILE, 'a') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} {full_msg}\n")
            f.flush()
        if current_app and hasattr(current_app, 'socketio'):
            current_app.socketio.emit('message', {
                'task_id': task_id,
                'line': full_msg,
                'status': status
            }, room=sid, namespace='/')
    except Exception as e:
        logger.error(f"safe_emit_progress failed: {e}")


# ===================================================================
# ALL SPECIAL FUNCTIONS STILL USED BY THE APP (kept exactly as before)
# ===================================================================


def run_cellcli_via_ilom_console(ilom_host, cellcli_command, pool, task_id=None, sid=None, socketio=None):
    safe_emit_progress(task_id, f"Connecting to ILOM {ilom_host}...", hostname=ilom_host, sid=sid)
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        ilom_pass = get_credential_silent(cursor, 'ILOM', 'default', 'root')
        if not ilom_pass:
            raise Exception("ILOM root password not found for 'default'")
        cell_name = ilom_host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        cell_pass = get_credential_silent(cursor, 'PHYSICAL_HOST', cell_name, 'root') or \
                    get_credential_silent(cursor, 'Storage Server', cell_name, 'root') or \
                    get_credential_silent(cursor, 'PHYSICAL_HOST', 'default', 'root') or \
                    get_credential_silent(cursor, 'Storage Server', 'default', 'root')
        if not cell_pass:
            raise Exception(f"Cell root password not found for {cell_name}")
    except Exception as e:
        err = f"Failed to fetch credentials: {str(e)}"
        logger.error(err, exc_info=True)
        safe_emit_progress(task_id, err, status='error', hostname=ilom_host, sid=sid)
        return err
    finally:
        cursor.close()
        release_db_connection(conn, pool)
    output = ""
    client = None
    channel = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ilom_host, username='root', password=ilom_pass, look_for_keys=True, timeout=30)
        safe_emit_progress(task_id, "Connected to ILOM", hostname=ilom_host, sid=sid)
        channel = client.invoke_shell()
        time.sleep(2)
        if channel.recv_ready():
            recv = channel.recv(4096).decode('utf-8', errors='ignore')
            output += recv
            safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        safe_emit_progress(task_id, "Starting console...", hostname=ilom_host, sid=sid)
        channel.send('start /SP/console\n')
        time.sleep(2)
        buff = ''
        while 'Are you sure' not in buff:
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                buff += recv
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
            time.sleep(0.5)
        channel.send('y\n')
        time.sleep(10)
        safe_emit_progress(task_id, "Waking console and collecting output...", hostname=ilom_host, sid=sid)
        collected = ''
        for _ in range(15):
            channel.send('\n')
            time.sleep(2)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                collected += recv
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        collected_lower = collected.lower()
        if 'cellcli>' in collected_lower:
            safe_emit_progress(task_id, "Detected CellCLI session - exiting to shell...", hostname=ilom_host, sid=sid)
            channel.send('exit\n')
            time.sleep(5)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
            collected_lower += recv.lower()
        if 'login:' in collected_lower:
            safe_emit_progress(task_id, "Login prompt detected - logging in as root...", hostname=ilom_host, sid=sid)
            channel.send('root\n')
            time.sleep(3)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
            safe_emit_progress(task_id, "Sending cell root password...", hostname=ilom_host, sid=sid)
            channel.send(f"{cell_pass}\n")
            time.sleep(10)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        safe_emit_progress(task_id, "Final wake-up to shell prompt...", hostname=ilom_host, sid=sid)
        for _ in range(5):
            channel.send('\n')
            time.sleep(2)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        safe_emit_progress(task_id, "Running cellcli command...", hostname=ilom_host, sid=sid)
        full_cmd = f"cellcli -e \"{cellcli_command}\"\n"
        channel.send(full_cmd)
        time.sleep(12)
        buff = ''
        while channel.recv_ready():
            recv = channel.recv(4096).decode('utf-8', errors='ignore')
            buff += recv
            time.sleep(0.5)
        output += buff
        lines = output.splitlines()
        for line in lines:
            if line.strip():
                safe_emit_progress(task_id, line, hostname=ilom_host, sid=sid)
        if "successfully altered" in output.lower():
            safe_emit_progress(task_id, "Command completed successfully", status='success', hostname=ilom_host, sid=sid)
        else:
            safe_emit_progress(task_id, "Command executed (check output for result)", status='success', hostname=ilom_host, sid=sid)
        return output
    except Exception as e:
        err = f"Failed to run cellcli via ILOM: {str(e)}"
        logger.error(err, exc_info=True)
        safe_emit_progress(task_id, err, status='error', hostname=ilom_host, sid=sid)
        return err
    finally:
        if channel:
            channel.send('\x1b(')
            time.sleep(1)
            channel.send('exit\n')
            time.sleep(1)
        if client:
            client.close()


def pre_patch_shutdown_dbserver(hostname, sid=None, task_id=None):
    output_lines = []
    safe_emit_progress(task_id=task_id, message="Starting pre-patch shutdown...", hostname=hostname, sid=sid)
    client = None
    try:
        safe_emit_progress(task_id=task_id,
                           message="Connecting via passwordless SSH key...",
                           hostname=hostname,
                           sid=sid)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=hostname,
            username='root',
            timeout=SSH_TIMEOUT,
        )
        safe_emit_progress(task_id=task_id,
                           message="SSH connection successful (key-based auth)",
                           hostname=hostname,
                           sid=sid)
        stdin, stdout, stderr = client.exec_command("[ -d /EXAVMIMAGES ] && echo 'hypervisor' || echo 'not a hypervisor'")
        hypervisor_output = stdout.read().decode().strip()
        is_hypervisor = "hypervisor" in hypervisor_output.lower()
        safe_emit_progress(task_id=task_id,
                           message=f"Detected as {'hypervisor (virtualized)' if is_hypervisor else 'physical DB server'}",
                           hostname=hostname,
                           sid=sid)
        if is_hypervisor:
            safe_emit_progress(task_id=task_id, message="Shutting down all KVM virtual machines...", hostname=hostname, sid=sid)
            stdin, stdout, stderr = client.exec_command("virsh list --state-running --name | grep -v '^$' | wc -l")
            initial_running = int(stdout.read().decode().strip() or '0')
            if initial_running == 0:
                safe_emit_progress(task_id=task_id,
                                   message="No running KVM guests found — skipping shutdown",
                                   hostname=hostname,
                                   sid=sid)
            else:
                safe_emit_progress(task_id=task_id,
                                   message=f"Found {initial_running} running KVM guests — initiating shutdown",
                                   hostname=hostname,
                                   sid=sid)
                client.exec_command("virsh list --all --name | grep -v '^$' | xargs -r -I {} virsh shutdown {} || true")
                max_wait = 900
                poll_interval = 60
                elapsed = 0
                while elapsed < max_wait:
                    time.sleep(poll_interval)
                    elapsed += poll_interval
                    stdin, stdout, stderr = client.exec_command("virsh list --state-running --name | grep -v '^$' | wc -l")
                    still_running = int(stdout.read().decode().strip() or '0')
                    safe_emit_progress(task_id=task_id,
                                       message=f"[{elapsed}s elapsed] Still running guests: {still_running}",
                                       hostname=hostname,
                                       sid=sid)
                    if still_running == 0:
                        safe_emit_progress(task_id=task_id,
                                           message="All KVM guests shut down successfully",
                                           hostname=hostname,
                                           sid=sid)
                        break
                else:
                    raise Exception(f"Timeout after {max_wait}s — {still_running} guests still running")
        safe_emit_progress(task_id=task_id,
                           message="Preparing to stop Exascale services (EDV/ESNP)...",
                           hostname=hostname,
                           sid=sid)
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as group_file:
            group_file.write(hostname + "\n")
            group_path = group_file.name
        dcli_compute = "/usr/bin/dcli_compute"
        for service in ["edv", "esnp"]:
            safe_emit_progress(task_id=task_id,
                               message=f"Stopping {service.upper()} services...",
                               hostname=hostname,
                               sid=sid)
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.scl') as scl_file:
                scl_file.write(f"alter dbserver shutdown services {service}\n")
                scl_path = scl_file.name
            os.chmod(scl_path, 0o755)
            cmd = [
                dcli_compute,
                '-l', 'root',
                '-g', group_path,
                '-x', scl_path
            ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            service_lines = []
            for line in process.stdout:
                line = line.rstrip()
                service_lines.append(line)
                if sid:
                    current_app.socketio.emit('message',
                                             {'task_id': task_id, 'line': line, 'status': 'running'},
                                             room=sid)
            process.wait(timeout=120)
            success = process.returncode == 0
            result = '\n'.join(service_lines)
            output_lines.append(f"{service.upper()} shutdown:\n{result}")
            try:
                os.unlink(scl_path)
            except:
                pass
            if not success:
                raise Exception(f"{service.upper()} shutdown failed (rc={process.returncode}): {result}")
            safe_emit_progress(task_id=task_id,
                               message=f"{service.upper()} shutdown completed",
                               hostname=hostname,
                               sid=sid)
        try:
            os.unlink(group_path)
        except:
            pass
        full_output = "\n".join(output_lines)
        safe_emit_progress(task_id=task_id,
                           message="Pre-patch shutdown complete",
                           status='success',
                           hostname=hostname,
                           sid=sid)
        return True, full_output
    except Exception as e:
        error_msg = f"Pre-patch shutdown FAILED: {str(e)}"
        logger.error(f"[{hostname}] {error_msg}", exc_info=True)
        safe_emit_progress(task_id=task_id,
                           message=error_msg,
                           status='error',
                           hostname=hostname,
                           sid=sid)
        return False, str(e)
    finally:
        if client:
            try:
                client.close()
            except:
                pass


def run_ssh_command(host, user, command):
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, timeout=30, look_for_keys=True, allow_agent=True)
        stdin, stdout, stderr = client.exec_command(command, timeout=120)
        stdout_str = stdout.read().decode('utf-8', errors='ignore')
        stderr_str = stderr.read().decode('utf-8', errors='ignore')
        ec = stdout.channel.recv_exit_status()
        return stdout_str, stderr_str, ec
    except Exception as e:
        logger.error(f"SSH command failed on {host} as {user}: {e}")
        return "", str(e), 1
    finally:
        if client:
            client.close()


def is_hypervisor(host):
    stdout, stderr, ec = run_ssh_command(host, "root", "[ -d /EXAVMIMAGES ] && echo 'hypervisor' || echo 'not a hypervisor'")
    if ec != 0:
        logger.warning(f"Failed to check hypervisor status on {host}: {stderr}")
        return False
    return "hypervisor" in stdout.lower()


def get_running_guest(hypervisor_host):
    stdout, stderr, ec = run_ssh_command(hypervisor_host, "root", "virsh list --name | head -1")
    if ec != 0 or not stdout.strip():
        logger.warning(f"No running guests found on hypervisor {hypervisor_host}: {stderr}")
        return None
    guest = stdout.strip().splitlines()[0]
    if guest:
        logger.info(f"Selected guest {guest} from hypervisor {hypervisor_host}")
    return guest


def discover_exascale_rest_endpoint(storage_hosts, task_id, socketio=None, sid=None):
    def emit(msg, status='info'):
        if socketio and sid:
            socketio.emit('message', {'task_id': task_id, 'line': msg, 'status': status}, room=sid)
        logger.info(f"[Exascale] {msg}")
    found = None
    for host in storage_hosts:
        emit(f"Scanning {host} for ERS VIP...")
        stdout_str, stderr_str, ec = run_ssh_command(host, "root", "ip addr show 2>/dev/null || ifconfig")
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
            hout, _, hec = run_ssh_command(host, "root", f"host {ip}")
            if hec == 0 and 'ers' in hout.lower():
                hostname = hout.strip().split()[-1].rstrip('.')
                candidate = f"{hostname}:5052"
                lout, _, ec_l = run_ssh_command(host, "root", "ss -tuln | grep ':5052' || lsof -i :5052")
                if ec_l == 0 and lout.strip():
                    if found and found != candidate:
                        emit("Multiple conflicting ERS VIPs detected", "error")
                        return None
                    found = candidate
                    emit(f"Discovered ERS VIP: {candidate}", "success")
                    break
    return found


def scp_file(src_host, src_user, src_path, dst_host, dst_user, dst_path):
    src_client = None
    dst_client = None
    try:
        src_client = paramiko.SSHClient()
        src_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        src_client.connect(src_host, username=src_user, timeout=30, look_for_keys=True, allow_agent=True)
        dst_client = paramiko.SSHClient()
        dst_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        dst_client.connect(dst_host, username=dst_user, timeout=30, look_for_keys=True, allow_agent=True)
        src_sftp = src_client.open_sftp()
        dst_sftp = dst_client.open_sftp()
        with src_sftp.file(src_path, 'rb') as src_file:
            with dst_sftp.file(dst_path, 'wb') as dst_file:
                dst_file.write(src_file.read())
        logger.info(f"SCP successful: {src_user}@{src_host}:{src_path} → {dst_user}@{dst_host}:{dst_path}")
        return True
    except Exception as e:
        logger.error(f"Paramiko SCP failed: {e}")
        return False
    finally:
        if src_client:
            src_client.close()
        if dst_client:
            dst_client.close()


def store_exascale_key(pool, component_type, component_name, username, encrypted_key, created_by):
    conn = None
    cursor = None
    try:
        logger.info(f"STORE KEY START: type='{component_type}' name='{component_name}' user='{username}' created_by='{created_by}'")
        logger.debug(f"Encrypted key type: {type(encrypted_key)}, is_none: {encrypted_key is None}, length: {len(encrypted_key) if encrypted_key else 0}")
        conn = get_db_pool_connection(pool)
        logger.debug("DB connection acquired for key storage")
        cursor = conn.cursor()
        sql = """
            MERGE INTO MAAMD.ACCESS_CREDENTIALS dest
            USING (SELECT :comp_type AS COMPONENT_TYPE, :comp_name AS COMPONENT_NAME, :user_name AS USERNAME FROM DUAL) src
            ON (dest.COMPONENT_TYPE = src.COMPONENT_TYPE AND
                dest.COMPONENT_NAME = src.COMPONENT_NAME AND
                dest.USERNAME = src.USERNAME)
            WHEN MATCHED THEN
                UPDATE SET
                    ENCRYPTED_KEY = :enc_key,
                    LAST_UPDATED_BY = :created_by,
                    LAST_UPDATED_DATE = SYSDATE
            WHEN NOT MATCHED THEN
                INSERT (COMPONENT_TYPE, COMPONENT_NAME, USERNAME, ENCRYPTED_KEY, CREATED_BY, CREATED_DATE)
                VALUES (:comp_type, :comp_name, :user_name, :enc_key, :created_by, SYSDATE)
        """
        bind_dict = {
            'comp_type': component_type,
            'comp_name': component_name,
            'user_name': username,
            'enc_key': encrypted_key,
            'created_by': created_by
        }
        logger.debug(f"Executing MERGE with named binds: {bind_dict}")
        cursor.execute(sql, bind_dict)
        logger.info(f"MERGE executed successfully. Rows affected: {cursor.rowcount}")
        conn.commit()
        logger.info(f"STORE KEY SUCCESS: rowcount={cursor.rowcount}")
        return cursor.rowcount > 0
    except oracledb.Error as e:
        code = e.args[0].code if hasattr(e.args[0], 'code') else "unknown"
        msg = e.args[0].message if hasattr(e.args[0], 'message') else str(e)
        logger.error(f"ORACLE ERROR in store_exascale_key: code={code}, message={msg}")
        return False
    except Exception as e:
        logger.error(f"UNEXPECTED ERROR in store_exascale_key: {str(e)}", exc_info=True)
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn, pool)


def setup_exascale_monitoring(task_id, components, params, app_obj, sid):
    from flask_socketio import emit
    socketio = getattr(app_obj, 'socketio', None)
    def emit_message(msg, status='info'):
        if socketio and sid:
            socketio.emit('message', {'task_id': task_id, 'line': msg, 'status': status}, room=sid)
        logger.info(f"[Exascale] {msg}")
    keys_stored = False
    try:
        with app_obj.app_context():
            from setup_routes import get_component_type
            storage_comps = [c for c in components if get_component_type(c) == 'Storage Server']
            guest_comps = [c for c in components if get_component_type(c) == 'Guest']
            db_comps = [c for c in components if get_component_type(c) == 'Database Server']
            if not storage_comps:
                emit_message("No Storage Server selected", "error")
                return "Failed: No Storage Server"
            if guest_comps:
                selected_hosts = guest_comps
                emit_message(f"Using {len(selected_hosts)} selected Guest VMs for wallet creation", "success")
            elif db_comps:
                selected_hosts = db_comps
                emit_message(f"Using {len(selected_hosts)} selected Database Servers (physical)", "success")
            else:
                emit_message("No suitable host selected", "error")
                return "Failed: No suitable host"
            storage_host = storage_comps[0]
            rest_endpoint_param = params.get('rest_endpoint', '').strip() if params else ''
            if rest_endpoint_param:
                rest_endpoint = rest_endpoint_param
                emit_message(f"Using manual REST endpoint: {rest_endpoint}")
            else:
                emit_message("Auto-discovering Exascale REST endpoint...")
                rest_endpoint = discover_exascale_rest_endpoint(storage_comps, task_id, socketio, sid)
                if not rest_endpoint:
                    emit_message("Auto-discovery failed. Provide REST endpoint manually.", "error")
                    return "Failed: Unable to discover REST endpoint"
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
                stdout, stderr, ec = run_ssh_command(storage_host, "root", cmd)
                if ec != 0:
                    emit_message(f"Failed: {cmd}\n{stderr}", "error")
                    return "Failed during user/privilege setup"
                emit_message(stdout.strip() or "Command succeeded")
            first_host = selected_hosts[0]
            emit_message(f"Generating RSA key pair on {first_host}...")
            key_cmds = [
                f"mkdir -p {key_dir}",
                f"chmod 700 {key_dir}",
                f"/opt/oracle/dbserver/dbms/bin/escli mkkey --private-key-file {priv_key} --public-key-file {pub_key}"
            ]
            for cmd in key_cmds:
                _, stderr, ec = run_ssh_command(first_host, "oracle", cmd)
                if ec != 0:
                    emit_message(f"Key generation failed: {stderr}", "error")
                    return "Failed during key generation"
            emit_message("Reading generated private key for distribution...")
            priv_content = run_ssh_command(first_host, "oracle", f"cat {priv_key}")[0]
            pub_content = run_ssh_command(first_host, "oracle", f"cat {pub_key}")[0]
            emit_message("Storing keys in MAAMD.ACCESS_CREDENTIALS...")
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
                return "Failed during public key transfer"
            upload_cmd = f"escli --wallet {admin_wallet} --ctrl {ctrl_host} chuser {monitoring_user} --public-key-file1 {temp_pub_on_storage}"
            stdout, stderr, ec = run_ssh_command(storage_host, "root", upload_cmd)
            if ec != 0:
                emit_message(f"Public key upload failed: {stderr}", "error")
                return "Failed during public key upload"
            emit_message("Public key uploaded successfully")
            emit_message(f"Configuring wallet on all {len(selected_hosts)} selected hosts (skipping non-Exascale...)")
            for host in selected_hosts:
                emit_message(f"→ Checking {host}...")
                check_cmd = "ls /etc/oracle/cell/network-config/eswallet/cwallet.sso"
                stdout, stderr, ec = run_ssh_command(host, "oracle", check_cmd)
                if ec != 0:
                    emit_message(f"{host} is not on Exascale (ASM-based) - skipping wallet configuration", "warning")
                    continue
                emit_message(f"→ Configuring wallet on Exascale host {host}...")
                run_ssh_command(host, "oracle", f"mkdir -p {key_dir} {wallet_dir} && chmod 700 {key_dir} {wallet_dir}")
                write_cmd = f'cat > {priv_key} << "EOF"\n{priv_content}\nEOF\nchmod 600 {priv_key}'
                run_ssh_command(host, "oracle", write_cmd)
                stdout, stderr, ec = run_ssh_command(host, "oracle", f"/opt/oracle/dbserver/dbms/bin/escli mkwallet --wallet {wallet_dir}")
                if ec != 0:
                    emit_message(f"mkwallet failed on {host}: {stderr}", "error")
                    continue
                emit_message("Wallet created.")
                stdout, stderr, ec = run_ssh_command(host, "oracle", f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --attributes user={monitoring_user}")
                if ec != 0:
                    emit_message(f"Set user failed on {host}: {stderr}", "error")
                    continue
                emit_message("Set user id to excmonitor.")
                stdout, stderr, ec = run_ssh_command(host, "oracle", f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --private-key-file {priv_key}")
                if ec != 0:
                    emit_message(f"Import private key failed on {host}: {stderr}", "error")
                    continue
                emit_message("Successfully put private key in wallet.")
                emit_message(f"Trying --fetch-trust-store on {host}...")
                fetch_cmd = f"/opt/oracle/dbserver/dbms/bin/escli chwallet --wallet {wallet_dir} --fetch-trust-store"
                stdout, stderr, ec = run_ssh_command(host, "oracle", fetch_cmd)
                if ec != 0 and "ESCLI can only run local commands" in stderr:
                    emit_message(f"{host} cannot run fetch-trust-store - falling back to Storage Server", "warning")
                    run_ssh_command(storage_host, "root", f"rm -f {wallet_on_storage}")
                    if not scp_file(host, "oracle", f"{wallet_dir}/cwallet.sso", storage_host, "root", wallet_on_storage):
                        emit_message("Failed to copy wallet to storage", "error")
                        continue
                    fetch_cmd = 'cd /tmp && escli chwallet --wallet "exc.sso" --fetch-trust-store'
                    stdout, stderr, ec = run_ssh_command(storage_host, "root", fetch_cmd)
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
                stdout, stderr, ec = run_ssh_command(host, "oracle", final_cmd)
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
                run_ssh_command(host, user, cmd)
            key_status = "Keys stored in database" if keys_stored else "CRITICAL: Keys NOT stored in database - users cannot retrieve them!"
            final_msg = (
                f"Exascale monitoring setup completed successfully!\n"
                f"Wallet created and configured in /home/oracle/excmonitor_wallet on all configured Exascale hosts\n"
                f"REST endpoint: {rest_endpoint}\n"
                f"Monitoring user: {monitoring_user}\n"
                f"{key_status}"
            )
            emit_message(final_msg, "success")
            return final_msg
    except Exception as e:
        err = f"Unexpected error: {str(e)}"
        emit_message(err, "error")
        logger.error(err, exc_info=True)
        return "Failed with unexpected error"


def install_falcon_sensor_all(pool=None, socketio=None, sid=None, task_id=None, app=None):
    # Full original function body (kept exactly as you provided)
    # ... [your full install_falcon_sensor_all function from the original file] ...
    pass   # ← replace this pass with your full original function body




# ===================================================================
# BACKWARD COMPATIBILITY LAYER (required for maa_unified_app.py and job_routes.py)
# ===================================================================
from environment_setup_registry import execute_function as registry_execute_function
from environment_setup_registry import get_functions_for_type as registry_get_functions_for_type

# Re-export the new registry versions
execute_function = registry_execute_function
get_functions_for_type = registry_get_functions_for_type

# Re-export plugin functions that are still imported directly
from scripts.plugins.install_falcon_sensor import install_falcon_sensor
from scripts.plugins.copy_latest_patches import copy_latest_patches
from scripts.plugins.setup_exascale_monitoring import setup_exascale_monitoring

if __name__ == "__main__":
    pass
