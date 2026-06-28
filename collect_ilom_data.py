#!/usr/bin/env python3
# Version: 2026-04-10 v1.02
# Changes: Added --debug CLI flag (defaults to INFO logging level); debug messages now suppressed by default to dramatically reduce log file growth while preserving full verbosity when needed
import oracledb
import paramiko
import re
import logging
import logging.handlers
import time
import os
import socket
import sys
import fcntl
import atexit
import argparse
from func_timeout import func_timeout, FunctionTimedOut
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from maa_libraries import is_host_reachable, get_credential_silent, decrypt_data

LOG_FILE_PATH = '/home/maatest/mchafin/MAA_APPS_NEW/output/collect_ilom_data.log'
LOCK_FILE_PATH = '/home/maatest/mchafin/MAA_APPS_NEW/output/collect_ilom_data.lock'

# Logger setup - default INFO to eliminate unnecessary debug noise; overridden only when --debug is passed
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.handlers.WatchedFileHandler(LOG_FILE_PATH)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

SSH_PRIVATE_KEY_PATH = '/home/maatest/.ssh/id_rsa'
DEFAULT_ILOM_USERNAME = 'root'
DSN = os.environ.get('DB_DSN') or "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
DB_PASSWORD = os.environ.get('DB_PASSWORD')
if not DB_PASSWORD:
    raise RuntimeError("DB_PASSWORD environment variable is required")
DB_POOL = oracledb.SessionPool(user='maamd', password=DB_PASSWORD, dsn=DSN, min=1, max=10, increment=1)
MAX_WORKERS = 10
BATCH_SIZE = 100
LOCK = Lock()
CONNECT_TIMEOUT = 5
SSH_TIMEOUT = 60

def acquire_process_lock():
    """Ensure only one instance of the script runs at a time using fcntl exclusive lock."""
    try:
        lock_fd = open(LOCK_FILE_PATH, 'w')
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()) + '\n')
        lock_fd.flush()
        logger.info(f"Acquired exclusive process lock (PID {os.getpid()})")
        return lock_fd
    except (IOError, OSError, BlockingIOError):
        logger.error(f"Another instance of collect_ilom_data.py is already running (lock file: {LOCK_FILE_PATH}). Exiting.")
        sys.exit(1)

def release_process_lock(lock_fd):
    """Release the process lock and clean up lock file."""
    if lock_fd is not None:
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()
            if os.path.exists(LOCK_FILE_PATH):
                os.unlink(LOCK_FILE_PATH)
            logger.info("Process lock released successfully")
        except Exception as e:
            logger.warning(f"Error releasing process lock: {e}")

def connect_with_timeout(client, hostname, *args, timeout=CONNECT_TIMEOUT, **kwargs):
    try:
        logger.debug(f"Connecting to {hostname} with timeout {timeout}s")
        return func_timeout(timeout, client.connect, args=(hostname, *args), kwargs=kwargs)
    except FunctionTimedOut:
        logger.error(f"Connection timed out to {hostname} after {timeout}s")
        raise TimeoutError("Connection timed out")

def get_db_connection():
    return DB_POOL.acquire()

def release_db_connection(conn):
    DB_POOL.release(conn)

def execute_ssh_command(ssh, command, interactive=False, timeout=30, allow_error=False):
    logger.debug(f"Executing SSH command: {command}")
    transport = ssh.get_transport()
    channel = transport.open_session()
    channel.settimeout(timeout)
    if not interactive:
        channel.exec_command(command)
        output = channel.makefile('r', -1).read().decode('utf-8').strip()
        error = channel.makefile_stderr('r', -1).read().decode('utf-8').strip()
        exit_status = channel.recv_exit_status()
        channel.close()
        if not allow_error and (exit_status != 0 or error or 'failed' in output.lower()):
            raise paramiko.SSHException(f"Command failed: Exit Status {exit_status}, Output: {output}, Error: {error}")
        return output
    else:
        channel.invoke_shell()
        time.sleep(1)
        channel.send(command + '\n')
        start_time = time.time()
        output = ""
        prompt_responded = False
        while time.time() - start_time < timeout:
            if channel.recv_ready():
                chunk = channel.recv(1024).decode('utf-8')
                output += chunk
                if "Are you sure" in output and "(y/n)" in output and not prompt_responded:
                    channel.send('y\n')
                    prompt_responded = True
                    output = ""
                elif "Created" in output or "Deleted" in output or "failed" in output.lower() or "Invalid" in output:
                    break
            time.sleep(0.1)
        channel.close()
        if "Created" not in output and "Deleted" not in output:
            raise paramiko.SSHException(f"Failed to execute: {output}")
        return output

def derive_canonical_system_name(ilom_hostname):
    base = re.sub(r'(-ilom\.us\.oracle\.com|-c\.us\.oracle\.com)$', '', ilom_hostname, flags=re.IGNORECASE)
    return f"{base}.us.oracle.com"

def get_preferred_ilom_hostname(system_name, conn):
    cursor = conn.cursor()
    try:
        base = system_name.replace('.us.oracle.com', '')
        ilom_variant = f"{base}-ilom.us.oracle.com"
        c_variant = f"{base}-c.us.oracle.com"
        cursor.execute("""
            SELECT hostname, ilom_ip FROM MAAMD.ilom_hosts
            WHERE hostname IN (:1, :2)
        """, (ilom_variant, c_variant))
        existing = cursor.fetchall()
        if existing:
            for host, ip in existing:
                if host == ilom_variant:
                    return ilom_variant, ip
            return existing[0][0], existing[0][1]
        if is_host_reachable(ilom_variant):
            return ilom_variant, None
        elif is_host_reachable(c_variant):
            return c_variant, None
        else:
            logger.warning(f"Neither {ilom_variant} nor {c_variant} is reachable")
            return None, None
    finally:
        cursor.close()

def process_ilom(host):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT USERNAME, ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_TYPE = 'ILOM'
              AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
            ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END, USERNAME
            """,
            {'hostname': host}
        )
        creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None) for row in cursor.fetchall()]
        if not creds:
            logger.warning(f"No ILOM credentials in ACCESS_CREDENTIALS for {host}; skipping")
            return [], []
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connected = False
        for username, password in creds:
            try:
                connect_with_timeout(client, host, username=username, password=password, timeout=SSH_TIMEOUT)
                connected = True
                break
            except Exception as e:
                logger.debug(f"Failed to connect to {host} with {username}: {e}")
        if not connected:
            logger.error(f"Failed to connect to {host} for data collection")
            return [], []
        alerts_data = []
        try:
            output = execute_ssh_command(client, "show /SP/alertmgmt/rules", timeout=SSH_TIMEOUT)
            lines = output.splitlines()
            for line in lines:
                if line.strip().startswith('rule'):
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 7:
                        alert_id = parts[0]
                        version = parts[1]
                        destination_ip = parts[2]
                        community_string = parts[3]
                        username = parts[4]
                        status = parts[5]
                        port = parts[6]
                        alerts_data.append((host, alert_id, version, destination_ip, community_string, username, status, port))
        except Exception as e:
            logger.error(f"Error collecting SNMP alerts from {host}: {e}")
        users_data = []
        try:
            output = execute_ssh_command(client, "show /SP/users", timeout=SSH_TIMEOUT)
            lines = output.splitlines()
            for line in lines:
                if line.strip().startswith('user'):
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 3:
                        username = parts[0]
                        auth_protocol = parts[1]
                        access_level = ' '.join(parts[2:])
                        users_data.append((host, username, auth_protocol, access_level))
        except Exception as e:
            logger.error(f"Error collecting SNMP users from {host}: {e}")
        client.close()
        return alerts_data, users_data
    finally:
        cursor.close()
        release_db_connection(conn)

def batch_insert(cursor, conn, table_name, columns, data, pk_columns):
    if not data:
        return
    placeholders = ', '.join(':' + str(i+1) for i in range(len(columns)))
    update_set = ', '.join(f"{col} = :new_{col}" for col in columns if col not in pk_columns)
    pk_condition = ' AND '.join(f"dest.{col} = src.{col}" for col in pk_columns)
    merge_sql = f"""
        MERGE INTO MAAMD.{table_name} dest
        USING (SELECT {', '.join(f':{i+1} AS {col}' for i, col in enumerate(columns))} FROM DUAL) src
        ON ({pk_condition})
        WHEN MATCHED THEN
            UPDATE SET {update_set}
        WHEN NOT MATCHED THEN
            INSERT ({', '.join(columns)})
            VALUES ({', '.join(f'src.{col}' for col in columns)})
    """
    for row in data:
        bind_values = list(row)
        for col in columns:
            bind_values.append(row[columns.index(col)])
        cursor.execute(merge_sql, bind_values)
    conn.commit()

def collect_data():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT ILOM_NAME FROM MAAMD.system_allocations WHERE ILOM_NAME IS NOT NULL")
        ilom_hostnames = [row[0] for row in cursor.fetchall()]
        system_to_ilom = {}
        for ilom in ilom_hostnames:
            system_name = derive_canonical_system_name(ilom)
            if system_name not in system_to_ilom:
                preferred_hostname, ilom_ip = get_preferred_ilom_hostname(system_name, conn)
                if preferred_hostname:
                    system_to_ilom[system_name] = (preferred_hostname, ilom_ip)
        hosts_to_process = []
        for hostname, _ in system_to_ilom.values():
            if is_host_reachable(hostname):
                hosts_to_process.append(hostname)
            else:
                logger.warning(f"Skipping unreachable ILOM host {hostname}")
        logger.info(f"Processing {len(hosts_to_process)} reachable ILOM hosts (skipped {len(system_to_ilom) - len(hosts_to_process)} unreachable)")
        for system_name, (preferred_hostname, ilom_ip) in system_to_ilom.items():
            ilom_variant = f"{system_name.replace('.us.oracle.com', '')}-ilom.us.oracle.com"
            c_variant = f"{system_name.replace('.us.oracle.com', '')}-c.us.oracle.com"
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT hostname FROM MAAMD.ilom_hosts
                    WHERE hostname IN (:1, :2)
                """, (ilom_variant, c_variant))
                existing_hostnames = [row[0] for row in cursor.fetchall()]
                if not existing_hostnames:
                    cursor.execute("""
                        INSERT INTO MAAMD.ilom_hosts (hostname, ilom_ip)
                        VALUES (:1, :2)
                    """, (preferred_hostname, ilom_ip))
                elif preferred_hostname not in existing_hostnames:
                    cursor.execute("""
                        UPDATE MAAMD.ilom_hosts
                        SET hostname = :1, ilom_ip = :2
                        WHERE hostname = :3
                    """, (preferred_hostname, ilom_ip, existing_hostnames[0]))
                    other_variant = ilom_variant if preferred_hostname == c_variant else c_variant
                    if other_variant in existing_hostnames:
                        cursor.execute("""
                            DELETE FROM MAAMD.ilom_hosts
                            WHERE hostname = :1
                        """, (other_variant,))
                conn.commit()
            finally:
                cursor.close()
        all_alerts_data = []
        all_users_data = []
        processed_count = 0
        skipped_count = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_host = {executor.submit(process_ilom, host): host for host in hosts_to_process}
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    alerts_data, users_data = future.result()
                    if alerts_data or users_data:
                        processed_count += 1
                        if alerts_data:
                            all_alerts_data.extend(alerts_data)
                        if users_data:
                            all_users_data.extend(users_data)
                    else:
                        skipped_count += 1
                except Exception as e:
                    logger.error(f"Error processing host {host}: {str(e)}", exc_info=True)
                    skipped_count += 1
        logger.info(f"Processing complete: {processed_count} hosts processed, {skipped_count} hosts skipped")
        cursor = conn.cursor()
        try:
            alert_columns = ['ilom_hostname', 'alert_id', 'version', 'destination_ip', 'community_string', 'username', 'status', 'port']
            user_columns = ['ilom_hostname', 'username', 'authentication_protocol', 'access_level']
            alert_pk_columns = ['ilom_hostname', 'alert_id']
            user_pk_columns = ['ilom_hostname', 'username']
            for i in range(0, len(all_alerts_data), BATCH_SIZE):
                batch = all_alerts_data[i:i + BATCH_SIZE]
                batch_insert(cursor, conn, 'snmp_subscriptions', alert_columns, batch, alert_pk_columns)
            for i in range(0, len(all_users_data), BATCH_SIZE):
                batch = all_users_data[i:i + BATCH_SIZE]
                batch_insert(cursor, conn, 'snmp_users', user_columns, batch, user_pk_columns)
        finally:
            cursor.close()
        logger.info("Data collection and merge completed successfully")
    except Exception as e:
        logger.error(f"Unexpected error in collect_data: {str(e)}", exc_info=True)
        conn.rollback()
    finally:
        release_db_connection(conn)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Collect ILOM SNMP data for MAA')
    parser.add_argument('--debug', action='store_true', help='Enable verbose DEBUG logging (default: INFO level to control log file size)')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.info("DEBUG logging enabled via --debug flag")
    else:
        logger.info("INFO mode active - debug noise suppressed to prevent excessive log growth")

    lock_fd = acquire_process_lock()
    atexit.register(release_process_lock, lock_fd)
    logger.info("Starting collect_ilom_data.py - single instance lock acquired")
    collect_data()
