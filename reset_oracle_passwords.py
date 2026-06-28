#!/usr/bin/env python3
# Filename: reset_oracle_passwords.py
"""
Script to check and reset expired Oracle user passwords on Linux hosts.
- Checks all physical hosts (from MAAMD.SYSTEM_ALLOCATIONS) and guests (from MAAMD.GUESTS).
- Resets expired passwords to the default stored in MAAMD.ACCESS_CREDENTIALS.
- Unlocks accounts if locked due to invalid attempts or inactivity.
- Uses root user credentials for password resets, with credential retrieval inspired by collect_agent_data.py.
- Logs all actions and errors to a dedicated log file.
- Uses direct SSH command execution with DNS and pam_tally2/faillock checks.
Version: 3.0.11
Changelog:
- 3.0.11: Fixed ORA-01461 on JOB_HISTORY update (setinputsizes for LONG); truncate error message; improved host mismatch handling in pool.
- 3.0.10: Added DNS resolution checks; support pam_tally2 and faillock; enhanced SSH debug; relaxed host validation.
- 3.0.9: Added time import; enhanced proxy routing debug with host validation; retry SSH on host mismatch.
- 3.0.8: Replaced execute_ssh_command_wrapper with execute_ssh_command_direct; added fallback getent passwd in check_oracle_user; added SSH context debug; retry id oracle.
- 3.0.7: Added execute_ssh_command_wrapper to capture stdout, stderr, and exit status; updated check_oracle_user and command calls; increased SSH_COMMAND_TIMEOUT to 60.
- 3.0.6: Fixed execute_ssh_command handling to expect single string output per maa_libraries.py; updated check_oracle_user and command calls.
- 3.0.5: Added robust handling for execute_ssh_command output; checks for oracle user existence; increased SSH_RETRIES to 2.
- 3.0.4: Fixed syntax error in SSHConnectionPool.release_client method (incorrect 'Notif' parameter).
- 3.0.3: Fixed Queue.Empty to queue.Empty in SSHConnectionPool.get_client.
- 3.0.2: Corrected file paths from /home/maomedb to /home/maatest/mchafin for log_directory and SSH_KEY_PATH.
- 3.0.1: Fixed syntax error in DB_USER constant (missing closing quote).
- 3.0.0: Integrated database connection and credential retrieval from collect_agent_data.py; added SSH connection pooling.
- 2.0.0: Updated to fetch guests from MAAMD.GUESTS table.
- 1.0.0: Initial version checking SYSTEM_ALLOCATIONS.
"""
import os
import sys
import logging
import threading
import queue
from queue import Queue
from datetime import datetime
import oracledb  # Explicit import
import paramiko
import time
import socket
from paramiko.ssh_exception import SSHException, AuthenticationException
from maa_unified_app import app
from maa_libraries import get_credential_silent, is_host_reachable

# Constants
DB_USER = "maamd"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
ROOT_USER = "root"
ORACLE_USER = "oracle"
SSH_TIMEOUT = 30
SSH_BANNER_TIMEOUT = 30
SSH_RETRIES = 2
SSH_RETRY_DELAY = 5
SSH_COMMAND_TIMEOUT = 60
SSH_KEY_PATH = "/home/maatest/.ssh/id_rsa"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
if not DB_PASSWORD:
    logging.critical("Environment variable DB_PASSWORD is not set")
    sys.exit(1)

# Logging setup
log_directory = "/home/maatest/mchafin/MAA_APPS_NEW/output"
log_file = f"{log_directory}/reset_oracle_passwords.log"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)
reset_logger = logging.getLogger('ResetOraclePasswords')
reset_logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
reset_logger.addHandler(file_handler)

# SSH Connection Pool
class SSHConnectionPool:
    def __init__(self, max_size=20):
        self.pool = Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.max_size = max_size

    def get_client(self, hostname, component_type="PHYSICAL_HOST"):
        with self.lock:
            # Resolve hostname to IP
            try:
                ip = socket.gethostbyname(hostname)
                reset_logger.debug(f"DNS resolution for {hostname}: {ip}")
            except socket.gaierror as e:
                reset_logger.warning(f"DNS resolution failed for {hostname}: {str(e)}")
                return None
            if not is_host_reachable(hostname, ip):
                reset_logger.warning(f"Skipping {hostname}: ping failed or high latency")
                return None
            try:
                client = self.pool.get_nowait()
                transport = client.get_transport()
                if transport.is_active():
                    stdin, stdout, stderr = client.exec_command("whoami", timeout=SSH_TIMEOUT)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        # Validate target host
                        stdin, stdout, stderr = client.exec_command("hostname", timeout=SSH_COMMAND_TIMEOUT)
                        target_host = stdout.read().decode().strip().lower()
                        expected_host = hostname.split('.')[0].lower()
                        if expected_host not in target_host:
                            reset_logger.warning(f"Host mismatch for {hostname}: expected {expected_host}, got {target_host} — closing reused connection")
                            client.close()
                            raise Exception("Host mismatch")
                        reset_logger.info(f"Reusing SSH connection for {hostname} (pool size: {self.pool.qsize()})")
                        transport.send_ignore()
                        return client
                    reset_logger.info(f"SSH session for {hostname} is invalid, closing")
                client.close()
            except queue.Empty:
                pass
            except Exception as e:
                reset_logger.debug(f"Reused client invalid ({str(e)}), creating new")
            for attempt in range(SSH_RETRIES):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connected = False
                # Try key-based authentication first
                if os.path.isfile(SSH_KEY_PATH):
                    try:
                        key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
                        reset_logger.info(f"Attempting SSH key auth for {hostname} ({ip}) as {ROOT_USER}, attempt {attempt+1}/{SSH_RETRIES}")
                        client.connect(
                            hostname, username=ROOT_USER, pkey=key,
                            timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT
                        )
                        client.get_transport().set_keepalive(30)
                        reset_logger.info(f"SSH key auth successful for {hostname} ({ip}) as {ROOT_USER}")
                        # Validate target host
                        stdin, stdout, stderr = client.exec_command("hostname", timeout=SSH_COMMAND_TIMEOUT)
                        target_host = stdout.read().decode().strip().lower()
                        expected_host = hostname.split('.')[0].lower()
                        if expected_host not in target_host:
                            reset_logger.warning(f"Host mismatch for {hostname}: expected {expected_host}, got {target_host}")
                            client.close()
                            continue
                        reset_logger.debug(f"SSH connection validated for {hostname}: target host {target_host}")
                        connected = True
                    except AuthenticationException:
                        reset_logger.info(f"SSH key auth failed for {hostname} ({ip}) as {ROOT_USER}, attempt {attempt+1}")
                    except SSHException as e:
                        reset_logger.warning(f"SSH protocol error for {hostname} ({ip}): {str(e)}")
                if not connected:
                    # Try password-based authentication
                    password = CREDENTIAL_CACHE.get((component_type, hostname, ROOT_USER))
                    if not password:
                        password = CREDENTIAL_CACHE.get((component_type, "default", ROOT_USER))
                    if not password:
                        conn = app.config['DB_POOL'].acquire()
                        try:
                            cursor = conn.cursor()
                            password = get_credential_silent(cursor, component_type, hostname, ROOT_USER)
                            if not password:
                                password = get_credential_silent(cursor, component_type, "default", ROOT_USER)
                            if password:
                                CREDENTIAL_CACHE[(component_type, hostname, ROOT_USER)] = password
                        finally:
                            cursor.close()
                            app.config['DB_POOL'].release(conn)
                    if password:
                        reset_logger.info(f"Attempting SSH password auth for {hostname} ({ip}) as {ROOT_USER}, attempt {attempt+1}/{SSH_RETRIES}")
                        try:
                            client.connect(
                                hostname, username=ROOT_USER, password=password,
                                timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT
                            )
                            client.get_transport().set_keepalive(30)
                            reset_logger.info(f"Password auth successful for {hostname} ({ip}) as {ROOT_USER}")
                            # Validate target host
                            stdin, stdout, stderr = client.exec_command("hostname", timeout=SSH_COMMAND_TIMEOUT)
                            target_host = stdout.read().decode().strip().lower()
                            expected_host = hostname.split('.')[0].lower()
                            if expected_host not in target_host:
                                reset_logger.warning(f"Host mismatch for {hostname}: expected {expected_host}, got {target_host}")
                                client.close()
                                continue
                            reset_logger.debug(f"SSH connection validated for {hostname}: target host {target_host}")
                            connected = True
                        except AuthenticationException:
                            reset_logger.warning(f"Password auth failed for {hostname} ({ip}) as {ROOT_USER}")
                        except SSHException as e:
                            reset_logger.warning(f"SSH error for {hostname} ({ip}): {str(e)}")
                if connected:
                    return client
                client.close()
                if attempt < SSH_RETRIES - 1:
                    reset_logger.info(f"Retrying connection to {hostname} after {SSH_RETRY_DELAY} seconds")
                    time.sleep(SSH_RETRY_DELAY)
            reset_logger.error(f"Failed to connect to {hostname} ({ip}) after {SSH_RETRIES} attempts")
            return None

    def release_client(self, client):
        with self.lock:
            if client is None:
                return
            try:
                if self.pool.qsize() < self.max_size and client.get_transport().is_active():
                    self.pool.put(client)
                    reset_logger.info(f"Released SSH client to pool for {client.get_transport().getpeername()[0]}")
                else:
                    client.close()
            except Exception as e:
                reset_logger.error(f"Error releasing SSH client: {str(e)}")
                client.close()

SSH_POOL = SSHConnectionPool(max_size=20)
CREDENTIAL_CACHE = {}

def load_default_credentials(conn):
    """Load default credentials for root user."""
    try:
        cursor = conn.cursor()
        for component_type in ["PHYSICAL_HOST", "GUEST"]:
            password = get_credential_silent(cursor, component_type, "default", ROOT_USER)
            if password:
                CREDENTIAL_CACHE[(component_type, "default", ROOT_USER)] = password
                reset_logger.info(f"Cached default password for {component_type}:default:{ROOT_USER}")
            else:
                reset_logger.info(f"No default password for {component_type}:default:{ROOT_USER}")
        cursor.close()
    except oracledb.Error as e:
        reset_logger.error(f"Error caching default credentials: {str(e)}")

def execute_ssh_command_direct(client, command, hostname, timeout=SSH_COMMAND_TIMEOUT):
    """Directly execute SSH command, returning stdout, stderr, and exit status."""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        reset_logger.debug(f"SSH command '{command}' on {hostname}: output='{output}', error='{error}', exit_status={exit_status}")
        return output, error, exit_status
    except Exception as e:
        reset_logger.error(f"Failed to execute SSH command '{command}' on {hostname}: {str(e)}")
        return "", str(e), 1

def check_oracle_user(client, hostname):
    """Check if the oracle user exists on the host with retry and fallback."""
    # Debug SSH context
    context_cmd = "whoami; hostname"
    context_output, context_error, context_exit_status = execute_ssh_command_direct(client, context_cmd, hostname)
    reset_logger.debug(f"SSH context on {hostname}: whoami;hostname output='{context_output}', error='{context_error}', exit_status={context_exit_status}")
    # Try id oracle with retry
    cmd = "id oracle"
    for attempt in range(2):
        output, error, exit_status = execute_ssh_command_direct(client, cmd, hostname)
        if exit_status == 0 and "uid=" in output:
            reset_logger.info(f"Oracle user exists on {hostname}: {output}")
            return True
        if exit_status != 0 and "no such user" in error.lower():
            reset_logger.warning(f"Oracle user does not exist on {hostname} (attempt {attempt+1}): {error}")
            if attempt == 0:
                reset_logger.info(f"Retrying id oracle on {hostname}")
                time.sleep(1)
                continue
            break
        reset_logger.error(f"Error checking oracle user on {hostname} (attempt {attempt+1}): exit_status={exit_status}, output={output}, error={error}")
        if attempt == 0:
            reset_logger.info(f"Retrying id oracle on {hostname}")
            time.sleep(1)
    # Fallback to getent passwd oracle
    cmd = "getent passwd oracle"
    output, error, exit_status = execute_ssh_command_direct(client, cmd, hostname)
    if exit_status == 0 and output:
        reset_logger.info(f"Oracle user exists on {hostname} (via getent): {output}")
        return True
    if exit_status != 0:
        reset_logger.warning(f"Oracle user not found on {hostname} (via getent): exit_status={exit_status}, error={error}")
    else:
        reset_logger.warning(f"No output from getent passwd on {hostname}: error={error}")
    return False

def check_account_lock(client, hostname):
    """Check if oracle account is locked using pam_tally2 or faillock."""
    # Check if pam_tally2 exists
    cmd = "command -v pam_tally2"
    output, error, exit_status = execute_ssh_command_direct(client, cmd, hostname)
    if exit_status == 0:
        cmd = "pam_tally2 --user oracle"
        output, error, exit_status = execute_ssh_command_direct(client, cmd, hostname)
        if exit_status == 0:
            reset_logger.debug(f"pam_tally2 output on {hostname}: {output}")
            if "Fail count" in output and int(output.split("Fail count")[1].split()[0]) > 0:
                reset_logger.info(f"Oracle account on {hostname} locked due to failed login attempts (pam_tally2)")
                return True
            return False
        reset_logger.warning(f"Failed to execute pam_tally2 on {hostname}: exit_status={exit_status}, error={error}")
    else:
        reset_logger.debug(f"pam_tally2 not found on {hostname}, trying faillock")
    # Try faillock
    cmd = "command -v faillock"
    output, error, exit_status = execute_ssh_command_direct(client, cmd, hostname)
    if exit_status == 0:
        cmd = "faillock --user oracle"
        output, error, exit_status = execute_ssh_command_direct(client, cmd, hostname)
        if exit_status == 0:
            reset_logger.debug(f"faillock output on {hostname}: {output}")
            if "failures" in output.lower() and any(int(n) > 0 for n in output.split() if n.isdigit()):
                reset_logger.info(f"Oracle account on {hostname} locked due to failed login attempts (faillock)")
                return True
            return False
        reset_logger.warning(f"Failed to execute faillock on {hostname}: exit_status={exit_status}, error={error}")
    else:
        reset_logger.warning(f"Neither pam_tally2 nor faillock found on {hostname}, skipping account lock check")
    return False

def check_and_reset_oracle_passwords(job_id=None):
    """
    Check Oracle user password status and reset if expired or locked for all hosts and guests.
    Args:
        job_id: Job ID for logging (optional)
    Returns:
        bool: True if successful, False otherwise
    """
    conn = None
    cursor = None
    try:
        conn = app.config['DB_POOL'].acquire()
        cursor = conn.cursor()
        # Load default credentials
        load_default_credentials(conn)
        # Fetch physical hosts from SYSTEM_ALLOCATIONS (excluding storage servers and ILOMs)
        cursor.execute("""
            SELECT DISTINCT SYSTEM_NAME
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE SYSTEM_NAME NOT LIKE '%celadm%'
              AND SYSTEM_NAME NOT LIKE '%-c%'
              AND SYSTEM_NAME NOT LIKE '%-ilom%'
        """)
        physical_hosts = {row[0].lower() for row in cursor.fetchall()}
        # Fetch guests from GUESTS table
        cursor.execute("SELECT DISTINCT HOSTNAME FROM MAAMD.GUESTS")
        guest_hosts = {row[0].lower() for row in cursor.fetchall()}
        # Combine and deduplicate hosts
        all_hosts = physical_hosts.union(guest_hosts)
        reset_logger.info(f"Found {len(all_hosts)} unique hosts to check (Physical: {len(physical_hosts)}, Guests: {len(guest_hosts)})")
        # Track results
        success_count = 0
        failure_count = 0
        skipped_count = 0
        for hostname in sorted(all_hosts):
            try:
                # Skip if host is not reachable
                if not is_host_reachable(hostname):
                    reset_logger.warning(f"Host {hostname} is not reachable, skipping")
                    skipped_count += 1
                    continue
                # Determine component type
                component_type = 'GUEST' if hostname in guest_hosts else 'PHYSICAL_HOST'
                # Establish SSH connection as root
                client = SSH_POOL.get_client(hostname, component_type)
                if not client:
                    reset_logger.error(f"Failed to establish SSH connection to {hostname} as {ROOT_USER}, skipping")
                    skipped_count += 1
                    continue
                try:
                    # Check if oracle user exists
                    if not check_oracle_user(client, hostname):
                        reset_logger.warning(f"Skipping {hostname} ({component_type}): oracle user does not exist")
                        skipped_count += 1
                        continue
                    # Check Oracle user password status
                    check_cmd = "chage -l oracle"
                    output, error, exit_status = execute_ssh_command_direct(client, check_cmd, hostname)
                    if exit_status != 0:
                        reset_logger.error(f"Failed to execute chage command on {hostname}: exit_status={exit_status}, error={error}")
                        failure_count += 1
                        continue
                    if not output:
                        reset_logger.error(f"No output from chage command on {hostname}, error={error}")
                        failure_count += 1
                        continue
                    reset_logger.debug(f"Password status for oracle on {hostname}: {output}")
                    # Parse chage output
                    password_expired = False
                    account_locked = False
                    for line in output.splitlines():
                        if "Password expires" in line and "never" not in line.lower():
                            try:
                                expiry_date = datetime.strptime(line.split(":")[1].strip(), "%b %d, %Y")
                                if expiry_date < datetime.now():
                                    password_expired = True
                            except (ValueError, IndexError):
                                reset_logger.warning(f"Could not parse expiry date on {hostname}: {line}")
                        if "Account expires" in line and "never" not in line.lower():
                            try:
                                account_expiry = datetime.strptime(line.split(":")[1].strip(), "%b %d, %Y")
                                if account_expiry < datetime.now():
                                    account_locked = True
                            except (ValueError, IndexError):
                                reset_logger.warning(f"Could not parse account expiry on {hostname}: {line}")
                        if "Minimum number of days between password change" in line:
                            # Check for lock due to failed login attempts
                            account_locked = account_locked or check_account_lock(client, hostname)
                    action_taken = False
                    if password_expired:
                        # Get default Oracle password
                        oracle_password = CREDENTIAL_CACHE.get((component_type, "default", ORACLE_USER))
                        if not oracle_password:
                            cursor.execute(
                                "SELECT ENCRYPTED_PASSWORD FROM MAAMD.ACCESS_CREDENTIALS WHERE COMPONENT_TYPE = :1 AND COMPONENT_NAME = 'default' AND USERNAME = :2",
                                (component_type, ORACLE_USER)
                            )
                            row = cursor.fetchone()
                            if row and row[0]:
                                oracle_password = get_credential_silent(cursor, component_type, "default", ORACLE_USER)
                                if oracle_password:
                                    CREDENTIAL_CACHE[(component_type, "default", ORACLE_USER)] = oracle_password
                        if not oracle_password:
                            reset_logger.error(f"No default Oracle password found for {component_type}, skipping {hostname}")
                            skipped_count += 1
                            continue
                        # Reset password
                        reset_cmd = f"echo 'oracle:{oracle_password}' | chpasswd"
                        reset_output, reset_error, reset_exit_status = execute_ssh_command_direct(client, reset_cmd, hostname)
                        if reset_exit_status != 0:
                            reset_logger.error(f"Failed to reset password on {hostname}: exit_status={reset_exit_status}, error={reset_error}")
                            failure_count += 1
                            continue
                        reset_logger.info(f"Reset Oracle user password on {hostname}: {reset_output}")
                        action_taken = True
                    if account_locked:
                        # Unlock account
                        unlock_cmd = "faillock --user oracle --reset" if check_account_lock(client, hostname) else "pam_tally2 --user oracle --reset"
                        unlock_output, unlock_error, unlock_exit_status = execute_ssh_command_direct(client, unlock_cmd, hostname)
                        if unlock_exit_status != 0:
                            reset_logger.error(f"Failed to unlock account on {hostname}: exit_status={unlock_exit_status}, error={unlock_error}")
                            failure_count += 1
                            continue
                        reset_logger.info(f"Unlocked Oracle account on {hostname}: {unlock_output}")
                        expiry_cmd = "chage -E -1 oracle"
                        expiry_output, expiry_error, expiry_exit_status = execute_ssh_command_direct(client, expiry_cmd, hostname)
                        if expiry_exit_status != 0:
                            reset_logger.error(f"Failed to disable account expiry on {hostname}: exit_status={expiry_exit_status}, error={expiry_error}")
                            failure_count += 1
                            continue
                        reset_logger.info(f"Disabled account expiry for Oracle on {hostname}: {expiry_output}")
                        action_taken = True
                    if action_taken:
                        reset_logger.info(f"Processed {hostname} ({component_type}): Password {'reset' if password_expired else 'not expired'}, Account {'unlocked' if account_locked else 'not locked'}")
                        success_count += 1
                    else:
                        reset_logger.info(f"No action needed for {hostname} ({component_type}): Password not expired, Account not locked")
                        success_count += 1
                finally:
                    SSH_POOL.release_client(client)
            except Exception as e:
                reset_logger.error(f"Error processing {hostname} ({component_type}): {str(e)}")
                failure_count += 1
                continue
        # Log summary
        reset_logger.info(f"Password reset summary: {success_count} successful, {failure_count} failed, {skipped_count} skipped")
        # Update JOB_HISTORY if job_id provided
        if job_id:
            error_msg = f"{failure_count} hosts failed, {skipped_count} skipped" if failure_count > 0 else None
            if error_msg:
                error_msg = error_msg[:3900]  # Truncate to safe length
            cursor.setinputsizes(error=oracledb.LONG_STRING)
            cursor.execute(
                """
                UPDATE MAAMD.JOB_HISTORY
                SET STATUS = :status, ERROR_MESSAGE = :error, RUN_TIME = SYSTIMESTAMP
                WHERE JOB_ID = :job_id
                """,
                {
                    'status': 'Success' if failure_count == 0 else 'Failed',
                    'error': error_msg,
                    'job_id': job_id
                }
            )
            conn.commit()
        return True
    except oracledb.Error as e:
        reset_logger.error(f"Database error: {str(e)}")
        if job_id and cursor:
            cursor.setinputsizes(error=oracledb.LONG_STRING)
            cursor.execute(
                """
                UPDATE MAAMD.JOB_HISTORY
                SET STATUS = 'Failed', ERROR_MESSAGE = :error, RUN_TIME = SYSTIMESTAMP
                WHERE JOB_ID = :job_id
                """,
                {'error': str(e)[:3900], 'job_id': job_id}
            )
            conn.commit()
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            app.config['DB_POOL'].release(conn)

if __name__ == "__main__":
    reset_logger.info("Starting standalone execution of reset_oracle_passwords.py")
    success = check_and_reset_oracle_passwords()
    sys.exit(0 if success else 1)
