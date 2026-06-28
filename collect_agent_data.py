#!/usr/bin/env python3
import os
import sys
import time
import json
import shlex
import socket
import logging
import threading
import subprocess
import re
import traceback
import getpass
import resource
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime, timezone
import pytz
from collections import defaultdict
from queue import Queue, Empty as queue_empty
import oracledb
import paramiko
import select
from paramiko.ssh_exception import SSHException, AuthenticationException, NoValidConnectionsError, BadAuthenticationType
from maa_libraries import get_db_connection, get_credential_silent
# Version: 1.0.5 - 2025-12-04
# Changelog:
# - 1.0.0: Initial version with core functionality for collecting OEM agent data
# - 1.0.1: Added LAST_SUCCESSFUL_UPLOAD and LAST_ATTEMPTED_UPLOAD parsing; converted timestamps to UTC
# - 1.0.2: Added agent_owner field to capture the owner of the agent home directory
# - 1.0.3: Fixed HOST_LOCK not defined error by adding global threading.Lock (2025-05-30)
# - 1.0.5: Complete rewrite of agent discovery for 2025 — finds every agent home anywhere on host
# Constants
DB_USER = "maamd"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
ORACLE_USER = "oracle"
ROOT_USER = "root"
ALTERNATIVE_USERS = ["oraha", "orarom", "michaf2", "orarom1+"]
SSH_AUTH_FAIL_LIMIT = 2
SSH_RETRIES = 1
SSH_TIMEOUT = 30
SSH_BANNER_TIMEOUT = 30
SSH_RETRY_DELAY = 5
SSH_COMMAND_TIMEOUT = 30
AGENT_HOME_CHECK_WORKERS = 10
MAX_WORKERS = 50
MAX_HOSTS = 1000
HOST_TIMEOUT = 150
DEBUG_MODE = False
SSH_KEYS = [
    ("/home/maatest/.ssh/id_rsa", "rsa"),
    ("/home/maatest/.ssh/id_ed25519", "ed25519"),
    ("/home/maatest/.ssh/id_ecdsa", "ecdsa")
]
# Global variables
DNS_CACHE = {}
UUID_FQDN_CACHE = {}
CREDENTIAL_CACHE = {}
SKIPPED_HOSTS = {}
PROCESSED_HOSTS = set()
PROCESSED_AGENT_HOMES = set()
CONNECTION_POOL = Queue(maxsize=50)
CONNECTION_POOL_LOCK = threading.Lock()
HOST_LOCK = threading.Lock() # Added to fix 'HOST_LOCK not defined'
LOG_FILE = os.path.join(os.path.dirname(__file__), "output", "collect_agent_data.log")
DB_PASSWORD = os.environ.get("DB_PASSWORD", None)
if not DB_PASSWORD:
    logging.critical("Environment variable DB_PASSWORD is not set")
    sys.exit(1)
# Logging setup
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE)
        ]
    )
    paramiko_logger = logging.getLogger('paramiko')
    paramiko_logger.setLevel(logging.WARNING)
def log(message):
    logging.info(message)
setup_logging()
# SSH Connection Pool
class SSHConnectionPool:
    def __init__(self, max_size=20):
        self.pool = Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.max_size = max_size
    def get_client(self, hostname, component_type="GUEST"):
        with self.lock:
            if not ping_host(hostname):
                log(f"Skipping {hostname}: ping failed or high latency")
                return None
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            log(f"Open file descriptor limit for {hostname}: {soft}/{hard}")
            try:
                client = self.pool.get_nowait()
                transport = client.get_transport()
                if transport.is_active():
                    stdin, stdout, stderr = client.exec_command("whoami", timeout=SSH_TIMEOUT)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        log(f"Reusing SSH connection for {hostname} (pool size: {self.pool.qsize()})")
                        transport.send_ignore()
                        return client
                    log(f"SSH session for {hostname} is invalid, closing")
                client.close()
            except queue_empty:
                pass
            except Exception as e:
                log(f"Error reusing SSH connection for {hostname}: {e}")
            for attempt in range(SSH_RETRIES):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connected = False
                allowed_auth_types = ['publickey', 'password']
                log(f"Assuming allowed authentication types for {hostname}: {allowed_auth_types}")
                for username in [ORACLE_USER, ROOT_USER] + ALTERNATIVE_USERS:
                    keys = []
                    for key_path, key_type in SSH_KEYS:
                        if os.path.isfile(key_path):
                            try:
                                if key_type == "rsa":
                                    key = paramiko.RSAKey.from_private_key_file(key_path)
                                elif key_type == "ecdsa":
                                    key = paramiko.ECDSAKey.from_private_key_file(key_path)
                                elif key_type == "ed25519":
                                    key = paramiko.Ed25519Key.from_private_key_file(key_path)
                                keys.append((key, key_type))
                            except Exception as e:
                                log(f"Failed to load SSH key {key_path}: {e}")
                    key_success = False
                    for key, key_type in keys:
                        log(f"Attempting SSH key auth for {hostname} with {key_type} as {username}, attempt {attempt+1}/{SSH_RETRIES}")
                        try:
                            client.connect(
                                hostname, username=username, pkey=key,
                                timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT,
                                look_for_keys=True, allow_agent=False
                            )
                            client.get_transport().set_keepalive(30)
                            banner = client.get_transport().remote_version
                            log(f"SSH banner for {hostname}: {banner}")
                            log(f"SSH key auth successful for {hostname} with {key_type} as {username}")
                            connected = True
                            key_success = True
                            break
                        except AuthenticationException as e:
                            log(f"Attempt {attempt+1}/{SSH_RETRIES} - SSH key auth failed for {hostname}: {e}")
                            if "transport shut down or saw EOF" in str(e):
                                log(f"Suggestion: Check SSH server config on {hostname}")
                        except SSHException as e:
                            log(f"Attempt {attempt+1}/{SSH_RETRIES} - SSH protocol error for {hostname}: {e}")
                        except Exception as e:
                            log(f"Attempt {attempt+1}/{SSH_RETRIES} - Unexpected SSH error: {e}")
                    if connected:
                        break
                    if 'password' not in allowed_auth_types:
                        log(f"Skipping password auth for {hostname} as {username}: only publickey allowed")
                        continue
                    default_key = (component_type, "default", username)
                    password = CREDENTIAL_CACHE.get(default_key)
                    if not keys and not password:
                        log(f"Skipping {username} for {hostname}: no valid credentials available")
                        continue
                    if password:
                        log(f"Attempting SSH default password auth for {hostname} as {username}, attempt {attempt+1}/{SSH_RETRIES}")
                        try:
                            client.connect(
                                hostname, username=username, password=password,
                                timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT
                            )
                            client.get_transport().set_keepalive(30)
                            banner = client.get_transport().remote_version
                            log(f"SSH banner for {hostname}: {banner}")
                            log(f"Default password auth successful for {hostname} as {username}")
                            connected = True
                            break
                        except BadAuthenticationType as e:
                            log(f"Password auth not allowed for {hostname}: {e}")
                            break
                        except AuthenticationException as e:
                            log(f"Default password auth failed: {e}")
                        except Exception as e:
                            log(f"Default password error: {e}")
                    if not connected:
                        conn = get_db_connection(DB_USER, DB_PASSWORD, DB_DSN)
                        cursor = conn.cursor()
                        try:
                            password = get_credential_silent(cursor, component_type, hostname, username)
                            if password:
                                CREDENTIAL_CACHE[(component_type, hostname, username)] = password
                                log(f"Attempting SSH host-specific password auth for {hostname} as {username}")
                                try:
                                    client.connect(
                                        hostname, username=username, password=password,
                                        timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT
                                    )
                                    client.get_transport().set_keepalive(30)
                                    banner = client.get_transport().remote_version
                                    log(f"SSH banner for {hostname}: {banner}")
                                    log(f"Host-specific password auth successful for {hostname} as {username}")
                                    connected = True
                                except BadAuthenticationType as e:
                                    log(f"Password auth not allowed: {e}")
                                    break
                                except AuthenticationException as e:
                                    log(f"Host-specific password auth failed: {e}")
                                except Exception as e:
                                    log(f"Host-specific password auth error: {e}")
                            else:
                                log(f"No host-specific password for {component_type}:{hostname}:{username}")
                        finally:
                            cursor.close()
                            conn.close()
                    if connected:
                        break
                if connected:
                    try:
                        stdin, stdout, stderr = client.exec_command(
                            "grep -E 'MaxSessions|MaxStartups|ClientAliveInterval' /etc/ssh/sshd_config || echo 'Not configured'",
                            timeout=SSH_TIMEOUT
                        )
                        ssh_limits = stdout.read().decode().strip()
                        log(f"SSH server limits for {hostname}: {ssh_limits}")
                    except Exception as e:
                        log(f"Failed to check SSHD config for {hostname}: {e}")
                    return client
                log(f"Attempt {attempt+1}/{SSH_RETRIES} - Failed to connect to {hostname}")
                client.close()
                if attempt < SSH_RETRIES - 1:
                    time.sleep(SSH_RETRY_DELAY)
            log(f"Failed to connect to {hostname} after {SSH_RETRIES} attempts")
            return None
    def release_client(self, client):
        with self.lock:
            if client is None:
                return
            try:
                if self.pool.qsize() < self.max_size and client.get_transport().is_active():
                    self.pool.put(client)
                    log(f"Released SSH client to pool for {client.get_transport().getpeername()[0]}")
                else:
                    client.close()
            except Exception as e:
                log(f"Error releasing SSH client: {e}")
                client.close()
SSH_POOL = SSHConnectionPool(max_size=20)
def load_dns_cache():
    try:
        cache_file = os.path.join(os.path.dirname(__file__), "dns_cache.json")
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                global DNS_CACHE
                DNS_CACHE = json.load(f)
                log(f"Loaded DNS cache with {len(DNS_CACHE)} entries")
    except Exception as e:
        log(f"Error loading DNS cache: {e}")
def save_dns_cache():
    try:
        cache_file = os.path.join(os.path.dirname(__file__), "dns_cache.json")
        with open(cache_file, 'w') as f:
            json.dump(DNS_CACHE, f, indent=2)
        log(f"Saved DNS cache with {len(DNS_CACHE)} entries")
    except Exception as e:
        log(f"Error saving DNS cache: {e}")
def load_uuid_fqdn_cache(conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT uuid, fqdn FROM maamd.uuid_fqdn_cache")
            for uuid, fqdn in cursor.fetchall():
                UUID_FQDN_CACHE[uuid] = fqdn
            log(f"Loaded {len(UUID_FQDN_CACHE)} UUID-to-FQDN mappings")
    except oracledb.Error as e:
        log(f"Error loading UUID-FQDN cache: {e}")
def save_uuid_fqdn_cache(uuid, fqdn, conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO maamd.uuid_fqdn_cache (uuid, fqdn, last_updated)
                VALUES (:1, :2, SYSDATE)
                ON CONFLICT (uuid) DO UPDATE
                SET fqdn = :2, last_updated = SYSDATE
                """,
                (uuid, fqdn)
            )
            conn.commit()
            UUID_FQDN_CACHE[uuid] = fqdn
            log(f"Cached UUID {uuid} to FQDN {fqdn}")
    except oracledb.Error as e:
        log(f"Error saving UUID-FQDN cache for {uuid}: {e}")
def classify_host(hostname):
    hostname = hostname.lower()
    if 'celadm' in hostname:
        return 'storage_server'
    if 'adm' in hostname or 'dv' in hostname or 'vm' in hostname:
        return 'database_server'
    if 'ilom' in hostname or '-c' in hostname:
        return 'ilom'
    return 'unknown'
def resolve_hostname(hostname, conn):
    if hostname in DNS_CACHE:
        log(f"Using cached DNS result for {hostname}: {DNS_CACHE[hostname]}")
        return DNS_CACHE[hostname]
    try:
        socket.gethostbyname(hostname)
        DNS_CACHE[hostname] = True
        log(f"Resolved hostname {hostname}")
        return True
    except socket.gaierror:
        DNS_CACHE[hostname] = False
        log(f"Failed to resolve hostname {hostname}")
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    MERGE INTO maamd.unresolvable_hosts uh
                    USING (SELECT :host AS hostname FROM dual) src
                    ON (uh.hostname = src.hostname)
                    WHEN MATCHED THEN
                        UPDATE SET failure_count = failure_count + 1,
                            last_failed = SYSDATE
                    WHEN NOT MATCHED THEN
                        INSERT (hostname, failure_count, first_failed, last_failed)
                        VALUES (src.hostname, 1, SYSDATE, SYSDATE)
                    """,
                    {"host": hostname}
                )
                cursor.execute(
                    "SELECT failure_count FROM maamd.unresolvable_hosts WHERE hostname = :1",
                    (hostname,)
                )
                row = cursor.fetchone()
                failure_count = row[0] if row else 1
                if failure_count >= 2:
                    cursor.execute(
                        "DELETE FROM maamd.system_allocations WHERE system_name = :1",
                        (hostname,)
                    )
                    deleted = cursor.rowcount
                    cursor.execute(
                        "DELETE FROM maamd.guests WHERE hostname = :1",
                        (hostname,)
                    )
                    deleted += cursor.rowcount
                    log(f"Removed {hostname} from database after {failure_count} DNS failures (deleted {deleted} rows)")
                conn.commit()
        except oracledb.Error as e:
            log(f"Error updating unresolvable_hosts for {hostname}: {e}")
        return False
def ping_host(hostname):
    try:
        cmd = ["ping", "-c", "4", "-W", "1", hostname]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        log(f"Ping result for {hostname}: {result.stdout}")
        if result.returncode != 0:
            log(f"Ping failed for {hostname}: Return code {result.returncode}, stderr: {result.stderr}")
            return False
        avg_rtt = None
        packet_loss = None
        for line in result.stdout.splitlines():
            if "rtt min/avg/max/mdev" in line:
                match = re.match(r".*rtt min/avg/max/mdev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)", line)
                if match:
                    avg_rtt = float(match.group(2))
                    log(f"Parsed average RTT for {hostname}: {avg_rtt}ms")
                    if avg_rtt > 100:
                        log(f"High latency for {hostname}: average RTT {avg_rtt}ms")
                        return False
            if "% packet loss" in line:
                packet_loss = re.search(r"(\d+)% packet loss", line)
                if packet_loss and int(packet_loss.group(1)) > 0:
                    log(f"Packet loss for {hostname}: {packet_loss.group(1)}%")
                    return False
        return True
    except subprocess.TimeoutExpired:
        log(f"Ping timeout for {hostname}")
        return False
    except Exception as e:
        log(f"Ping error for {hostname}: {e}")
        return False
def resolve_uuid_to_fqdn(uuid, conn, connection_cache):
    if uuid in UUID_FQDN_CACHE:
        log(f"Using cached UUID-FQDN mapping for {uuid}: {UUID_FQDN_CACHE[uuid]}")
        return UUID_FQDN_CACHE[uuid]
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT LOWER(HOSTNAME)
                FROM maamd.guests
                WHERE HOSTNAME = :uuid
                AND EXISTS (
                    SELECT 1
                    FROM maamd.system_allocations sa
                    WHERE sa.SYSTEM_NAME = maamd.guests.HYPERVISOR
                )
                """,
                {"uuid": uuid}
            )
            result = cursor.fetchone()
            if result and result[0] != uuid.lower():
                fqdn = result[0]
                save_uuid_fqdn_cache(uuid, fqdn, conn)
                return fqdn
    except oracledb.Error as e:
        log(f"Error checking guests table for UUID {uuid}: {e}")
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT LOWER(hypervisor)
                FROM maamd.guests
                WHERE HOSTNAME = :uuid
                """,
                {"uuid": uuid}
            )
            result = cursor.fetchone()
            if result:
                hypervisor = result[0]
                log(f"Found hypervisor {hypervisor} for UUID {uuid}")
                client = SSH_POOL.get_client(hypervisor, "PHYSICAL_HOST")
                if client:
                    try:
                        cmd = f"virsh list --all | grep {uuid} | awk '{{print $2}}'"
                        stdin, stdout, stderr = execute_ssh_command(client, cmd, hypervisor)
                        if stdout:
                            vm_name = stdout.strip()
                            if vm_name:
                                fqdn = resolve_hostname(vm_name, conn)
                                if fqdn:
                                    save_uuid_fqdn_cache(uuid, vm_name, conn)
                                    return vm_name
                        error = stderr.strip() if stderr else ""
                        if error:
                            log(f"Error querying virsh on {hypervisor} for UUID {uuid}: {error}")
                    finally:
                        SSH_POOL.release_client(client)
    except oracledb.Error as e:
        log(f"Error retrieving hypervisor for UUID {uuid}: {e}")
    SKIPPED_HOSTS[uuid] = "Failed to resolve UUID to FQDN"
    log(f"Failed to resolve UUID {uuid} to FQDN")
    return None
def validate_host(host, conn, connection_cache):
    log(f"Validating host {host}")
    if re.match(r'^[0-9a-f]{32}$', host) or re.match(r'^0004fb00.*$', host):
        log(f"Host {host} is a UUID, attempting to resolve to FQDN")
        fqdn = resolve_uuid_to_fqdn(host, conn, connection_cache)
        if not fqdn:
            SKIPPED_HOSTS[host] = "Failed to resolve UUID to FQDN"
            log(f"Skipping host {host}: failed to resolve UUID to FQDN")
            return False, host
        host = fqdn
    log(f"Pinging host {host}")
    if not ping_host(host):
        SKIPPED_HOSTS[host] = "Ping failed"
        log(f"Skipping host {host}: ping failed")
        return False, host
    if not resolve_hostname(host, conn):
        SKIPPED_HOSTS[host] = "DNS resolution failed"
        log(f"Skipping host {host}: DNS resolution failed")
        return False, host
    return True, host
def execute_ssh_command(client, command, hostname, run_as_oracle=None, retries=SSH_RETRIES):
    if client is None or client.get_transport() is None or not client.get_transport().is_active():
        log(f"Invalid or closed SSH client for {hostname}")
        return None, None, None
    backoff = SSH_RETRY_DELAY
    for attempt in range(retries):
        try:
            log(f"Executing command on {hostname}: {command}, attempt {attempt + 1}")
            if run_as_oracle and client.get_transport().get_username() != run_as_oracle:
                if not isinstance(run_as_oracle, str):
                    log(f"Invalid run_as_oracle value for {hostname}: {run_as_oracle}")
                    return None, None, None
                command = f"su - {run_as_oracle} -c {shlex.quote(command)}"
                log(f"{hostname}: Attempting command as {run_as_oracle} via su: {command}")
            stdin, stdout, stderr = client.exec_command(command, timeout=SSH_COMMAND_TIMEOUT)
            stdout.channel.settimeout(SSH_COMMAND_TIMEOUT)
            output = []
            error = []
            while not stdout.channel.exit_status_ready():
                rlist, _, _ = select.select([stdout.channel], [], [], SSH_COMMAND_TIMEOUT)
                if not rlist:
                    raise TimeoutError("SSH read timeout")
                if stdout.channel.recv_ready():
                    output.append(stdout.channel.recv(65536).decode('utf-8', errors='ignore'))
                if stdout.channel.recv_stderr_ready():
                    error.append(stderr.channel.recv_stderr(65536).decode('utf-8', errors='ignore'))
            while stdout.channel.recv_ready():
                output.append(stdout.channel.recv(65536).decode('utf-8', errors='ignore'))
            while stdout.channel.recv_stderr_ready():
                error.append(stderr.channel.recv_stderr(65536).decode('utf-8', errors='ignore'))
            exit_status = stdout.channel.recv_exit_status()
            log(f"Command exit status for {hostname}: {exit_status}")
            client.get_transport().set_keepalive(30)
            return stdin, ''.join(output), ''.join(error)
        except (SSHException, EOFError, socket.timeout, TimeoutError) as e:
            if attempt < retries - 1:
                log(f"Retrying command due to error on {hostname}: {e}")
                try:
                    client.close()
                except:
                    pass
                client = SSH_POOL.get_client(hostname, "GUEST" if "vm" in hostname.lower() else "PHYSICAL_HOST")
                if not client:
                    log(f"Failed to reconnect for {hostname} after error")
                    return None, None, None
                time.sleep(backoff)
                backoff *= 1.5
                continue
            log(f"Failed to execute command on {hostname}: {e}")
            return None, None, None
    log(f"Exhausted retries for command execution on {hostname}")
    return None, None, None
def check_agent_home(args):
    client, agent_home, hostname = args
    try:
        cmd = f"test -d {shlex.quote(agent_home)} && echo 'exists' || echo 'missing'"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle="oracle")
        if stdout:
            result = stdout.strip()
            log(f"{hostname}: Agent home {agent_home} check: {result}")
            return (agent_home, result == 'exists')
        log(f"{hostname}: Failed to check agent home {agent_home}: {stderr}")
        return (agent_home, False)
    except Exception as e:
        log(f"{hostname}: Error checking agent home {agent_home}: {e}")
        return (agent_home, False)
def check_user(hostname, username, conn, connection_cache):
    client = SSH_POOL.get_client(hostname, "GUEST" if "vm" in hostname.lower() else "PHYSICAL_HOST")
    if client:
        try:
            cmd = "id"
            stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=username)
            if stdout:
                output = stdout.strip()
                log(f"{hostname}: User {username} exists, id output: {output}")
                return True
            error = stderr.strip() if stderr else "Unknown error"
            log(f"{hostname}: Failed to verify user {username} existence: {error}")
            if "user oracle does not exist" in error.lower():
                log(f"{hostname}: Warning: User {username} does not exist on host")
                return False
            return True
        except Exception as e:
            log(f"{hostname}: Error checking user {username}: {e}")
        finally:
            SSH_POOL.release_client(client)
    log(f"{hostname}: User {username} does not exist or is not accessible via SSH")
    return False
def get_historical_agent_data(hostname, conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT hostname, pid, "PID_TM", port, agent_home, oms_url,
                       TO_CHAR(install_date, 'YYYY-MM-DD HH24:MI:SS'),
                       total_space_mb, cpu_usage_percent, memory_usage_mb,
                       target_count, agent_version, oms_version, heartbeat_status,
                       running_duration_hours, agent_status
                FROM maamd.agent_home_info
                WHERE hostname = :1
                AND created_date >= SYSDATE - 1
                """,
                (hostname,)
            )
            agent_data = []
            for row in cursor.fetchall():
                row_str = ','.join(str(x) if x is not None else 'None' for x in row)
                agent_data.append(row_str)
            log(f"{hostname}: Retrieved {len(agent_data)} historical agent data entries")
            return agent_data
    except oracledb.Error as e:
        log(f"Error retrieving historical agent data for {hostname}: {e}")
        return []
def get_agent_install_date(client, agent_home, hostname, effective_user):
    try:
        cmd = (
            f"test -f {shlex.quote(agent_home)}/install.log && "
            f"grep 'Installation completed successfully' {shlex.quote(agent_home)}/install.log | head -n 1"
        )
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=effective_user)
        if stdout:
            output = stdout.strip()
            error = stderr.strip() if stderr else ""
            if error:
                log(f"{hostname}: Error checking install date for {agent_home}: {error}")
            if output:
                match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)', output)
                if match:
                    install_date = datetime.strptime(match.group(1), '%b %d %H:%M:%S %Y')
                    install_date = install_date.replace(tzinfo=timezone.utc)
                    log(f"{hostname}: Install date from install.log for {agent_home}: {install_date}")
                    return install_date
        log(f"{hostname}: install.log not found or no install date for {agent_home}")
        cmd = f"stat -c %Y {shlex.quote(agent_home)} 2>/dev/null"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=effective_user)
        if stdout:
            output = stdout.strip()
            if output:
                timestamp = int(output)
                install_date = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                log(f"{hostname}: Install date from directory creation for {agent_home}: {install_date}")
                return install_date
        log(f"{hostname}: Failed to get install date for {agent_home}")
        return None
    except Exception as e:
        log(f"{hostname}: Error getting install date for {agent_home}: {e}")
        return None
def get_agent_space(client, agent_home, hostname, effective_user):
    try:
        cmd = f"du -sm {shlex.quote(agent_home)} 2>/dev/null | cut -f1"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=effective_user)
        if stdout:
            output = stdout.strip()
            error = stderr.strip() if stderr else ""
            if error:
                log(f"{hostname}: Error getting disk space for {agent_home}: {error}")
            if output:
                space_mb = int(output)
                log(f"{hostname}: Disk space for {agent_home}: {space_mb} MB")
                return space_mb
        log(f"{hostname}: Failed to get disk space for {agent_home}")
        return None
    except Exception as e:
        log(f"{hostname}: Error getting disk space for {agent_home}: {e}")
        return None
def get_agent_cpu_memory(client, emwd_pid, tm_pid, hostname, effective_user):
    try:
        pids = [emwd_pid]
        if tm_pid != "Unknown":
            pids.append(tm_pid)
        pid_list = ','.join(pids)
        cmd = f"ps -p {pid_list} -o %cpu,rss 2>/dev/null | tail -n +2"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=effective_user)
        if stdout:
            output = stdout.strip()
            error = stderr.strip() if stderr else ""
            if error:
                log(f"{hostname}: Error getting CPU/memory for PIDs {pid_list}: {error}")
            if output:
                cpu_total = 0.0
                memory_total = 0.0
                for line in output.splitlines():
                    cpu, rss = line.strip().split()
                    cpu_total += float(cpu)
                    memory_total += float(rss) / 1024
                log(f"{hostname}: CPU: {cpu_total}% and Memory: {memory_total} MB for PIDs {pid_list}")
                return cpu_total, memory_total
        log(f"{hostname}: Failed to get CPU/memory for PIDs {pid_list}")
        return None, None
    except Exception as e:
        log(f"{hostname}: Error getting CPU/memory for PIDs {pid_list}: {e}")
        return None, None
def get_agent_owner(client, agent_home, hostname):
    """
    Retrieve the owner of the agent home directory.
    """
    try:
        cmd = f"ls -ld {shlex.quote(agent_home)} | awk '{{print $3}}'"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname)
        if stdout:
            owner = stdout.strip()
            error = stderr.strip() if stderr else ""
            if error:
                log(f"{hostname}: Error getting owner for {agent_home}: {error}")
            if owner:
                log(f"{hostname}: Owner for {agent_home}: {owner}")
                return owner
        log(f"{hostname}: Failed to get owner for {agent_home}")
        return None
    except Exception as e:
        log(f"{hostname}: Error getting owner for {agent_home}: {e}")
        return None
def get_agent_metrics(client, agent_home, hostname, effective_user):
    try:
        cmd = f"test -f {shlex.quote(agent_home)}/bin/emctl && echo 'exists' || echo 'missing'"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=effective_user)
        if stdout and stdout.strip() != 'exists':
            log(f"{hostname}: emctl not found at {agent_home}/bin/emctl")
            return None, None, None, None, None, None, None, None, None, None, None, None
        cmd = f"{shlex.quote(agent_home)}/bin/emctl status agent"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname, run_as_oracle=effective_user)
        if stdout:
            output = stdout.strip()
            error = stderr.strip() if stderr else ""
            log(f"{hostname}: Full emctl status for {agent_home}: {output}")
            if error:
                log(f"{hostname}: emctl status error for {agent_home}: {error}")
            oms_url = None
            target_count = None
            agent_version = None
            oms_version = None
            heartbeat_status = None
            running_duration = None
            port = None
            agent_pid = None
            parent_pid = None
            agent_status = None
            last_successful_upload = None
            last_attempted_upload = None
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Agent URL"):
                    match = re.search(r':(\d+)/emd/main/', line)
                    if match:
                        port = int(match.group(1))
                        log(f"{hostname}: Parsed agent port {port} from Agent URL {line} for {agent_home}")
                elif line.startswith("Repository URL"):
                    oms_url = line.split(":", 1)[1].strip()
                elif line.startswith("Number of Targets"):
                    try:
                        target_count = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        log(f"{hostname}: Failed to parse Number of Targets: {line}")
                elif line.startswith("Agent Version"):
                    agent_version = line.split(":", 1)[1].strip()
                elif line.startswith("OMS Version"):
                    oms_version = line.split(":", 1)[1].strip()
                elif line.startswith("Heartbeat Status"):
                    heartbeat_status = line.split(":", 1)[1].strip()
                elif line.startswith("Started at"):
                    try:
                        start_time = datetime.strptime(line.split(":", 1)[1].strip(), '%Y-%m-%d %H:%M:%S')
                        start_time = start_time.replace(tzinfo=pytz.UTC)
                        running_duration = (datetime.now(timezone.utc) - start_time).total_seconds() / 3600
                        if running_duration < 0:
                            log(f"{hostname}: Negative running duration detected for {agent_home}: {running_duration} hours")
                            running_duration = 0.0
                    except ValueError:
                        log(f"{hostname}: Failed to parse Started at: {line}")
                elif line.startswith("Agent Process ID"):
                    try:
                        agent_pid = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        log(f"{hostname}: Failed to parse Agent Process ID: {line}")
                elif line.startswith("Parent Process ID"):
                    try:
                        parent_pid = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        log(f"{hostname}: Failed to parse Parent Process ID: {line}")
                elif line.startswith("Agent is") or "Running" in line:
                    agent_status = line
                elif line.startswith("Last successful upload"):
                    try:
                        timestamp_str = line.split(":", 1)[1].strip()
                        last_successful_upload = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        last_successful_upload = last_successful_upload.replace(tzinfo=pytz.UTC)
                        log(f"{hostname}: Parsed last successful upload: {last_successful_upload} for {agent_home}")
                    except ValueError:
                        log(f"{hostname}: Failed to parse last successful upload: {line}")
                elif line.startswith("Last attempted upload"):
                    try:
                        timestamp_str = line.split(":", 1)[1].strip()
                        last_attempted_upload = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        last_attempted_upload = last_attempted_upload.replace(tzinfo=pytz.UTC)
                        log(f"{hostname}: Parsed last attempted upload: {last_attempted_upload} for {agent_home}")
                    except ValueError:
                        log(f"{hostname}: Failed to parse last attempted upload: {line}")
            if agent_status:
                if "Agent is Running and Ready" in agent_status:
                    agent_status = "running"
                elif "Agent is Running but Not Ready" in agent_status:
                    agent_status = "running_not_ready"
                elif "Agent is Not Running" in agent_status:
                    agent_status = "stopped"
                else:
                    agent_status = f"error: {agent_status}"
            if agent_status == "stopped":
                agent_pid = None
                parent_pid = None
                running_duration = None
                cpu_percent = None
                memory_mb = None
            return (oms_url, target_count, agent_version, oms_version, heartbeat_status,
                    running_duration, port, agent_pid, parent_pid, agent_status,
                    last_successful_upload, last_attempted_upload)
        log(f"{hostname}: Failed to get agent metrics for {agent_home}")
        return None, None, None, None, None, None, None, None, None, None, None, None
    except Exception as e:
        log(f"{hostname}: Error getting agent metrics for {agent_home}: {e}")
        return None, None, None, None, None, None, None, None, None, None, None, None
def derive_ilom_name(hostname, conn):
    try:
        base_hostname = hostname.split('vm')[0] if 'vm' in hostname else hostname
        log(f"Using base hostname {base_hostname} for ILOM derivation of {hostname}")
        ilom_hostname = f"{base_hostname}-ilom.us.oracle.com"
        try:
            ip_address = socket.gethostbyname(ilom_hostname)
            log(f"Resolved ILOM {ilom_hostname} to {ip_address} for {hostname}")
            return ip_address
        except socket.gaierror:
            ilom_hostname_alt = base_hostname.replace('.us.oracle.com', '-ilom.us.oracle.com')
            try:
                ip_address = socket.gethostbyname(ilom_hostname_alt)
                log(f"Resolved alternative ILOM {ilom_hostname_alt} to {ip_address} for {hostname}")
                return ip_address
            except socket.gaierror:
                log(f"No resolvable ILOM found for {ilom_hostname} or {ilom_hostname_alt}")
                return None
    except socket.gaierror:
        log(f"Failed to resolve ILOM for {hostname}")
        return None
    except Exception as e:
        log(f"Error deriving ILOM for {hostname}: {e}")
        return None
def truncate_agent_hosts(conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO maamd.agent_hosts_history (hostname, ilom_ip, server_type_id, is_hypervisor, created_date, last_updated_date, archived_date)
                SELECT hostname, ilom_ip, TO_CHAR(server_type_id), is_hypervisor, created_date, last_updated_date, SYSDATE
                FROM maamd.agent_hosts
                """
            )
            archived_count = cursor.rowcount
            log(f"Archived {archived_count} rows to maamd.agent_hosts_history")
            cursor.execute("TRUNCATE TABLE maamd.agent_hosts")
            conn.commit()
            log("Truncated maamd.agent_hosts")
    except oracledb.Error as e:
        log(f"Error truncating agent_hosts: {e}")
def clean_agent_home_info(conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM maamd.agent_home_info
                WHERE created_date < SYSDATE - 7
                """
            )
            deleted_count = cursor.rowcount
            conn.commit()
            log(f"Deleted {deleted_count} agent records older than 7 days from maamd.agent_home_info")
    except oracledb.Error as e:
        log(f"Error cleaning agent_home_info: {e}")
def clean_stale_snmp_subscriptions(hostname, deleted_homes, conn):
    try:
        with conn.cursor() as cursor:
            placeholders = ','.join([':p' + str(i+1) for i in range(len(deleted_homes))])
            query = f"""
                DELETE FROM maamd.snmp_subscriptions
                WHERE ilom_hostname = :host
                AND agent_home IN ({placeholders})
            """
            params = {'host': hostname}
            for i, home in enumerate(deleted_homes):
                params[f'p{i+1}'] = home
            cursor.execute(query, params)
            deleted_count = cursor.rowcount
            conn.commit()
            log(f"{hostname}: Deleted {deleted_count} stale SNMP subscriptions for homes: {', '.join(deleted_homes)}")
    except oracledb.Error as e:
        log(f"{hostname}: Error cleaning stale SNMP subscriptions: {e}")
def clean_stale_hosts(valid_hosts, conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute("CREATE GLOBAL TEMPORARY TABLE temp_hosts (hostname VARCHAR2(255)) ON COMMIT DELETE ROWS")
            for host in valid_hosts:
                cursor.execute("INSERT INTO temp_hosts (hostname) VALUES (:1)", (host,))
            cursor.execute("SELECT COUNT(*) FROM temp_hosts")
            inserted_count = cursor.fetchone()[0]
            log(f"Inserted {inserted_count} hostnames into temp_hosts for stale host cleanup")
            cursor.execute(
                """
                DELETE FROM maamd.agent_home_info
                WHERE hostname NOT IN (
                    SELECT hostname FROM temp_hosts
                )
                """
            )
            deleted_count = cursor.rowcount
            conn.commit()
            log(f"Deleted {deleted_count} stale agent records for non-existent hosts")
            cursor.execute("DROP TABLE temp_hosts")
            conn.commit()
    except oracledb.Error as e:
        log(f"Error cleaning stale hosts: {e}")
        try:
            with conn.cursor() as cursor:
                cursor.execute("DROP TABLE temp_hosts")
                conn.commit()
        except oracledb.Error:
            pass
def get_non_hypervisor_hosts(conn):
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT LOWER(HOSTNAME)
                FROM maamd.HYPERVISORS
                WHERE IS_HYPERVISOR = 'N'
            """)
            non_hypervisor_hosts = {row[0] for row in cursor.fetchall()}
            log(f"Retrieved {len(non_hypervisor_hosts)} non-hypervisor hosts from maamd.HYPERVISORS")
            return non_hypervisor_hosts
    except oracledb.Error as e:
        log(f"Error fetching non-hypervisor hosts: {e}")
        return set()
def is_hypervisor_ssh(client, hostname):
    try:
        cmd = "ls /EXAVMIMAGES"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname)
        if stdout and not stderr:
            log(f"{hostname}: Detected as hypervisor due to /EXAVMIMAGES")
            return True
        cmd = (
            "ps -ef | grep -E 'qemu-kvm|libvirtd|xenstored|xenconsoled|xend' | grep -v grep >/dev/null && echo 'hypervisor' || echo 'no'"
        )
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname)
        if stdout and stdout.strip() == 'hypervisor':
            log(f"{hostname}: Detected as hypervisor due to virtualization processes")
            return True
        cmd = "test -d /proc/xen && echo 'hypervisor' || echo 'no'"
        stdin, stdout, stderr = execute_ssh_command(client, cmd, hostname)
        if stdout and stdout.strip() == 'hypervisor':
            log(f"{hostname}: Detected as hypervisor due to /proc/xen")
            return True
        log(f"{hostname}: Not a hypervisor")
        return False
    except Exception as e:
        log(f"{hostname}: Error checking hypervisor status via SSH: {e}")
        return False
def process_host(host, conn, non_hypervisor_hosts=None):
    start_time = time.time()
    with HOST_LOCK:
        if host in PROCESSED_HOSTS:
            log(f"Skipping host {host}: already processed by another thread")
            return [], (host, 'unknown', None, 'N')
        PROCESSED_HOSTS.add(host)
    connection_cache = {}
    valid, resolved_host = validate_host(host, conn, connection_cache)
    if not valid:
        log(f"Host {host} failed validation, reason: {SKIPPED_HOSTS.get(host, 'Unknown')}")
        return [], (host, 'unknown', None, 'N')
    host = resolved_host
    host_type = classify_host(host)
    if host_type in ['storage_server', 'ilom']:
        SKIPPED_HOSTS[host] = f"Invalid host type: {host_type}"
        log(f"Skipping host {host}: type {host_type} is not processed for agent data collection")
        return [], (host, 'unknown', None, 'N')
    is_hyp = False
    hostname_lower = host.lower()
    if non_hypervisor_hosts is None:
        non_hypervisor_hosts = get_non_hypervisor_hosts(conn)
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT IS_HYPERVISOR
                FROM maamd.HYPERVISORS
                WHERE LOWER(HOSTNAME) = :1
            """, (hostname_lower,))
            result = cursor.fetchone()
            if result and result[0] == 'Y':
                log(f"{host}: Marked as hypervisor in maamd.HYPERVISORS, processing for agents")
                is_hyp = True
            elif result and result[0] == 'N':
                log(f"{host}: Confirmed as non-hypervisor from maamd.HYPERVISORS")
            else:
                log(f"{host}: Not found in maamd.HYPERVISORS, checking via SSH")
                ssh_client = SSH_POOL.get_client(host, "PHYSICAL_HOST")
                if ssh_client:
                    is_hyp = is_hypervisor_ssh(ssh_client, host)
                    cursor.execute("""
                        MERGE INTO maamd.HYPERVISORS dest
                        USING (SELECT :1 AS HOSTNAME, :2 AS IS_HYPERVISOR FROM dual) src
                        ON (LOWER(dest.HOSTNAME) = LOWER(src.HOSTNAME))
                        WHEN MATCHED THEN
                            UPDATE SET IS_HYPERVISOR = src.IS_HYPERVISOR, LAST_UPDATED_DATE = SYSDATE
                        WHEN NOT MATCHED THEN
                            INSERT (HOSTNAME, IS_HYPERVISOR, CREATED_DATE, LAST_UPDATED_DATE)
                            VALUES (src.HOSTNAME, src.IS_HYPERVISOR, SYSDATE, SYSDATE)
                        """, (host, 'Y' if is_hyp else 'N'))
                    conn.commit()
                    log(f"{host}: Updated maamd.HYPERVISORS with IS_HYPERVISOR = {'Y' if is_hyp else 'N'}")
                    SSH_POOL.release_client(ssh_client)
                else:
                    log(f"{host}: Failed to get SSH client for hypervisor check, assuming non-hypervisor")
                    SKIPPED_HOSTS[host] = "Failed to establish SSH connection for hypervisor check"
    except oracledb.Error as e:
        log(f"{host}: Error checking HYPERVISORS table: {e}")
    physical_host_data = (host, 'unknown', None, 'Y' if is_hyp else 'N')
    if is_hyp:
        log(f"Skipping host {host}: identified as a hypervisor, no OEM agents expected")
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM maamd.agent_home_info WHERE hostname = :1",
                    (host,)
                )
                conn.commit()
                log(f"Deleted {cursor.rowcount} stale agent records for hypervisor {host}")
        except oracledb.Error as e:
            log(f"Error cleaning stale agents for {host}: {e}")
        return [], physical_host_data
    component_type = "GUEST" if "vm" in hostname_lower else "PHYSICAL_HOST"
    client = SSH_POOL.get_client(host, component_type)
    if not client:
        SKIPPED_HOSTS[host] = "Failed to establish SSH connection as any user"
        log(f"Skipping host {host}: failed to establish SSH connection as any user")
        agent_data = get_historical_agent_data(host, conn)
        return agent_data, physical_host_data
    try:
        oracle_user_exists = check_user(host, ORACLE_USER, conn, connection_cache)
        if not oracle_user_exists:
            log(f"{host}: Warning: oracle user does not exist. Skipping OEM agent collection.")
            SKIPPED_HOSTS[host] = "No oracle user found"
            return get_historical_agent_data(host, conn), physical_host_data
        else:
            effective_user = ORACLE_USER
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT agent_home FROM maamd.agent_home_info WHERE hostname = :1",
                    (host,)
                )
                existing_agent_homes = [row[0] for row in cursor.fetchall()]
                log(f"{host}: Found {len(existing_agent_homes)} existing agent homes")
            if existing_agent_homes:
                results = [check_agent_home((client, ah, host)) for ah in existing_agent_homes]
                deleted_homes = [ah for ah, exists in results if exists is False and ah is not None]
                if deleted_homes:
                    try:
                        with conn.cursor() as cursor:
                            placeholders = ','.join([':p' + str(i+1) for i in range(len(deleted_homes))])
                            query = f"""
                                DELETE FROM maamd.agent_home_info
                                WHERE hostname = :host
                                AND agent_home IN ({placeholders})
                            """
                            params = {'host': host}
                            for i, home in enumerate(deleted_homes):
                                params[f'p{i+1}'] = home
                            cursor.execute(query, params)
                            deleted_count = cursor.rowcount
                            conn.commit()
                            log(f"{host}: Deleted {deleted_count} stale agent records (non-existent agent homes: {', '.join(deleted_homes)})")
                            if deleted_count > 0:
                                clean_stale_snmp_subscriptions(host, deleted_homes, conn)
                    except oracledb.Error as e:
                        log(f"{host}: Error cleaning stale agent homes: {e}")
                else:
                    log(f"{host}: No stale agent homes found")
            else:
                log(f"{host}: No existing agent homes to check")
            cmd = (
                "ps -u oracle -f | grep -E '[e]mwd\.pl|[T]MMain' | grep -v grep | "
                "awk '{print $2\",\"$3\",\"$0}' || true"
            )
            stdin, stdout, stderr = execute_ssh_command(client, cmd, host, run_as_oracle=effective_user)
            process_lines = stdout.strip() if stdout else ""
            error = stderr.strip() if stderr else ""
            if error:
                log(f"{host}: Error retrieving process list: {error}")
            if process_lines:
                log(f"{host}: Process list for oracle user: {process_lines[:500]}...")
            else:
                log(f"{host}: No OEM agent processes found for oracle user")
            emwd_processes = {}
            tm_processes = {}
            processed_pids = set()
            if process_lines:
                for line in process_lines.splitlines():
                    if not line.strip():
                        continue
                    parts = line.split(",", 2)
                    if len(parts) < 3:
                        log(f"{host}: Invalid process line format: {line}")
                        continue
                    pid, ppid, cmd = parts[0], parts[1], parts[2]
                    if pid in processed_pids:
                        log(f"{host}: Skipping duplicate PID {pid}")
                        continue
                    processed_pids.add(pid)
                    if "emwd.pl" in cmd:
                        emwd_processes[pid] = {"ppid": ppid, "cmd": cmd, "user": "oracle"}
                        log(f"{host}: Found emwd.pl process PID {pid}")
                    elif "TMMain" in cmd:
                        tm_processes[pid] = {"ppid": ppid, "cmd": cmd, "user": "oracle"}
                        log(f"{host}: Found TMMain process PID {pid}")
            log(f"{host}: Performing path-based search for agent homes")
            common_paths = [
                "/u01/app/oracle/product/*/agent_[0-9][0-9].[0-9].[0-9].[0-9].[0-9]",
                "/u01/app/oracle/em/*/agent_[0-9][0-9].[0-9].[0-9].[0-9].[0-9]",
                "/u02/agents/*/agent_[0-9][0-9].[0-9].[0-9].[0-9].[0-9]",
                "/opt/oracle/*/agent_[0-9][0-9].[0-9].[0-9].[0-9].[0-9]",
                "/exa_manual/*/agent_[0-9][0-9].[0-9].[0-9].[0-9].[0-9]",
                "/exa_auto/*/agent_[0-9][0-9].[0-9].[0-9].[0-9].[0-9]"
            ]
            cmd = (
                f"find {' '.join(common_paths)} -type d -maxdepth 1 -exec test -f {{}}/bin/emctl \\; -print 2>/dev/null"
            )
            stdin, stdout, stderr = execute_ssh_command(client, cmd, host, run_as_oracle=effective_user)
            agent_homes = []
            if stdout:
                output = stdout.strip()
                error = stderr.strip() if stderr else ""
                log(f"{host}: Common agent paths output: {output}")
                if error:
                    log(f"{host}: Common agent paths error: {error}")
                if output:
                    agent_homes = output.splitlines()
            else:
                log(f"{host}: Failed to check common agent paths")
            log(f"{host}: Found {len(agent_homes)} agent homes via path-based search")
            agent_data = []
            processed_agent_homes = set()
            running_pids = set(emwd_processes.keys())
            for emwd_pid, emwd_info in emwd_processes.items():
                user = emwd_info["user"]
                cmd = (
                    f"oh=$(cat /proc/{emwd_pid}/environ 2>/dev/null | tr '\\0' '\\n' | grep '^ORACLE_HOME=' | cut -d= -f2); "
                    f"[ -z \"$oh\" ] && oh=$(echo {shlex.quote(emwd_info['cmd'])} | grep -o '/[^ ]*/agent_[0-9][0-9]\\.[0-9]\\.[0-9]\\.[0-9]\\.[0-9]' | head -1); "
                    f"[ -z \"$oh\" ] && oh=\"Unknown\"; "
                    f"if [ \"$oh\" != \"Unknown\" ]; then test -d \"$oh\" && echo \"$oh:exists\" || echo \"$oh:missing\"; else echo \"$oh:missing\"; fi"
                )
                stdin, stdout, stderr = execute_ssh_command(client, cmd, host, run_as_oracle=effective_user)
                if stdout is None:
                    log(f"{host}: Failed to retrieve ORACLE_HOME for PID {emwd_pid} as {user}")
                    continue
                output = stdout.strip()
                error = stderr.strip() if stderr else ""
                if error:
                    log(f"{host}: Error retrieving ORACLE_HOME for PID {emwd_pid} as {user}: {error}")
                if not output:
                    log(f"{host}: No ORACLE_HOME output for PID {emwd_pid} as {user}")
                    continue
                oh, status = output.split(":", 1)
                log(f"{host}: ORACLE_HOME for PID {emwd_pid} as {user}: {oh}, status: {status}")
                if oh == "Unknown" or status == "missing":
                    log(f"{host}: Skipping agent with {'unknown' if oh == 'Unknown' else 'non-existent'} ORACLE_HOME {oh} for PID {emwd_pid} as {user}")
                    continue
                agent_home_key = (host, oh)
                global_key = (hostname_lower, oh)
                if global_key in PROCESSED_AGENT_HOMES:
                    log(f"{host}: Skipping agent home {oh}: already processed globally")
                    continue
                if agent_home_key in processed_agent_homes:
                    log(f"{host}: Warning: Duplicate emwd.pl process for {oh}, PID {emwd_pid} skipped")
                    continue
                processed_agent_homes.add(agent_home_key)
                PROCESSED_AGENT_HOMES.add(global_key)
                # Get agent home owner
                agent_owner = get_agent_owner(client, oh, host)
                cmd = f"{shlex.quote(oh)}/bin/emctl status agent"
                stdin, stdout, stderr = execute_ssh_command(client, cmd, host, run_as_oracle=effective_user)
                if stdout:
                    status_output = stdout.strip()
                    error = stderr.strip() if stderr else ""
                    if error:
                        log(f"{host}: emctl status error for {oh} as {user}: {error}")
                    log(f"{host}: emctl status for {oh} as {user}: {status_output[:500]}...")
                    agent_pid = None
                    for line in status_output.splitlines():
                        if line.startswith("Agent Process ID"):
                            try:
                                agent_pid = int(line.split(":", 1)[1].strip())
                                break
                            except ValueError:
                                pass
                    if agent_pid and str(agent_pid) != emwd_pid:
                        log(f"{host}: Overriding emwd.pl PID {emwd_pid} with Agent Process ID {agent_pid} from emctl status agent in {oh}")
                        emwd_pid = str(agent_pid)
                else:
                    log(f"{host}: Failed to run emctl status for {oh} as {user}, proceeding with partial data")
                tm_pid = "Unknown"
                for tm_pid_candidate, tm_info in tm_processes.items():
                    if tm_info["ppid"] == emwd_pid and tm_info["user"] == user:
                        tm_pid = tm_pid_candidate
                        log(f"{host}: Matched TMMain PID {tm_pid} to emwd.pl PID {emwd_pid} for user {user}")
                        break
                oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, agent_pid, parent_pid, agent_status, last_successful_upload, last_attempted_upload = get_agent_metrics(client, oh, host, user)
                if agent_pid is not None and str(agent_pid) != emwd_pid:
                    log(f"{host}: Overriding emwd.pl PID {emwd_pid} with Agent Process ID {agent_pid} from emctl status agent in {oh}")
                    emwd_pid = str(agent_pid)
                install_date = get_agent_install_date(client, oh, host, user)
                total_space_mb = get_agent_space(client, oh, host, user)
                cpu_percent, memory_mb = get_agent_cpu_memory(client, emwd_pid, tm_pid, host, user)
                install_date_str = install_date.strftime('%Y-%m-%d %H:%M:%S') if install_date else "None"
                total_space_str = str(total_space_mb) if total_space_mb is not None else "None"
                cpu_percent_str = str(cpu_percent) if cpu_percent is not None else "None"
                memory_mb_str = str(memory_mb) if memory_mb is not None else "None"
                target_count_str = str(target_count) if target_count is not None else "None"
                port_str = str(port) if port is not None else "Unknown"
                oms_url_str = oms_url if oms_url else "Unknown"
                agent_version_str = agent_version if agent_version else "Unknown"
                oms_version_str = oms_version if oms_version else "Unknown"
                heartbeat_status_str = heartbeat_status if heartbeat_status else "Unknown"
                running_duration_str = str(round(running_duration, 2)) if running_duration is not None else "None"
                agent_pid_str = emwd_pid
                parent_pid_str = str(parent_pid) if parent_pid is not None else tm_pid
                agent_status_str = agent_status if agent_status else "Unknown"
                last_successful_upload_str = last_successful_upload.strftime('%Y-%m-%d %H:%M:%S') if last_successful_upload else "None"
                last_attempted_upload_str = last_attempted_upload.strftime('%Y-%m-%d %H:%M:%S') if last_attempted_upload else "None"
                agent_owner_str = agent_owner if agent_owner else "oracle" # Default to oracle if unknown
                agent_data.append(
                    f"{host},{agent_pid_str},{parent_pid_str},{port_str},{oh},{oms_url_str},"
                    f"{install_date_str},{total_space_str},{cpu_percent_str},{memory_mb_str},"
                    f"{target_count_str},{agent_version_str},{oms_version_str},{heartbeat_status_str},"
                    f"{running_duration_str},{agent_status_str},{last_successful_upload_str},{last_attempted_upload_str},{agent_owner_str}"
                )
                log(f"{host}: Collected agent data: PID {agent_pid_str}, TMMain PID {parent_pid_str}, Agent Home {oh}, "
                    f"Owner {agent_owner_str}, Install Date {install_date_str}, Space {total_space_str} MB, CPU {cpu_percent_str}%, "
                    f"Memory {memory_mb_str} MB, Targets {target_count_str}, Agent Version {agent_version_str}, "
                    f"OMS Version {oms_version_str}, Heartbeat Status {heartbeat_status_str}, "
                    f"Running Duration {running_duration_str} hours, Port {port_str}, Status {agent_status_str}, "
                    f"Last Successful Upload {last_successful_upload_str}, Last Attempted Upload {last_attempted_upload_str}")
            for path in agent_homes:
                if path in [oh for _, oh in processed_agent_homes]:
                    log(f"{host}: Skipping already processed agent home {path}")
                    continue
                if path.endswith("/agent_inst"):
                    log(f"{host}: Skipping agent_inst directory {path} to avoid duplication")
                    continue
                agent_home_key = (host, path)
                global_key = (hostname_lower, path)
                if global_key in PROCESSED_AGENT_HOMES:
                    log(f"{host}: Skipping agent home {path}: already processed globally")
                    continue
                if agent_home_key in processed_agent_homes:
                    log(f"{host}: Warning: Duplicate agent home {path} skipped")
                    continue
                processed_agent_homes.add(agent_home_key)
                PROCESSED_AGENT_HOMES.add(global_key)
                log(f"{host}: Checking potential agent home: {path}")
                # Get agent home owner
                agent_owner = get_agent_owner(client, path, host)
                oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, agent_pid, parent_pid, agent_status, last_successful_upload, last_attempted_upload = get_agent_metrics(client, path, host, effective_user)
                if agent_status is None and agent_pid is None:
                    log(f"{host}: No valid agent found in {path}")
                    continue
                install_date = get_agent_install_date(client, path, host, effective_user)
                total_space_mb = get_agent_space(client, path, host, effective_user)
                cpu_percent, memory_mb = None, None
                install_date_str = install_date.strftime('%Y-%m-%d %H:%M:%S') if install_date else "None"
                total_space_str = str(total_space_mb) if total_space_mb is not None else "None"
                cpu_percent_str = "None"
                memory_mb_str = "None"
                target_count_str = str(target_count) if target_count is not None else "None"
                port_str = str(port) if port is not None else "Unknown"
                oms_url_str = oms_url if oms_url else "Unknown"
                agent_version_str = agent_version if agent_version else "Unknown"
                oms_version_str = oms_version if oms_version else "Unknown"
                heartbeat_status_str = heartbeat_status if heartbeat_status else "Unknown"
                running_duration_str = "None"
                agent_pid_str = str(agent_pid) if agent_pid is not None else "None"
                parent_pid_str = str(parent_pid) if parent_pid is not None else "Unknown"
                agent_status_str = agent_status if agent_status else "Stopped"
                last_successful_upload_str = last_successful_upload.strftime('%Y-%m-%d %H:%M:%S') if last_successful_upload else "None"
                last_attempted_upload_str = last_attempted_upload.strftime('%Y-%m-%d %H:%M:%S') if last_attempted_upload else "None"
                agent_owner_str = agent_owner if agent_owner else "oracle"
                agent_data.append(
                    f"{host},{agent_pid_str},{parent_pid_str},{port_str},{path},{oms_url_str},"
                    f"{install_date_str},{total_space_str},{cpu_percent_str},{memory_mb_str},"
                    f"{target_count_str},{agent_version_str},{oms_version_str},{heartbeat_status_str},"
                    f"{running_duration_str},{agent_status_str},{last_successful_upload_str},{last_attempted_upload_str},{agent_owner_str}"
                )
                log(f"{host}: Collected agent data for stopped agent: PID {agent_pid_str}, TMMain PID {parent_pid_str}, Agent Home {path}, "
                    f"Owner {agent_owner_str}, Install Date {install_date_str}, Space {total_space_str} MB, CPU {cpu_percent_str}%, "
                    f"Memory {memory_mb_str} MB, Targets {target_count_str}, Agent Version {agent_version_str}, "
                    f"OMS Version {oms_version_str}, Heartbeat Status {heartbeat_status_str}, "
                    f"Running Duration {running_duration_str} hours, Port {port_str}, Status {agent_status_str}, "
                    f"Last Successful Upload {last_successful_upload_str}, Last Attempted Upload {last_attempted_upload_str}")
            elapsed = time.time() - start_time
            log(f"{host}: Summary: Processed host in {elapsed:.2f} seconds, {len(emwd_processes)} emwd.pl processes found, "
                f"{len(tm_processes)} TMMain processes found, {len(agent_data)} agent homes collected")
            return agent_data, physical_host_data
        finally:
            SSH_POOL.release_client(client)
    except Exception as e:
        log(f"{host}: Error processing: {e}")
        return get_historical_agent_data(host, conn), physical_host_data
    finally:
        for cached_client in list(connection_cache.values()):
            SSH_POOL.release_client(cached_client)
def get_db_servers(conn):
    log("Retrieving database servers")
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT LOWER(SYSTEM_NAME)
                FROM maamd.system_allocations
                WHERE SYSTEM_NAME LIKE '%adm%'
                AND SYSTEM_NAME NOT LIKE '%celadm%'
                AND SYSTEM_NAME IS NOT NULL
                AND SYSTEM_NAME NOT IN (SELECT HOSTNAME FROM maamd.unresolvable_hosts WHERE FAILURE_COUNT >= 2)
            """)
            system_names = [row[0] for row in cursor.fetchall()]
            cursor.execute("""
                SELECT LOWER(HOSTNAME)
                FROM maamd.guests
                WHERE HOSTNAME IS NOT NULL
                AND HOSTNAME NOT IN (SELECT HOSTNAME FROM maamd.unresolvable_hosts WHERE FAILURE_COUNT >= 2)
            """)
            guest_hostnames = [row[0] for row in cursor.fetchall()]
            combined_hosts = list(dict.fromkeys(system_names + guest_hostnames))
            log(f"Retrieved {len(system_names)} system names from system_allocations and "
                f"{len(guest_hostnames)} hostnames from guests. Total unique hosts: {len(combined_hosts)}")
            test_host = 'scaqal02adm01vm01.us.oracle.com'
            if test_host in combined_hosts:
                combined_hosts.remove(test_host)
                combined_hosts.insert(0, test_host)
            combined_hosts = combined_hosts[:MAX_HOSTS]
            log(f"Limited to {len(combined_hosts)} hosts (MAX_HOSTS={MAX_HOSTS}): {', '.join(combined_hosts)}")
            valid_hosts = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                connection_cache = {}
                future_to_host = {executor.submit(validate_host, host, conn, connection_cache): host for host in combined_hosts}
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        valid, resolved_host = future.result()
                        if valid:
                            valid_hosts.append(resolved_host)
                        else:
                            log(f"Host {host} failed validation, added to SKIPPED_HOSTS: {SKIPPED_HOSTS.get(host, 'Unknown reason')}")
                    except Exception as e:
                        log(f"Error validating host {host}: {e}")
            log(f"Validated {len(valid_hosts)} hosts after DNS and ping checks")
            save_dns_cache()
            return valid_hosts
    except oracledb.Error as e:
        log(f"Failed to retrieve database servers from database: {e}")
        return []
def save_physical_host_data(physical_host_data_list, conn):
    log("Saving physical host data")
    if not physical_host_data_list:
        log("No physical host data to insert into maamd.agent_hosts")
        return
    try:
        with conn.cursor() as cursor:
            updated_data = []
            for hostname, _, server_type_id, is_hypervisor in physical_host_data_list:
                derived_ilom_ip = derive_ilom_name(hostname, conn)
                updated_data.append((hostname, derived_ilom_ip if derived_ilom_ip else 'unknown', server_type_id, is_hypervisor))
            cursor.executemany("""
                BEGIN
                    INSERT INTO maamd.agent_hosts (hostname, ilom_ip, server_type_id, is_hypervisor, created_date, last_updated_date)
                    VALUES (:1, :2, :3, :4, SYSDATE, SYSDATE);
                    EXCEPTION WHEN DUP_VAL_ON_INDEX THEN
                        UPDATE maamd.agent_hosts
                        SET ilom_ip = :2,
                            server_type_id = :3,
                            is_hypervisor = :4,
                            last_updated_date = SYSDATE
                        WHERE hostname = :1;
                END;
            """, updated_data)
            conn.commit()
            log(f"Updated {len(updated_data)} rows in agent_hosts with ILOM_IP values")
    except oracledb.Error as e:
        log(f"Database error inserting into agent_hosts: {e}")
def save_agent_data(agent_data, conn):
    log("Saving agent data")
    if not agent_data:
        log("No agent data collected to insert into maamd.agent_home_info")
        return
    try:
        with conn.cursor() as cursor:
            # Truncate agent_home_info table before insertion
            cursor.execute("TRUNCATE TABLE maamd.agent_home_info")
            conn.commit()
            log("Truncated maamd.agent_home_info before inserting new data")
            insert_data = []
            seen = set()
            log(f"Processing {len(agent_data)} agent data entries for insertion")
            for line in agent_data:
                log(f"Preparing agent data for insertion: {line[:500]}...")
                parts = line.split(",", 18) # Handle 19 fields including agent_owner
                if len(parts) != 19:
                    log(f"Invalid data format: {line}")
                    continue
                hostname, emwd_pid, tm_pid, port, agent_home, oms_url, install_date, total_space_mb, cpu_percent, memory_mb, target_count, agent_version, oms_version, heartbeat_status, running_duration, agent_status, last_successful_upload, last_attempted_upload, agent_owner = parts
                key = (hostname.lower(), agent_home)
                if key in seen:
                    log(f"Skipping duplicate agent data for {hostname} in {agent_home}")
                    continue
                seen.add(key)
                try:
                    emwd_pid = int(emwd_pid) if emwd_pid and emwd_pid != 'None' else None
                    tm_pid = int(tm_pid) if tm_pid and tm_pid != 'Unknown' else None
                    port = int(port) if port and port != 'Unknown' else None
                    oms_url = oms_url if oms_url and oms_url != 'Unknown' else None
                    install_date = datetime.strptime(install_date, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc) if install_date and install_date != 'None' else None
                    total_space_mb = int(total_space_mb) if total_space_mb and total_space_mb != 'None' else None
                    cpu_percent = float(cpu_percent) if cpu_percent and cpu_percent != 'None' else None
                    memory_mb = float(memory_mb) if memory_mb is not None and memory_mb != 'None' else None
                    target_count = int(target_count) if target_count and target_count != 'None' else None
                    agent_version = agent_version if agent_version and agent_version != 'Unknown' else None
                    oms_version = oms_version if oms_version and oms_version != 'Unknown' else None
                    heartbeat_status = heartbeat_status if heartbeat_status and heartbeat_status != 'Unknown' else None
                    running_duration = float(running_duration) if running_duration and running_duration != 'None' else None
                    agent_status = agent_status if agent_status and agent_status != 'Unknown' else None
                    last_successful_upload = datetime.strptime(last_successful_upload, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc) if last_successful_upload and last_successful_upload != 'None' else None
                    last_attempted_upload = datetime.strptime(last_attempted_upload, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc) if last_attempted_upload and last_attempted_upload != 'None' else None
                    agent_owner = agent_owner if agent_owner and agent_owner != 'oracle' else 'oracle' # Default to oracle if unknown
                    insert_data.append((
                        hostname, emwd_pid, tm_pid, port, agent_home, DB_USER,
                        oms_url, install_date, total_space_mb, cpu_percent, memory_mb, target_count,
                        agent_version, oms_version, heartbeat_status, running_duration, agent_status,
                        last_successful_upload, last_attempted_upload, agent_owner
                    ))
                except ValueError as e:
                    log(f"Invalid data for {hostname}: {line}. Error: {e}")
                if insert_data:
                    start_time = time.time()
                    batch_size = 1000
                    for i in range(0, len(insert_data), batch_size):
                        cursor.executemany("""
                            BEGIN
                                INSERT INTO maamd.agent_home_info (
                                    hostname, pid, "PID_TM", port, agent_home, created_by, created_date, oms_url,
                                    install_date, total_space_mb, cpu_usage_percent, memory_usage_mb, target_count,
                                    agent_version, oms_version, heartbeat_status, running_duration_hours, agent_status,
                                    last_successful_upload, last_attempted_upload, agent_owner
                                )
                                VALUES (:1, :2, :3, :4, :5, :6, SYSDATE, :7, :8, :9, :10, :11, :12, :13, :14, :15, :16, :17, :18, :19, :20);
                                EXCEPTION WHEN DUP_VAL_ON_INDEX THEN
                                    UPDATE maamd.agent_home_info
                                    SET pid = :2,
                                        "PID_TM" = :3,
                                        port = :4,
                                        created_by = :6,
                                        created_date = SYSDATE,
                                        oms_url = :7,
                                        install_date = :8,
                                        total_space_mb = :9,
                                        cpu_usage_percent = :10,
                                        memory_usage_mb = :11,
                                        target_count = :12,
                                        agent_version = :13,
                                        oms_version = :14,
                                        heartbeat_status = :15,
                                        running_duration_hours = :16,
                                        agent_status = :17,
                                        last_successful_upload = :18,
                                        last_attempted_upload = :19,
                                        agent_owner = :20
                                    WHERE hostname = :1
                                    AND agent_home = :5;
                            END;
                        """, insert_data[i:i + batch_size])
                        conn.commit()
                        log(f"Inserted batch {i//batch_size + 1} of {len(insert_data)//batch_size + 1}, rows: {len(insert_data[i:i + batch_size])}")
                    log(f"Bulk insert completed in {time.time() - start_time:.2f} seconds")
                    cursor.execute("SELECT COUNT(*) FROM maamd.agent_home_info")
                    total_rows = cursor.fetchone()[0]
                    log(f"Total rows in maamd.agent_home_info: {total_rows}")
                else:
                    log("No valid agent data to insert after processing")
    except oracledb.Error as e:
        log(f"Database error inserting into agent_home_info: {e}")
def load_default_credentials(conn):
    """Load default credentials for all usernames and component types."""
    try:
        with conn.cursor() as cursor:
            for username in [ORACLE_USER, ROOT_USER] + ALTERNATIVE_USERS:
                for component_type in ["GUEST", "PHYSICAL_HOST"]:
                    password = get_credential_silent(cursor, component_type, "default", username)
                    if password:
                        CREDENTIAL_CACHE[(component_type, "default", username)] = password
                        log(f"Cached default password for {component_type}:default:{username}")
                    else:
                        log(f"No default password for {component_type}:default:{username}")
    except oracledb.Error as e:
        log(f"Error caching default credentials: {e}")
def main():
    log("Starting main execution")
    log(f"Running as user: {getpass.getuser()}, Python: {sys.executable}, Version: {sys.version}")
    try:
        for key_path, key_type in SSH_KEYS:
            if os.path.exists(key_path) and os.access(key_path, os.W_OK):
                os.chmod(key_path, 0o600)
                log(f"Set permissions to 600 for SSH key: {key_path}")
            else:
                log(f"Skipping permission change for SSH key {key_path}: no write access or does not exist")
    except Exception as e:
        log(f"Failed to set SSH key permissions: {e}")
    conn = None
    try:
        start_time = time.time()
        conn = get_db_connection(DB_USER, DB_PASSWORD, DB_DSN)
        if not conn:
            log("Failed to establish database connection")
            sys.exit(1)
        log("Database connection established")
        # Load default credentials
        load_default_credentials(conn)
        load_dns_cache()
        load_uuid_fqdn_cache(conn)
        truncate_agent_hosts(conn)
        clean_agent_home_info(conn)
        db_servers = get_db_servers(conn)
        log(f"Processing {len(db_servers)} hosts")
        non_hypervisor_hosts = get_non_hypervisor_hosts(conn)
        agent_data = []
        physical_host_data_list = []
        processed_count = 0
        skipped_hosts = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_host = {executor.submit(process_host, host, conn, non_hypervisor_hosts): host for host in db_servers}
            for future in as_completed(future_to_host, timeout=HOST_TIMEOUT * len(db_servers)):
                host = future_to_host[future]
                try:
                    host_agent_data, physical_host_data = future.result(timeout=HOST_TIMEOUT)
                    agent_data.extend(host_agent_data)
                    physical_host_data_list.append(physical_host_data)
                    processed_count += 1
                    log(f"Progress: Processed {processed_count}/{len(db_servers)} hosts ({host}): {len(host_agent_data)} agent data entries")
                except TimeoutError:
                    log(f"Timeout processing {host} after {HOST_TIMEOUT} seconds")
                    SKIPPED_HOSTS[host] = f"Timeout after {HOST_TIMEOUT} seconds"
                    skipped_hosts.append(host)
                except Exception as e:
                    log(f"Error processing {host}: {e}")
                    SKIPPED_HOSTS[host] = f"Error: {str(e)}"
                    skipped_hosts.append(host)
        # Retry skipped hosts
        if skipped_hosts:
            log(f"Retrying {len(skipped_hosts)} skipped hosts: {', '.join(skipped_hosts)}")
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_host = {executor.submit(process_host, host, conn, non_hypervisor_hosts): host for host in skipped_hosts}
                for future in as_completed(future_to_host, timeout=HOST_TIMEOUT * len(skipped_hosts)):
                    host = future_to_host[future]
                    try:
                        host_agent_data, physical_host_data = future.result(timeout=HOST_TIMEOUT)
                        agent_data.extend(host_agent_data)
                        physical_host_data_list.append(physical_host_data)
                        processed_count += 1
                        log(f"Retry success: Processed {host}: {len(host_agent_data)} agent data entries")
                        del SKIPPED_HOSTS[host]
                    except TimeoutError:
                        log(f"Retry timeout for {host} after {HOST_TIMEOUT} seconds")
                    except Exception as e:
                        log(f"Retry error for {host}: {e}")
        save_physical_host_data(physical_host_data_list, conn)
        save_agent_data(agent_data, conn)
        clean_stale_hosts(db_servers, conn)
        elapsed_time = time.time() - start_time
        physical_count = len([h for h in db_servers if h not in SKIPPED_HOSTS or 'UUID' not in SKIPPED_HOSTS.get(h, '')])
        vm_count = len([h for h in db_servers if h in SKIPPED_HOSTS and 'UUID' in SKIPPED_HOSTS.get(h, '')])
        log(f"Completed processing {len(db_servers)} hosts ({physical_count} physical, {vm_count} VMs) "
            f"in {elapsed_time:.2f} seconds. Collected {len(agent_data)} agent data entries.")
        if SKIPPED_HOSTS:
            log(f"Skipped hosts: {json.dumps(SKIPPED_HOSTS, indent=2)}")
    except KeyboardInterrupt:
        log("Received KeyboardInterrupt, cleaning up...")
        while not CONNECTION_POOL.empty():
            try:
                client = CONNECTION_POOL.get_nowait()
                SSH_POOL.release_client(client)
            except Exception:
                pass
            time.sleep(0.1)
        log("Closed all pooled SSH connections")
        if conn:
            try:
                conn.close()
                log("Database connection closed")
            except Exception as e:
                log(f"Error closing database connection: {e}")
        sys.exit(1)
    except Exception as e:
        log(f"Main execution failed: {e}")
        while not CONNECTION_POOL.empty():
            try:
                client = CONNECTION_POOL.get_nowait()
                SSH_POOL.release_client(client)
            except Exception:
                pass
            time.sleep(0.1)
        log("Closed all pooled SSH connections")
        if conn:
            try:
                conn.close()
                log("Database connection closed")
            except Exception as e:
                log(f"Error closing database connection: {e}")
        sys.exit(1)
    finally:
        while not CONNECTION_POOL.empty():
            try:
                client = CONNECTION_POOL.get_nowait()
                SSH_POOL.release_client(client)
            except Exception:
                pass
            time.sleep(0.1)
        log("Closed all pooled SSH connections")
        if conn:
            try:
                conn.close()
                log("Database connection closed")
            except Exception as e:
                log(f"Error closing database connection: {e}")
if __name__ == "__main__":
    main()
