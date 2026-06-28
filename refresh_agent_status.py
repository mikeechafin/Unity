#!/usr/bin/env python3
# Version: 2026-04-13 v2.11
# Changes: Fixed cleanup_agent_inst_temp_files to accept and use real SSH client (prevents 'NoneType' exec_command error). Cleanup now called correctly inside refresh_host_agents where client is valid.
import os
import sys
import time
import json
import shlex
import socket
import logging
import logging.handlers
import threading
import subprocess
import re
import traceback
import getpass
import resource
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from collections import defaultdict
from queue import Queue, Empty as queue_empty
import oracledb
import paramiko
import select
from paramiko.ssh_exception import SSHException, AuthenticationException, NoValidConnectionsError, BadAuthenticationType
from maa_libraries import get_db_connection, get_credential_silent, is_host_reachable
import fcntl
import atexit
import argparse
import glob
import io
from cryptography.fernet import Fernet

def safe_format_date(dt):
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt.strip()
    if isinstance(dt, datetime):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return None

def normalize_hostname(h):
    if not h:
        return ''
    h = str(h).lower().strip().replace(',', '.')
    h = re.sub(r'o2', '02', h)
    if not h.endswith('.us.oracle.com'):
        h += '.us.oracle.com'
    return h

# Globals
CREDENTIAL_CACHE = {}
HOST_AUTH_CACHE = {}
PUBLICKEY_ONLY_HOSTS = set()
CLEANED_HOSTS = set()
KNOWN_BAD_HOSTS = {"maa-pe-kvm-sca-16vm001.us.oracle.com"}
STORAGE_PATTERNS = ['cel', 'cell', 'storage']
BAD_STAGING_PATTERNS = ['/perl', '/bin', '/install_dir', '/oracle_common/jdk', '/virtual', '/ahf_']
BAD_TEST_PATTERNS = ['GoldImage', 'ahf_', 'UPG', 'AMTEST', 'AGTEST', 'UPGTEST', 'TEST', 'test_', 'ahf_ui', 'dbimpact', 'basic_sanity', 'ui_validation', 'svm_', 'pcloud', 'agentbase', 'OracleHomesANA', 'ritmathu', 'pbhogara_test', 'u091']
# Constants
DB_USER = "maamd"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
ORACLE_USER = "oracle"
ROOT_USER = "root"
ALTERNATIVE_USERS = ["oraha", "orarom", "michaf2", "orarom1+"]
SSH_AUTH_FAIL_LIMIT = 2
SSH_RETRIES = 1
SSH_TIMEOUT = 240
SSH_BANNER_TIMEOUT = 120
SSH_RETRY_DELAY = 5
SSH_COMMAND_TIMEOUT = 180
MAX_WORKERS = 50
MAX_HOSTS = 1000
HOST_TIMEOUT = 300
STATIC_THRESHOLD_DAYS = 3
ARCHIVE_PURGE_DAYS = 30
BASE_SEARCH_PATHS = ["/u01/app", "/u02", "/u03", "/u04", "/u05", "/exa_manual", "/exa_auto", "/opt/oracle", "/product", "/OHomes*", "/u01/OHomes*"]
SSH_KEYS = [("/home/maatest/.ssh/id_rsa", "rsa"), ("/home/maatest/.ssh/id_ed25519", "ed25519"), ("/home/maatest/.ssh/id_ecdsa", "ecdsa")]
# fd staging (assumed pre-staged on app server)
FD_LOCAL_PATH = "./fd"
REMOTE_FD_PATH = "/tmp/fd"
REMOTE_SEARCH_SCRIPT = "/tmp/search.sh"
# Logging setup - ONLY to logfile; INFO level contains ONLY essential summaries; everything else is DEBUG
log_directory = '/home/maatest/mchafin/MAA_APPS_NEW/output'
log_file = os.path.join(log_directory, 'refresh_agent_status.log')
os.makedirs(log_directory, exist_ok=True)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.handlers.WatchedFileHandler(log_file)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logger.addHandler(handler)

class StderrToLogger:
    def __init__(self, logger, level=logging.ERROR):
        self.logger = logger
        self.level = level
    def write(self, message):
        if message.strip():
            self.logger.log(self.level, message.strip())
    def flush(self):
        pass
sys.stderr = StderrToLogger(logger)

# fd existence check (assume pre-staged)
if not os.path.exists(FD_LOCAL_PATH) or not os.access(FD_LOCAL_PATH, os.X_OK):
    logger.error(f"fd binary missing at {FD_LOCAL_PATH}. Run ./prepare-fd.sh once on the control machine.")
    sys.exit(1)
logger.info("✓ refresh_agent_status.py v2.11 started (fd pre-staged on app server - no curl)")

# =============================================================================
# SAFE TEMP FILE CLEANUP (Oracle EM Agent leaves these after emctl status agent)
# =============================================================================
def cleanup_agent_inst_temp_files(client, hostname, agent_inst_path):
    """Safe, targeted cleanup: only deletes exactly 10-character alphanumeric files containing 'Response From Agent: running' inside agent_inst directories."""
    if not client or not agent_inst_path or not agent_inst_path.endswith("agent_inst"):
        return
    logger.info(f" → [TEMP CLEANUP] Scanning {agent_inst_path} on {hostname} for orphaned EM response files...")
    cmd = f"""
find {shlex.quote(agent_inst_path)} -type f -name '[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]' -print0 2>/dev/null |
xargs -0 grep -l 'Response From Agent: running' 2>/dev/null |
xargs -0 rm -f 2>/dev/null || true
"""
    output, error, exit_status = exec_ssh_command(client, cmd, timeout=30, hostname=hostname)
    if output or error:
        logger.info(f"   Cleaned temp response files in {agent_inst_path} on {hostname}")
    else:
        logger.debug(f"   No temp response files found in {agent_inst_path} on {hostname}")

# Lock + Known Hosts
def pre_populate_known_hosts():
    try:
        conn = get_db_connection(DB_USER, os.environ.get('DB_PASSWORD'), DB_DSN)
        cursor = conn.cursor()
        cursor.execute("SELECT LOWER(hostname) FROM maamd.agent_home_info")
        hosts = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        if len(hosts) > 200:
            hosts = hosts[-200:]
        logger.debug(f"Pre-populating known_hosts for {len(hosts)} hosts")
        with open(os.path.expanduser('~/.ssh/known_hosts'), 'a') as f:
            for host in hosts:
                try:
                    subprocess.run(['timeout', '10s', 'ssh-keyscan', '-H', host], stdout=f, stderr=subprocess.DEVNULL, timeout=12)
                except:
                    pass
        logger.info("✓ Pre-populated known_hosts (limited)")
    except Exception as e:
        logger.debug(f"Pre-populate known_hosts failed: {e}")

def global_cleanup_known_hosts():
    try:
        subprocess.run(['ssh-keygen', '-R', '*'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        logger.info("✓ Global known_hosts cleanup completed at startup")
    except Exception as e:
        logger.debug(f"Global known_hosts cleanup failed: {e}")

lock_path = "/tmp/refresh_agent_status.lock"
lock_fd = None
try:
    lock_fd = open(lock_path, 'w')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    lock_fd.write(str(os.getpid()) + '\n')
    lock_fd.flush()
    logger.info("✓ Singleton lock acquired - no other instance running")
    def release_lock():
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
            if os.path.exists(lock_path):
                os.unlink(lock_path)
        except:
            pass
    atexit.register(release_lock)
except BlockingIOError:
    logger.error("✗ Another instance of refresh_agent_status.py is already running - exiting")
    sys.exit(1)
except Exception as e:
    logger.error(f"✗ Lock error: {e}")
    sys.exit(1)

key_file = '/home/maatest/mchafin/MAA_APPS_NEW/encryption_key.txt'
if os.path.exists(key_file):
    with open(key_file, 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(ENCRYPTION_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY)

def decrypt_data(encrypted_data):
    if not encrypted_data:
        return None
    try:
        if isinstance(encrypted_data, bytes):
            return cipher_suite.decrypt(encrypted_data).decode()
        elif hasattr(encrypted_data, 'read'):
            return cipher_suite.decrypt(encrypted_data.read()).decode()
        return None
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None

def get_ssh_private_key_for_user(hostname, username):
    conn = get_db_connection(DB_USER, os.environ.get('DB_PASSWORD'), DB_DSN)
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
                key = decrypt_data(row[0])
                if key:
                    return key
        cursor.execute("""
            SELECT ENCRYPTED_KEY
            FROM ACCESS_CREDENTIALS
            WHERE COMPONENT_NAME = 'default'
              AND USERNAME = :1
            ORDER BY NVL(LAST_UPDATED_DATE, CREATED_DATE) DESC NULLS LAST
        """, (username,))
        row = cursor.fetchone()
        if row and row[0]:
            return decrypt_data(row[0])
        return None
    finally:
        cursor.close()
        conn.close()

def clear_offending_host_key(hostname):
    if hostname in CLEANED_HOSTS:
        return
    try:
        subprocess.run(['ssh-keygen', '-R', hostname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        CLEANED_HOSTS.add(hostname)
        logger.debug(f"✓ Cleared stale host key for {hostname} (once per run)")
    except Exception as e:
        logger.debug(f"Host key cleanup failed for {hostname}: {e}")

class AcceptingPolicy(paramiko.AutoAddPolicy):
    def missing_host_key(self, client, hostname, key):
        clear_offending_host_key(hostname)
        return super().missing_host_key(client, hostname, key)

class SSHConnectionPool:
    def __init__(self, max_size=50):
        self.pool = Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.max_size = max_size
        self.password_attempted = set()
    def get_client(self, hostname, component_type, conn, agent_owner):
        with self.lock:
            if hostname in HOST_AUTH_CACHE:
                if HOST_AUTH_CACHE[hostname] is None:
                    return None, None
                return HOST_AUTH_CACHE[hostname]
            try:
                client = self.pool.get_nowait()
                if client.get_transport() and client.get_transport().is_active():
                    return client, client.get_transport().get_username()
                client.close()
            except queue_empty:
                pass
            except Exception as e:
                logger.error(f"[{hostname}] Error checking SSH client for reuse: {e}")
            clear_offending_host_key(hostname)
            if any(p in hostname.lower() for p in STORAGE_PATTERNS):
                logger.debug(f"[{hostname}] celadm host - using root-first strategy")
                for username in [ROOT_USER, ORACLE_USER]:
                    pw_key = (hostname.lower(), username)
                    if pw_key in self.password_attempted:
                        continue
                    password = self._get_password(hostname, username, component_type, conn)
                    if password:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(AcceptingPolicy())
                        try:
                            client.connect(hostname, username=username, password=password, timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT, allow_agent=False, look_for_keys=False)
                            client.get_transport().set_keepalive(15)
                            logger.info(f"Password auth successful for {hostname} as {username} (celadm)")
                            HOST_AUTH_CACHE[hostname] = (client, username)
                            self.password_attempted.add(pw_key)
                            return client, username
                        except Exception as e:
                            logger.debug(f"[{hostname}] Password auth failed as {username} (celadm): {e}")
                            self.password_attempted.add(pw_key)
                logger.error(f"[{hostname}] Failed to connect to celadm host after retries")
                HOST_AUTH_CACHE[hostname] = None
                return None, None
            for key_type in ["ed25519", "rsa"]:
                pkey = self._load_pkey(hostname, ORACLE_USER, key_type)
                if pkey:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(AcceptingPolicy())
                    try:
                        client.connect(hostname, username=ORACLE_USER, pkey=pkey, timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT, allow_agent=False, look_for_keys=False)
                        client.get_transport().set_keepalive(15)
                        logger.info(f"SSH {key_type.upper()} key auth successful for {hostname}")
                        if self._verify_and_append_key_if_missing(client, hostname, ORACLE_USER):
                            HOST_AUTH_CACHE[hostname] = (client, ORACLE_USER)
                            return client, ORACLE_USER
                    except Exception as e:
                        if "unpack requires a buffer of 4 bytes" in str(e) or "username" in str(e).lower():
                            logger.debug(f"[{hostname}] {key_type.upper()} key failed: {e} (skipping to next type)")
                        else:
                            logger.debug(f"[{hostname}] {key_type.upper()} key failed: {e}")
            if hostname not in PUBLICKEY_ONLY_HOSTS:
                for username in [ORACLE_USER, ROOT_USER]:
                    pw_key = (hostname.lower(), username)
                    if pw_key in self.password_attempted:
                        continue
                    password = self._get_password(hostname, username, component_type, conn)
                    if password:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(AcceptingPolicy())
                        try:
                            client.connect(hostname, username=username, password=password, timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT, allow_agent=False, look_for_keys=False)
                            client.get_transport().set_keepalive(15)
                            logger.info(f"Password auth successful for {hostname} as {username}")
                            HOST_AUTH_CACHE[hostname] = (client, username)
                            self.password_attempted.add(pw_key)
                            return client, username
                        except Exception as e:
                            logger.debug(f"[{hostname}] Password auth failed as {username}: {e}")
                            self.password_attempted.add(pw_key)
            logger.error(f"[{hostname}] Failed to connect to {hostname} after retries")
            HOST_AUTH_CACHE[hostname] = None
            return None, None
    def _load_pkey(self, hostname, username, key_type):
        try:
            raw_key = get_ssh_private_key_for_user(hostname, username)
            if not raw_key:
                raw_key = get_ssh_private_key_for_user("default", username)
            if not raw_key:
                return None
            if key_type == "ed25519":
                try:
                    return paramiko.Ed25519Key.from_private_key(io.StringIO(raw_key))
                except Exception as e:
                    if "unpack requires a buffer of 4 bytes" in str(e) or "username" in str(e).lower():
                        logger.debug(f"[{hostname}] ED25519 key failed: {e}")
                    return None
            else:
                try:
                    return paramiko.RSAKey.from_private_key(io.StringIO(raw_key))
                except Exception as e:
                    if "unpack requires a buffer of 4 bytes" in str(e):
                        logger.debug(f"[{hostname}] Failed to load rsa key: {e}")
                    return None
        except Exception as e:
            logger.debug(f"[{hostname}] Failed to load {key_type} key: {e}")
            return None
    def _get_password(self, hostname, username, component_type, conn):
        cache_key = (component_type, hostname, username)
        if cache_key in CREDENTIAL_CACHE:
            return CREDENTIAL_CACHE[cache_key]
        cursor = conn.cursor()
        try:
            password = get_credential_silent(cursor, component_type, hostname, username)
            if not password:
                password = get_credential_silent(cursor, component_type, "default", username)
            CREDENTIAL_CACHE[cache_key] = password
            return password
        finally:
            cursor.close()
    def _verify_and_append_key_if_missing(self, client, hostname, username):
        try:
            pubkey = open("/home/maatest/.ssh/id_ed25519_maa.pub").read().strip()
            cmd = f'grep -F "{pubkey}" /home/{username}/.ssh/authorized_keys || true'
            _, stdout, _ = client.exec_command(cmd)
            if not stdout.read().decode().strip():
                logger.warning(f"[{hostname}] Key missing in authorized_keys for {username} - appending")
                append_cmd = f"mkdir -p /home/{username}/.ssh && echo '{pubkey}' >> /home/{username}/.ssh/authorized_keys && chmod 600 /home/{username}/.ssh/authorized_keys"
                if username == ROOT_USER:
                    client.exec_command(append_cmd)
                else:
                    client.exec_command(f"su - {username} -c '{append_cmd}'")
                logger.info(f"[{hostname}] Key appended successfully for {username}")
            return True
        except Exception as e:
            logger.debug(f"[{hostname}] Key verification failed: {e}")
            return True
    def release_client(self, client):
        with self.lock:
            if client is None:
                return
            try:
                if self.pool.qsize() < self.pool.maxsize and client.get_transport().is_active():
                    self.pool.put(client)
                else:
                    client.close()
            except Exception as e:
                logger.error(f"Error releasing SSH client: {e}")
                try:
                    client.close()
                except:
                    pass
SSH_POOL = SSHConnectionPool()

def check_user(client, hostname, username):
    try:
        cmd = f"id {shlex.quote(username)}"
        output, error, exit_status = exec_ssh_command(client, cmd, timeout=10, hostname=hostname)
        if error and ("no such user" in error.lower() or "does not exist" in error.lower()):
            return False
        if "no such user" in output.lower() or "does not exist" in output.lower():
            return False
        if output and "uid=" in output:
            return True
        return False
    except Exception as e:
        logger.error(f"[{hostname}] Error checking user {username}: {e}")
        return False

def get_agent_owner(client, agent_home, hostname):
    try:
        cmd = f"ls -ld {shlex.quote(agent_home)} | awk '{{print $3}}'"
        output, error, exit_status = exec_ssh_command(client, cmd, timeout=10, hostname=hostname)
        owner = output.strip()
        if owner and owner != "ls:":
            return owner
        return ORACLE_USER
    except Exception as e:
        logger.error(f"[{hostname}] Error getting owner for {agent_home}: {e}")
        return ORACLE_USER

def exec_ssh_command(client, cmd, timeout=180, hostname="unknown"):
    logger.debug(f"[{hostname}] Executing: {cmd}")
    for attempt in range(SSH_RETRIES + 1):
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            exit_status = stdout.channel.recv_exit_status()
            return output.strip(), error.strip(), exit_status
        except Exception as e:
            logger.warning(f"[{hostname}] Command attempt {attempt+1}/{SSH_RETRIES} failed: {e}")
            if attempt == SSH_RETRIES:
                logger.error(f"[{hostname}] SSH command failed after {SSH_RETRIES} retries: {cmd}")
                raise
            time.sleep(SSH_RETRY_DELAY ** attempt)
    return "", "", -1

def clean_discovered_path(path):
    if not path:
        return ''
    candidates = re.split(r'[\n\s]+', path.strip())
    for p in candidates:
        norm = p.strip().rstrip('/')
        if any(c in norm for c in '()|[]{}*+?^$\\') or norm.startswith('(/agent_') or len(norm) < 10:
            continue
        if ':' in norm and '.jar' in norm:
            for part in norm.split(':'):
                if '/agent_' in part and not part.endswith('.jar') and '/jdk/bin/java' not in part:
                    norm = part
                    break
        while norm.endswith(('/oracle_common', '/oracle_common/jdk', '/jdk', '/bin', '/perl', '/install_dir')):
            norm = os.path.dirname(norm)
        if '/oracle_common' in norm.lower() or '/install_dir' in norm.lower():
            continue
        if len(norm) > 480:
            norm = norm[:480]
        if norm and re.search(r'/agent_\d+.\d+.\d+.\d+', norm):
            return norm
    return ''

def normalize_agent_home(home):
    if not home:
        return ''
    home = clean_discovered_path(home)
    home = home.strip().rstrip('/')
    if home.endswith('/bin'):
        home = os.path.dirname(home)
    return home

def is_temporary_test_home(home):
    if not home:
        return False
    lower = home.lower()
    return any(p in lower for p in BAD_TEST_PATTERNS)

def is_valid_agent_home(home):
    if not home:
        return False
    norm = normalize_agent_home(home)
    if not norm:
        return False
    if '/agent_inst' in norm.lower() or norm.lower().endswith('/agent_inst'):
        return False
    if not re.search(r'/agent_\d+.\d+.\d+.\d+', norm):
        logger.debug(f"Rejected non-versioned path: {norm}")
        return False
    if '/oracle_common' in norm.lower():
        logger.debug(f"Rejected oracle_common junk path: {norm}")
        return False
    lower_norm = norm.lower()
    if any(bad in lower_norm for bad in BAD_STAGING_PATTERNS):
        logger.debug(f"Rejected junk staging path: {norm}")
        return False
    if is_temporary_test_home(norm):
        logger.debug(f"Rejected temporary test home: {norm}")
        return False
    return True

def validate_agent_home_exists(client, hostname, home_path):
    if not home_path:
        return False
    home = shlex.quote(home_path.strip())
    cmd = f'test -d {home} && test -x {home}/bin/emctl && echo "VALID" || echo "INVALID"'
    output, error, exit_status = exec_ssh_command(client, cmd, timeout=10, hostname=hostname)
    valid = 'VALID' in output.upper()
    if not valid:
        logger.debug(f'[{hostname}] PHANTOM REJECTED: {home_path}')
    return valid

def is_storage_host(hostname):
    h = hostname.lower()
    return any(p in h for p in STORAGE_PATTERNS)

def stage_and_run_fd_search(client, hostname):
    try:
        with open(FD_LOCAL_PATH, 'rb') as f:
            fd_data = f.read()
        sftp = client.open_sftp()
        with sftp.file(REMOTE_FD_PATH, 'wb') as f:
            f.write(fd_data)
        sftp.chmod(REMOTE_FD_PATH, 0o755)
        remote_script = """#!/bin/bash
PATTERN="emctl"
THREADS=$(( $(nproc) - 8 ))
echo "[DEBUG fd command] /tmp/fd --threads $THREADS -u -t x -i --glob "$PATTERN" /" >&2
nice -n 15 ionice -c3 /tmp/fd --threads "$THREADS" -u -t x -i --glob "$PATTERN" / 2>&1
"""
        sftp.putfo(io.BytesIO(remote_script.encode()), REMOTE_SEARCH_SCRIPT)
        sftp.chmod(REMOTE_SEARCH_SCRIPT, 0o755)
        sftp.close()
        output, error, exit_status = exec_ssh_command(client, f"{REMOTE_SEARCH_SCRIPT}", timeout=SSH_COMMAND_TIMEOUT, hostname=hostname)
        cleanup_cmd = f"rm -f {REMOTE_FD_PATH} {REMOTE_SEARCH_SCRIPT} 2>/dev/null || true"
        exec_ssh_command(client, cleanup_cmd, timeout=10, hostname=hostname)
        if exit_status != 0:
            logger.debug(f"[{hostname}] fd search returned non-zero but output captured")
        return output.strip()
    except Exception as e:
        logger.error(f"[{hostname}] fd staging failed: {e}")
        return ""

def discover_agent_homes(client, hostname, effective_user):
    agent_homes = []
    fd_output = stage_and_run_fd_search(client, hostname)
    for line in fd_output.splitlines():
        if line.strip():
            agent_homes.append(line.strip())
    cmd = "awk -F: '{print $1}' /etc/oragchomelist 2>/dev/null || true"
    output, _, _ = exec_ssh_command(client, cmd, timeout=30, hostname=hostname)
    for line in output.splitlines():
        if line.strip():
            agent_homes.append(line.strip())
    ps_cmd = r"""ps -ef | grep -E 'emwd.pl|TMMain' | grep -E '(/agent*|/em/agent|/EM/|GoldImage|ha-em2|agent_vm|agent_phx|agent_haem|agent_emdb|agent_phxem)' | grep -v 'grep' | awk '{for(i=1;i<=NF;i++) if($i ~ /^\/.*agent_[0-9]+.[0-9]+.[0-9]+.[0-9]+/ && $i !~ /.jar:/) print $i}' | xargs -I {} dirname {} | xargs -I {} dirname {} | sort -u || true"""
    output, _, _ = exec_ssh_command(client, ps_cmd, timeout=30, hostname=hostname)
    for line in output.splitlines():
        if line.strip():
            agent_homes.append(line.strip())
    normalized = []
    accepted = 0
    rejected = 0
    for home in agent_homes:
        norm = normalize_agent_home(home)
        if is_valid_agent_home(norm):
            if validate_agent_home_exists(client, hostname, norm):
                if norm not in normalized:
                    normalized.append(norm)
                    accepted += 1
            else:
                rejected += 1
    agent_homes = normalized
    if accepted > 0 or rejected > 0:
        logger.debug(f"[{hostname}] Discovery summary: {accepted} accepted, {rejected} rejected")
    return agent_homes

def get_reachable_hosts(all_hosts):
    reachable = []
    logger.info(f"Starting parallel reachability check for {len(all_hosts)} hosts...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_host = {executor.submit(is_host_reachable, h): h for h in all_hosts}
        for future in as_completed(future_to_host):
            h = future_to_host[future]
            try:
                if future.result():
                    reachable.append(h)
            except:
                pass
    logger.info(f"Quick reachability check: {len(reachable)}/{len(all_hosts)} hosts are reachable")
    return reachable

def get_current_ssh_user(client, hostname):
    try:
        out, _, _ = exec_ssh_command(client, "whoami", timeout=5, hostname=hostname)
        return out.strip()
    except:
        return "root"

def run_emctl_status(client, hostname, emctl_path, owner_to_use):
    current_user = get_current_ssh_user(client, hostname)
    logger.debug(f"[{hostname}] Current SSH user: {current_user}, agent owner: {owner_to_use}")
    if current_user.lower() == owner_to_use.lower():
        emctl_cmd = f"{shlex.quote(emctl_path)} status agent"
        method = "direct"
    elif current_user.lower() == "root":
        emctl_cmd = f"su - {shlex.quote(owner_to_use)} -c '{shlex.quote(emctl_path)} status agent'"
        method = "su"
    else:
        emctl_cmd = f"sudo -u {shlex.quote(owner_to_use)} {shlex.quote(emctl_path)} status agent"
        method = "sudo"
    output, error, exit_status = exec_ssh_command(client, emctl_cmd, timeout=SSH_COMMAND_TIMEOUT, hostname=hostname)
    status_output = (output or error or "").strip()
    logger.debug(f"RAW EMCTL OUTPUT (as {owner_to_use} via {method}) for {emctl_path} on {hostname}:\n{status_output}")
    return status_output, exit_status

def get_full_agent_status(client, hostname, agent_home, owner_to_use):
    try:
        emctl_path = f"{agent_home}/bin/emctl"
        pid_cmd = f"ps -ef | grep '[e]mwd\.pl' | grep {shlex.quote(agent_home)} | awk '{{print $2}}' | head -1"
        output, _, _ = exec_ssh_command(client, pid_cmd, timeout=15, hostname=hostname)
        pid = int(output.strip()) if output.strip().isdigit() else 0
        if pid == 0:
            tm_cmd = f"ps -ef | grep TMMain | grep {shlex.quote(agent_home)} | awk '{{print $2}}' | head -1"
            tm_out, _, _ = exec_ssh_command(client, tm_cmd, timeout=10, hostname=hostname)
            if tm_out.strip().isdigit():
                pid = int(tm_out.strip())
        exists_cmd = f'test -x {shlex.quote(emctl_path)} && echo "EXISTS" || echo "MISSING"'
        exists_out, _, _ = exec_ssh_command(client, exists_cmd, timeout=10, hostname=hostname)
        if "MISSING" in exists_out.upper():
            logger.debug(f"[{hostname}] emctl binary missing at {emctl_path} - forcing stopped/PID=0")
            return pid or 0, None, 'stopped', None, None, None, None, None, None, None, None, None, None, None, None, None, 0
        status_output, exit_status = run_emctl_status(client, hostname, emctl_path, owner_to_use)
        initial_status = "stopped" if exit_status != 0 else "unknown"
        oms_url = None
        target_count = None
        agent_version = None
        oms_version = None
        heartbeat_status = None
        running_duration = None
        port = None
        last_successful_upload = None
        last_attempted_upload = None
        install_date = None
        total_space_mb = None
        total_errors = 0
        lines = [line.strip() for line in status_output.splitlines() if line.strip()]
        for line in lines:
            if 'Agent is Running and Ready' in line:
                initial_status = "running"
            elif 'Agent is Running but Not Ready' in line:
                initial_status = "running_not_ready"
            elif 'Agent is Not Running' in line:
                initial_status = "stopped"
            if re.search(r'Repository URL', line, re.I):
                m = re.search(r'https?://[^\s]+', line)
                if m:
                    oms_url = m.group(0)
            if re.search(r'Agent URL', line, re.I):
                m = re.search(r':(\d+)', line)
                if m:
                    port = int(m.group(1))
                if not oms_url:
                    m = re.search(r'https?://[^\s]+', line)
                    if m:
                        oms_url = m.group(0)
            if re.search(r'Agent Version', line, re.I):
                m = re.search(r'Agent Version\s*:\s*([\d.]+)', line, re.I)
                if m:
                    agent_version = m.group(1)
            if re.search(r'OMS Version', line, re.I):
                m = re.search(r'OMS Version\s*:\s*([\d.]+)', line, re.I)
                if m:
                    oms_version = m.group(1)
            if re.search(r'Heartbeat Status', line, re.I):
                m = re.search(r':\s*(.+)', line, re.I)
                if m:
                    heartbeat_status = m.group(1).strip()
            if re.search(r'Started at', line, re.I):
                m = re.search(r'Started at\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if m:
                    try:
                        start_time = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
                        running_duration = (datetime.now() - start_time).total_seconds() / (3600 * 24)
                        if running_duration < 0:
                            running_duration = 0.0
                    except:
                        pass
            if re.search(r'Last successful upload', line, re.I):
                m = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if m:
                    try:
                        last_successful_upload = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
                    except:
                        pass
            if re.search(r'Last attempted upload', line, re.I):
                m = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if m:
                    try:
                        last_attempted_upload = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
                    except:
                        pass
            if re.search(r'Number of Targets', line, re.I):
                m = re.search(r'(\d+)', line)
                if m:
                    target_count = int(m.group(1))
        if not agent_version:
            ver_cmd = f"su - {shlex.quote(owner_to_use)} -c '{shlex.quote(emctl_path)} version'" if get_current_ssh_user(client, hostname) == "root" else f"{shlex.quote(emctl_path)} version"
            ver_out, _, _ = exec_ssh_command(client, ver_cmd, timeout=20, hostname=hostname)
            m = re.search(r'Agent Version\s*:\s*([\d.]+)', ver_out, re.I)
            if m:
                agent_version = m.group(1)
        if not install_date:
            install_cmd = f"ls -l {shlex.quote(emctl_path)} | awk '{{print $6 " " $7 " " $8}}'"
            install_out, _, _ = exec_ssh_command(client, install_cmd, timeout=8, hostname=hostname)
            if install_out:
                try:
                    install_date = datetime.strptime(install_out.strip(), '%b %d %Y')
                except:
                    pass
        space_cmd = f"du -sm {shlex.quote(agent_home)} 2>/dev/null | awk '{{print $1}}'"
        space_out, _, _ = exec_ssh_command(client, space_cmd, timeout=12, hostname=hostname)
        if space_out and space_out.strip().isdigit():
            total_space_mb = int(space_out.strip())
        cpu_percent = memory_mb = None
        if pid != 0 and initial_status in ("running", "running_not_ready"):
            cpu_cmd = f"ps -p {pid} -o %cpu,rss 2>/dev/null | tail -n +2"
            cpu_out, _, _ = exec_ssh_command(client, cpu_cmd, timeout=10, hostname=hostname)
            if cpu_out:
                try:
                    parts = cpu_out.strip().split()
                    cpu_percent = float(parts[0])
                    memory_mb = float(parts[1]) / 1024
                except:
                    pass
        lsu = safe_format_date(last_successful_upload)
        lau = safe_format_date(last_attempted_upload)
        idt = safe_format_date(install_date)
        return pid or 0, None, initial_status, cpu_percent, memory_mb, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, lsu, lau, idt, total_space_mb, total_errors
    except Exception as e:
        logger.debug(f"[{hostname}] Status parse error for {agent_home}: {e}")
        return 0, None, 'unknown', None, None, None, None, None, None, None, None, None, None, None, None, None, 0

def ensure_archive_table_exists(conn):
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE maamd.agent_home_info_archive (
                hostname VARCHAR2(255) NOT NULL,
                pid NUMBER,
                agent_home VARCHAR2(500) NOT NULL,
                agent_owner VARCHAR2(100),
                AGENT_STATUS VARCHAR2(50),
                CPU_USAGE_PERCENT NUMBER,
                MEMORY_USAGE_MB NUMBER,
                LAST_REFRESHED DATE,
                CREATED_BY VARCHAR2(100),
                CREATED_DATE DATE,
                CONSTRAINT PK_AGENT_HOME_INFO_ARCHIVE PRIMARY KEY (hostname, agent_home)
            )
        """)
        logger.info("✓ Created agent_home_info_archive table (one-time)")
    except oracledb.Error as e:
        if "ORA-00955" in str(e):
            pass
        else:
            logger.error(f"Archive table creation error: {e}")
    finally:
        cursor.close()

def purge_old_archive(conn):
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM maamd.agent_home_info_archive WHERE last_refreshed < SYSDATE - 30")
        purged = cursor.rowcount
        if purged > 0:
            logger.info(f"Purged {purged} old entries from agent_home_info_archive (30+ days)")
        conn.commit()
    finally:
        cursor.close()

def refresh_host_agents(hostname, homes, component_type, conn, user_id, full_mode_for_host=False):
    results = []
    updates = []
    deletes = []
    inserts = []
    archive_inserts = []
    try:
        client, ssh_user = SSH_POOL.get_client(hostname, component_type, conn, ORACLE_USER)
        if not client:
            logger.error(f"[{hostname}] Failed to establish SSH connection")
            for pid, agent_home, _ in homes:
                updates.append((0, None, 'unknown', None, None, None, None, None, None, None, None, None, None, None, None, None, 0, hostname, agent_home))
                results.append((False, f"Agent home {agent_home} unreachable - marked unknown"))
            return results, updates, deletes, inserts, archive_inserts
        try:
            effective_user = ROOT_USER
            logger.debug(f"[{hostname}] Using direct ROOT_USER for discovery")
            valid_homes = []
            for pid, agent_home, agent_owner in homes:
                original_agent_home = agent_home.strip()
                norm_home = normalize_agent_home(original_agent_home)
                if not is_valid_agent_home(norm_home):
                    deletes.append((hostname, original_agent_home))
                    results.append((False, f"Invalid/junk path {original_agent_home} - deleted"))
                    continue
                if not validate_agent_home_exists(client, hostname, norm_home):
                    deletes.append((hostname, original_agent_home))
                    results.append((False, f"Phantom agent home {original_agent_home} - deleted"))
                    continue
                actual_owner = get_agent_owner(client, norm_home, hostname)
                owner_to_use = actual_owner if check_user(client, hostname, actual_owner) else effective_user
                valid_homes.append((pid, norm_home, owner_to_use, original_agent_home))
            discovered_homes = discover_agent_homes(client, hostname, effective_user)
            for agent_home in discovered_homes:
                if agent_home not in [h[1] for h in valid_homes]:
                    if validate_agent_home_exists(client, hostname, agent_home):
                        actual_owner = get_agent_owner(client, agent_home, hostname)
                        owner_to_use = actual_owner if check_user(client, hostname, actual_owner) else effective_user
                        pid, tm_pid, status, cpu, mem, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors = get_full_agent_status(client, hostname, agent_home, owner_to_use)
                        if pid is None:
                            pid = 0
                        if status in ["running", "running_not_ready"]:
                            inserts.append((hostname, pid, agent_home, owner_to_use, status, cpu, mem, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors))
                        else:
                            archive_inserts.append((hostname, pid, agent_home, owner_to_use, status, cpu, mem, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors))
                        valid_homes.append((None, agent_home, owner_to_use, agent_home))
                        logger.debug(f"New agent home discovered and marked for insert: {agent_home} on {hostname} (PID: {pid}, Status: {status})")
                        results.append((True, f"New agent home discovered and marked for insert: {agent_home} on {hostname} (PID: {pid}, Status: {status})"))
            for pid, norm_home, owner_to_use, original_agent_home in valid_homes:
                logger.debug(f"Updating agent home: {original_agent_home}")
                new_pid, tm_pid, initial_status, cpu_percent, memory_mb, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors = get_full_agent_status(client, hostname, norm_home, owner_to_use)
                updates.append((new_pid or 0, tm_pid, initial_status[:255], cpu_percent, memory_mb, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors, hostname, original_agent_home))
                results.append((True, f"Status refreshed for agent on {hostname} (PID: {new_pid or 0}, Status: {initial_status})"))

            # SAFE TEMP FILE CLEANUP after every host (using real client)
            agent_inst_path = None
            for _, home, _, _ in valid_homes:
                if "/agent_" in home:
                    agent_inst_path = os.path.join(os.path.dirname(home), "agent_inst")
                    break
            if agent_inst_path:
                cleanup_agent_inst_temp_files(client, hostname, agent_inst_path)

        finally:
            SSH_POOL.release_client(client)
    except Exception as e:
        logger.error(f"Error processing host {hostname}: {e}")
        for pid, agent_home, _ in homes:
            updates.append((0, None, 'unknown', None, None, None, None, None, None, None, None, None, None, None, None, None, 0, hostname, agent_home))
            results.append((False, f"Error processing host {hostname}: {e}"))
    return results, updates, deletes, inserts, archive_inserts

def get_all_hosts(password):
    conn = get_db_connection(DB_USER, password, DB_DSN)
    cursor = conn.cursor()
    hosts = set()
    try:
        cursor.execute("SELECT LOWER(SYSTEM_NAME) FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME IS NOT NULL")
        system_hosts = [normalize_hostname(r[0]) for r in cursor]
        hosts.update(system_hosts)
        cursor.execute("SELECT LOWER(HOSTNAME) FROM MAAMD.GUESTS WHERE HOSTNAME IS NOT NULL")
        guest_hosts = [normalize_hostname(r[0]) for r in cursor]
        hosts.update(guest_hosts)
        cursor.execute("SELECT DISTINCT LOWER(hostname) FROM maamd.agent_home_info")
        existing = [normalize_hostname(r[0]) for r in cursor]
        hosts.update(existing)
        logger.info(f"Bootstrap discovery: Loaded {len(hosts)} unique hosts from SYSTEM_ALLOCATIONS + GUESTS + existing table (normalized)")
        return sorted(list(hosts))
    finally:
        cursor.close()
        conn.close()

def refresh_all_agent_status(full_mode=False, workers=None, single_host=None):
    try:
        password = os.environ.get('DB_PASSWORD')
        if not password:
            logger.error("Environment variable DB_PASSWORD is not set")
            return {"success": False, "message": "Environment variable DB_PASSWORD is not set"}
        logger.info("Retrieved database credentials for refreshing agent status")
        conn = get_db_connection(DB_USER, password, DB_DSN)
        cursor = conn.cursor()
        ensure_archive_table_exists(conn)
        query = """
        SELECT hostname, pid, agent_home, NVL(agent_owner, 'oracle') AS agent_owner
        FROM maamd.agent_home_info
        ORDER BY hostname, agent_home
        """
        cursor.execute(query)
        agent_homes = cursor.fetchall()
        logger.info(f"Fetched {len(agent_homes)} agent homes for status refresh")
        host_to_homes = defaultdict(list)
        is_bootstrap = full_mode and not single_host
        if single_host:
            single_host = normalize_hostname(single_host)
            logger.info(f"Single-host testing mode: Processing only {single_host}")
            host_to_homes[single_host] = [(pid, agent_home, agent_owner) for hostname, pid, agent_home, agent_owner in agent_homes if normalize_hostname(hostname) == single_host]
            if not host_to_homes[single_host]:
                host_to_homes[single_host] = []
        else:
            if is_bootstrap:
                logger.warning("Entering FULL discovery mode to repopulate table from scratch")
                logger.info("FULL mode: 100% ADDITIVE - table NEVER cleared")
                all_hosts = get_all_hosts(password)
                reachable_hosts = get_reachable_hosts(all_hosts)
                reachable_hosts = [normalize_hostname(h) for h in reachable_hosts]
                for hostname in reachable_hosts:
                    host_to_homes[hostname] = []
                logger.debug(f"FULL mode processing ALL {len(reachable_hosts)} normalized hosts")
            else:
                for hostname, pid, agent_home, agent_owner in agent_homes:
                    host_to_homes[normalize_hostname(hostname)].append((pid, agent_home, agent_owner))
        results = []
        updates = []
        deletes = []
        inserts = []
        archive_inserts = []
        start_time = time.time()
        worker_count = workers or (8 if full_mode else 24)
        processed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = []
            for hostname, homes in host_to_homes.items():
                if hostname in KNOWN_BAD_HOSTS:
                    logger.debug(f"[{hostname}] Skipping known-bad host")
                    continue
                futures.append(executor.submit(refresh_host_agents, hostname, homes, "GUEST" if "vm" in hostname.lower() else "PHYSICAL_HOST", conn, "system", full_mode and single_host))
                processed += 1
                if full_mode:
                    time.sleep(3.5)
                if processed % 5 == 0:
                    logger.debug(f"Progress: Submitted {processed}/{len(host_to_homes)} hosts...")
            for future in as_completed(futures):
                try:
                    host_results, host_updates, host_deletes, host_inserts, host_archive_inserts = future.result()
                    results.extend(host_results)
                    updates.extend(host_updates)
                    deletes.extend(host_deletes)
                    inserts.extend(host_inserts)
                    archive_inserts.extend(host_archive_inserts)
                except Exception as e:
                    logger.error(f"Host future failed: {e}")
        cursor = conn.cursor()
        try:
            conn.begin()
            if deletes:
                cursor.executemany("DELETE FROM maamd.agent_home_info WHERE hostname = :1 AND agent_home = :2", deletes)
                logger.info(f"Hard deleted {len(deletes)} stale agent homes")
            if inserts:
                insert_dict = {}
                for hostname, pid, agent_home, owner, status, cpu, mem, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors in inserts:
                    agent_home = normalize_agent_home(agent_home)
                    if not agent_home:
                        continue
                    if pid is None:
                        pid = 0
                    key = (hostname, agent_home)
                    if key not in insert_dict:
                        lsu = safe_format_date(last_successful_upload)
                        lau = safe_format_date(last_attempted_upload)
                        idt = safe_format_date(install_date)
                        insert_dict[key] = (
                            hostname,
                            pid,
                            agent_home,
                            owner,
                            status,
                            cpu,
                            mem,
                            oms_url,
                            target_count,
                            agent_version,
                            oms_version,
                            heartbeat_status,
                            running_duration,
                            port,
                            lsu,
                            lau,
                            idt,
                            total_space_mb,
                            total_errors,
                            'SYSTEM'
                        )
                insert_data = list(insert_dict.values())
                cursor.executemany("""
                    MERGE INTO maamd.agent_home_info t
                    USING (SELECT :1 hostname, :2 pid, :3 agent_home, :4 agent_owner, :5 AGENT_STATUS, :6 CPU_USAGE_PERCENT, :7 MEMORY_USAGE_MB, :8 OMS_URL, :9 TARGET_COUNT, :10 AGENT_VERSION, :11 OMS_VERSION, :12 HEARTBEAT_STATUS, :13 RUNNING_DURATION_HOURS, :14 PORT, :15 LAST_SUCCESSFUL_UPLOAD, :16 LAST_ATTEMPTED_UPLOAD, :17 INSTALL_DATE, :18 TOTAL_SPACE_MB, :19 TOTAL_ERRORS, SYSDATE LAST_REFRESHED, :20 CREATED_BY, SYSDATE CREATED_DATE FROM dual) s
                    ON (t.hostname = s.hostname AND t.agent_home = s.agent_home)
                    WHEN NOT MATCHED THEN
                        INSERT (hostname, pid, agent_home, agent_owner, AGENT_STATUS, CPU_USAGE_PERCENT, MEMORY_USAGE_MB, OMS_URL, TARGET_COUNT, AGENT_VERSION, OMS_VERSION, HEARTBEAT_STATUS, RUNNING_DURATION_HOURS, PORT, LAST_SUCCESSFUL_UPLOAD, LAST_ATTEMPTED_UPLOAD, INSTALL_DATE, TOTAL_SPACE_MB, TOTAL_ERRORS, LAST_REFRESHED, CREATED_BY, CREATED_DATE)
                        VALUES (s.hostname, s.pid, s.agent_home, s.agent_owner, s.AGENT_STATUS, s.CPU_USAGE_PERCENT, s.MEMORY_USAGE_MB, s.OMS_URL, s.TARGET_COUNT, s.AGENT_VERSION, s.OMS_VERSION, s.HEARTBEAT_STATUS, s.RUNNING_DURATION_HOURS, s.PORT,
                                TO_DATE(s.LAST_SUCCESSFUL_UPLOAD, 'YYYY-MM-DD HH24:MI:SS'),
                                TO_DATE(s.LAST_ATTEMPTED_UPLOAD, 'YYYY-MM-DD HH24:MI:SS'),
                                TO_DATE(s.INSTALL_DATE, 'YYYY-MM-DD HH24:MI:SS'),
                                s.TOTAL_SPACE_MB, s.TOTAL_ERRORS, s.LAST_REFRESHED, s.CREATED_BY, s.CREATED_DATE)
                """, insert_data)
                logger.info(f"Inserted {len(insert_data)} newly discovered agent homes (with PID) - deduplicated")
            if archive_inserts:
                archive_dict = {}
                for hostname, pid, agent_home, owner, status, cpu, mem, oms_url, target_count, agent_version, oms_version, heartbeat_status, running_duration, port, last_successful_upload, last_attempted_upload, install_date, total_space_mb, total_errors in archive_inserts:
                    agent_home = normalize_agent_home(agent_home)
                    if not agent_home:
                        continue
                    if pid is None:
                        pid = 0
                    key = (hostname, agent_home)
                    if key not in archive_dict:
                        archive_dict[key] = (
                            hostname,
                            pid,
                            agent_home,
                            owner,
                            status,
                            cpu,
                            mem,
                            'SYSTEM'
                        )
                archive_data = list(archive_dict.values())
                cursor.executemany("""
                    INSERT INTO maamd.agent_home_info_archive (hostname, pid, agent_home, agent_owner, AGENT_STATUS, CPU_USAGE_PERCENT, MEMORY_USAGE_MB, LAST_REFRESHED, CREATED_BY, CREATED_DATE)
                    VALUES (:1, :2, :3, :4, :5, :6, :7, SYSDATE, :8, SYSDATE)
                """, archive_data)
                logger.info(f"Inserted {len(archive_data)} non-running agents directly to archive")
            if updates:
                logger.info(f"Applying status update for {len(updates)} existing agent homes")
                batch_size = 100
                total_updated = 0
                for i in range(0, len(updates), batch_size):
                    batch = updates[i:i + batch_size]
                    cursor.executemany("""
                        UPDATE maamd.agent_home_info
                        SET pid = :1, "PID_TM" = :2, AGENT_STATUS = :3,
                            CPU_USAGE_PERCENT = :4, MEMORY_USAGE_MB = :5,
                            OMS_URL = :6, TARGET_COUNT = :7, AGENT_VERSION = :8,
                            OMS_VERSION = :9, HEARTBEAT_STATUS = :10,
                            RUNNING_DURATION_HOURS = :11, PORT = :12,
                            LAST_SUCCESSFUL_UPLOAD = TO_DATE(:13, 'YYYY-MM-DD HH24:MI:SS'),
                            LAST_ATTEMPTED_UPLOAD = TO_DATE(:14, 'YYYY-MM-DD HH24:MI:SS'),
                            INSTALL_DATE = TO_DATE(:15, 'YYYY-MM-DD HH24:MI:SS'),
                            TOTAL_SPACE_MB = :16, TOTAL_ERRORS = :17,
                            last_refreshed = SYSDATE
                        WHERE hostname = :18 AND agent_home = :19
                    """, batch)
                    total_updated += cursor.rowcount
                logger.info(f"Successfully updated {total_updated} rows in agent_home_info")
            purge_old_archive(conn)
            conn.commit()
            logger.info("All DB changes committed in single atomic transaction")
        except oracledb.Error as e:
            logger.error(f"Database error during cleanup/insert/update: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()
        success_count = sum(1 for success, _ in results if success)
        failure_count = len(results) - success_count
        elapsed_time = time.time() - start_time
        logger.info(f"Completed refresh: {success_count} successful, {failure_count} failed, {len(deletes)} deleted, {len(inserts)} inserted in {elapsed_time:.2f} seconds")
        failed_hosts = set()
        for success, msg in results:
            if not success:
                if "unreachable" in msg.lower() or "failed to connect" in msg.lower():
                    failed_hosts.add("unreachable")
                else:
                    failed_hosts.add(msg.split("on ")[-1].split(" ")[0] if "on " in msg else "unknown")
        if failed_hosts:
            logger.info(f"Failed hosts summary: {', '.join(sorted(failed_hosts))}")
        conn.close()
        return {
            "success": True,
            "message": f"Refreshed {success_count} agent homes successfully (deleted {len(deletes)}, inserted {len(inserts)})",
            "failures": failure_count
        }
    except oracledb.Error as e:
        logger.error(f"Database error: {e}", exc_info=True)
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return {"success": False, "message": f"Database error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return {"success": False, "message": f"Unexpected error: {str(e)}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Refresh EM Agent status')
    parser.add_argument('--full', action='store_true', help='FULL discovery scan (use every 2 hours)')
    parser.add_argument('--workers', type=int, default=None, help='Number of parallel workers (default 8 for --full, 24 otherwise)')
    parser.add_argument('--host', type=str, default=None, help='Run only on this specific hostname for testing')
    parser.add_argument('--debug', action='store_true', help='Enable verbose DEBUG logging (default: INFO level to control log file size)')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.info("DEBUG logging enabled via --debug flag")
    else:
        logger.info("INFO mode active - debug noise suppressed to prevent excessive log growth")
    result = refresh_all_agent_status(full_mode=args.full, workers=args.workers, single_host=args.host)
    logger.info(f"Result: {result}")
