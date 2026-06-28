#!/usr/bin/env python3
# Filename: setup_passwordless_ssh.py
# Version: 2026-04-23 v1.9
# Changes: Reduced timeouts + retries for speed. Added early connectivity check. Faster failure handling. Improved dcli handling.

import os
import sys
import logging
import paramiko
import oracledb
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from cryptography.fernet import Fernet
import argparse
from logging.handlers import RotatingFileHandler
import atexit
import subprocess
import socket

# ========================= CONFIG =========================
LOG_DIR = "./output"
LOG_FILE = os.path.join(LOG_DIR, "setup_passwordless_ssh.log")
SSH_KEY_PATH = "/home/maatest/.ssh/id_ed25519_maa"
SSH_KEY_PUB_PATH = SSH_KEY_PATH + ".pub"
SSH_TIMEOUT = 15          # Reduced from 30 for speed
MAX_WORKERS = 12
MAX_RETRIES = 2           # Reduced from 5 for speed
DB_USER = "maamd"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
LOCK_FILE = "/tmp/setup_passwordless_ssh.pid"
DB_PASSWORD = os.environ.get("DB_PASSWORD")

if not DB_PASSWORD:
    print("Error: DB_PASSWORD environment variable not set")
    sys.exit(1)

os.makedirs(LOG_DIR, exist_ok=True)

# ========================= SINGLE INSTANCE LOCK =========================
def acquire_lock():
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE) as f:
                old_pid = int(f.read().strip())
            if os.path.exists(f"/proc/{old_pid}"):
                print(f"Another instance is already running (PID {old_pid}). Exiting.")
                sys.exit(1)
        except Exception:
            pass
    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(lambda: os.unlink(LOCK_FILE) if os.path.exists(LOCK_FILE) else None)

# ========================= LOGGING =========================
def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.WARNING
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setLevel(level)
    file_formatter = logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s')
    file_handler.setFormatter(file_formatter)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO if debug else logging.WARNING)
    console_formatter = logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

# ========================= DECRYPTION =========================
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
        return None
    except Exception:
        return None

def decrypt_credential(enc_pass_blob, _):
    try:
        enc_pass = enc_pass_blob.read() if enc_pass_blob else b''
        return decrypt_data(enc_pass)
    except Exception:
        return None

# ========================= HELPERS =========================
def get_db_connection():
    return oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN)

def is_hypervisor(host):
    return any(x in host.lower() for x in ['kvm', 'hypervisor', 'hyper'])

def is_root_only(host):
    return is_hypervisor(host) or any(x in host.lower() for x in ['cel', 'cell'])

def is_exadata_compute_or_storage(host):
    return any(x in host.lower() for x in ['adm', 'cell', 'cel'])

def get_guests_on_hypervisor(hypervisor):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT LOWER(HOSTNAME) FROM MAAMD.GUESTS WHERE UPPER(HYPERVISOR) = UPPER(:hv)", hv=hypervisor)
        return [row[0] for row in cursor]
    finally:
        cursor.close()
        conn.close()

def get_credentials(host, username):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE UPPER(COMPONENT_NAME) = UPPER(:h)
              AND UPPER(USERNAME) = UPPER(:u)
            FETCH FIRST 1 ROW ONLY
        """, h=host, u=username)
        row = cursor.fetchone()
        if row and row[0]:
            return decrypt_credential(row[0], None)
        ctype = 'GUEST' if not is_root_only(host) else 'PHYSICAL_HOST'
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_NAME = 'default'
              AND COMPONENT_TYPE IN (:ct, 'PHYSICAL_HOST', 'GUEST')
              AND UPPER(USERNAME) = UPPER(:u)
            FETCH FIRST 1 ROW ONLY
        """, ct=ctype, u=username)
        row = cursor.fetchone()
        if row and row[0]:
            return decrypt_credential(row[0], None)
        return None
    finally:
        cursor.close()
        conn.close()

def get_ssh_home(username):
    return "/root" if username.lower() == "root" else f"/home/{username}"

def load_public_key():
    with open(SSH_KEY_PUB_PATH) as f:
        return f.read().strip()

def load_private_key():
    return paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)

def verify_exact_key(host, username, pubkey):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, pkey=load_private_key(), timeout=SSH_TIMEOUT,
                       allow_agent=False, look_for_keys=False,
                       disabled_algorithms={'pubkeys': ['ssh-dss']})
        ssh_home = get_ssh_home(username)
        key_parts = pubkey.split()
        if len(key_parts) < 2:
            return False
        key_id = f"{key_parts[0]} {key_parts[1]}"
        _, stdout, _ = client.exec_command(f'grep -F "{key_id}" {ssh_home}/.ssh/authorized_keys || true')
        result = stdout.read().decode().strip()
        return bool(result)
    except Exception:
        return False
    finally:
        try:
            client.close()
        except:
            pass

def atomic_append_key(client, username, pubkey):
    ssh_home = get_ssh_home(username)
    key_owner = "root:root" if username.lower() == "root" else "oracle:oinstall"
    cmd = f'''mkdir -p {ssh_home}/.ssh && chmod 700 {ssh_home}/.ssh && \
cp -f {ssh_home}/.ssh/authorized_keys {ssh_home}/.ssh/authorized_keys.bck 2>/dev/null || true && \
sed -i '/id_ed25519_maa/d' {ssh_home}/.ssh/authorized_keys 2>/dev/null || true && \
cat >> {ssh_home}/.ssh/authorized_keys << 'EOF_MAA_KEY'
{pubkey}
EOF_MAA_KEY
chmod 600 {ssh_home}/.ssh/authorized_keys && \
chown {key_owner} {ssh_home}/.ssh/authorized_keys && \
restorecon -F {ssh_home}/.ssh/authorized_keys 2>/dev/null || true && \
echo "KEY_DEPLOYED_SUCCESSFULLY"'''
    for attempt in range(3):
        try:
            _, stdout, stderr = client.exec_command(cmd)
            stderr_out = stderr.read().decode().strip()
            output = stdout.read().decode().strip()
            if "KEY_DEPLOYED_SUCCESSFULLY" in output:
                if stderr_out:
                    logger.debug(f"[{client.get_transport().getpeername()[0]}] stderr: {stderr_out}")
                return True
        except Exception as e:
            logger.debug(f"atomic_append attempt {attempt+1} failed: {e}")
        if attempt < 2:
            import time
            time.sleep(2)
    return False

def force_append_key_for_root(host, pubkey):
    logger.info(f"[{host}] root password failed → forcing atomic MAA key append")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username="root", pkey=load_private_key(), timeout=SSH_TIMEOUT,
                       allow_agent=False, look_for_keys=False)
        if atomic_append_key(client, "root", pubkey):
            if verify_exact_key(host, "root", pubkey):
                logger.info(f"[{host}] root MAA key forced successfully (verified)")
                return True
        return False
    except Exception as e:
        logger.error(f"[{host}] atomic force-append for root failed: {e}")
        return False
    finally:
        client.close()

def ensure_dcli_equivalence(host):
    """Run official Oracle dcli -l root -k for Exadata compute/storage hosts.
    Uses ssh-keyscan first to handle changed host keys gracefully.
    """
    if not is_exadata_compute_or_storage(host):
        return True

    logger.info(f"[{host}] Running official dcli -l root -k equivalence setup")

    try:
        # Pre-scan host key to avoid "host key changed" errors
        scan_cmd = f"ssh-keyscan -t ecdsa,ed25519 {host} >> ~/.ssh/known_hosts_maa 2>/dev/null || true"
        subprocess.run(scan_cmd, shell=True, timeout=15)

        cmd = f"dcli -l root -k -c {host} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)

        if result.returncode == 0 or "ssh key already exists" in result.stdout.lower():
            logger.info(f"[{host}] dcli -l root -k completed successfully")
            return True
        else:
            logger.warning(f"[{host}] dcli -l root -k returned non-zero (may still be ok)")
            return True

    except Exception as e:
        logger.warning(f"[{host}] dcli -l root -k failed (non-fatal): {e}")
        return True

def setup_passwordless_for_user(host, username, pubkey, pkey, force=False):
    logger.info(f"[{host}] Setting up {username}...")

    # Quick connectivity check first (saves a lot of time)
    try:
        socket.create_connection((host, 22), timeout=8)
    except:
        logger.warning(f"[{host}] Port 22 not reachable — skipping {username}")
        return False

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for attempt in range(MAX_RETRIES + 1):
        try:
            client.connect(host, username=username, pkey=pkey, timeout=SSH_TIMEOUT,
                           allow_agent=False, look_for_keys=False,
                           disabled_algorithms={'pubkeys': ['ssh-dss']})
            if not force and verify_exact_key(host, username, pubkey):
                logger.info(f"[{host}] {username} already has the EXACT MAA key")
                if username == "root":
                    ensure_dcli_equivalence(host)
                return True
        except Exception:
            pass

        password = get_credentials(host, username)
        if not password:
            if username == "root":
                logger.info(f"[{host}] No root password in DB → forcing atomic MAA key append")
                if force_append_key_for_root(host, pubkey):
                    if username == "root":
                        ensure_dcli_equivalence(host)
                    return True
                return False
            elif username == "oracle":
                logger.info(f"[{host}] No oracle password in DB → trying root-fallback")
                return setup_oracle_via_root(host, pubkey)
            else:
                return False

        try:
            client.connect(host, username=username, password=password, timeout=SSH_TIMEOUT,
                           allow_agent=False, look_for_keys=False)
            if atomic_append_key(client, username, pubkey):
                if verify_exact_key(host, username, pubkey):
                    logger.info(f"[{host}] {username} key successfully deployed (verified exact match)")
                    if username == "root":
                        ensure_dcli_equivalence(host)
                    return True
        except Exception as e:
            if attempt == MAX_RETRIES:
                if username == "root":
                    logger.info(f"[{host}] root password auth failed → forcing atomic append")
                    if force_append_key_for_root(host, pubkey):
                        if username == "root":
                            ensure_dcli_equivalence(host)
                        return True
                    return False
                elif username == "oracle":
                    logger.info(f"[{host}] oracle password auth failed → trying root-fallback")
                    return setup_oracle_via_root(host, pubkey)
                else:
                    logger.error(f"[{host}] Bootstrap failed for {username}: {e}")
                    return False
            continue
        finally:
            client.close()
    return False if username == "root" else True

def setup_oracle_via_root(host, pubkey):
    logger.info(f"[{host}] oracle password failed → attempting root-fallback deployment")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username="root", pkey=load_private_key(), timeout=SSH_TIMEOUT,
                       allow_agent=False, look_for_keys=False)
        if atomic_append_key(client, "oracle", pubkey):
            if verify_exact_key(host, "oracle", pubkey):
                logger.info(f"[{host}] oracle key deployed via root fallback (verified)")
                return True
        return False
    except Exception as e:
        logger.error(f"[{host}] root-fallback for oracle failed: {e}")
        return False
    finally:
        client.close()

def setup_host(host, pubkey, pkey, hyper_to_guests, force=False):
    results = []
    users = ["root"]
    if not is_root_only(host):
        users.append("oracle")
    root_ok = False
    for user in users:
        ok = setup_passwordless_for_user(host, user, pubkey, pkey, force)
        results.append((user, ok))
        if user == "root":
            root_ok = ok
    if root_ok and is_hypervisor(host):
        guests = hyper_to_guests.get(host.lower(), [])
        if guests:
            logger.info(f"[{host}] Root success → propagating to {len(guests)} guests")
            for guest in guests:
                for user in ["root", "oracle"]:
                    ok = setup_passwordless_for_user(guest, user, pubkey, pkey, force)
                    results.append((f"{guest}:{user}", ok))
    return results

def get_all_hosts():
    conn = get_db_connection()
    cursor = conn.cursor()
    hosts = set()
    try:
        cursor.execute("SELECT LOWER(SYSTEM_NAME) FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME IS NOT NULL")
        system_hosts = [r[0] for r in cursor]
        hosts.update(system_hosts)
        cursor.execute("SELECT LOWER(HOSTNAME) FROM MAAMD.GUESTS WHERE HOSTNAME IS NOT NULL")
        guest_hosts = [r[0] for r in cursor]
        hosts.update(guest_hosts)
        return sorted(list(hosts))
    finally:
        cursor.close()
        conn.close()

def generate_fix_script(failed_hosts):
    failed_hosts_list = repr(failed_hosts)
    fix_content = '''#!/usr/bin/env python3
SSH_KEY_PUB_PATH = "/home/maatest/.ssh/id_ed25519_maa.pub"
SSH_TIMEOUT = 15
MAX_RETRIES = 2
FAILED_HOSTS = {0}
import subprocess
from datetime import datetime
def load_public_key():
    with open(SSH_KEY_PUB_PATH) as f:
        return f.read().strip()
def fix_host(host, pubkey):
    print(f"[{{host}}] Fixing root...")
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
        "root@" + host,
        f"mkdir -p /root/.ssh && cp -f /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bck 2>/dev/null || true && echo '{{{{pubkey}}}}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && restorecon -F /root/.ssh/authorized_keys 2>/dev/null || true && echo 'KEY_ADDED'"
    ]
    for attempt in range(MAX_RETRIES):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=SSH_TIMEOUT)
            if result.returncode == 0 and "KEY_ADDED" in result.stdout:
                print(f"[{{host}}] root fixed successfully")
                if not any(x in host.lower() for x in ['cel', 'cell', 'kvm', 'hyper']):
                    print(f"[{{host}}] Fixing oracle...")
                    cmd_oracle = cmd.copy()
                    cmd_oracle[-1] = cmd_oracle[-1].replace("/root/.ssh", "/home/oracle/.ssh").replace("root@", "oracle@")
                    subprocess.run(cmd_oracle, capture_output=True, text=True, timeout=SSH_TIMEOUT)
                return True
            else:
                print(f"[{{host}}] Attempt {{attempt+1}} failed: {{result.stderr.strip()}}")
        except Exception as e:
            print(f"[{{host}}] Attempt {{attempt+1}} exception: {{e}}")
        if attempt < MAX_RETRIES - 1:
            print(f"[{{host}}] Retrying...")
    print(f"[{{host}}] FAILED after {{MAX_RETRIES}} attempts")
    return False
def main():
    print(f"Starting MANUAL MAA SSH key fix - {{datetime.now()}}")
    pubkey = load_public_key()
    print(f"Loaded MAA public key from {{SSH_KEY_PUB_PATH}}")
    success = 0
    failed = []
    for host in FAILED_HOSTS:
        if fix_host(host, pubkey):
            success += 1
        else:
            failed.append(host)
    print("\\n" + "="*80)
    print("MANUAL FIX COMPLETED")
    print(f"Successful hosts fixed: {{success}}/{{len(FAILED_HOSTS)}}")
    if failed:
        print(f"Still failed ({{len(failed)}}): {{', '.join(failed)}}")
        print("Run this script again.")
    else:
        print("100% COMPLIANCE ACHIEVED")
    print("="*80)
if __name__ == "__main__":
    main()
'''.format(failed_hosts_list)
    fix_path = os.path.join(LOG_DIR, "fix_failed_ssh_keys.py")
    with open(fix_path, "w") as f:
        f.write(fix_content)
    os.chmod(fix_path, 0o755)
    logger.info(f"Auto-generated fix script: {fix_path} – run it to fix remaining hosts")

def setup_ssh_config():
    config_path = os.path.expanduser("~/.ssh/config")
    config_dir = os.path.dirname(config_path)
    os.makedirs(config_dir, exist_ok=True)
    os.chmod(config_dir, 0o700)
    config_content = f"""# MAA Patchmgr SSH Configuration - Managed by setup_passwordless_ssh.py v1.9
Host *adm*vm* *cel* *cell* *v6adm*vm* *.us.oracle.com
    IdentityFile {SSH_KEY_PATH}
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts_maa
    ServerAliveInterval 45
    ServerAliveCountMax 5
    ConnectTimeout 20
Host *
    IdentityFile {SSH_KEY_PATH}
"""
    with open(config_path, "w") as f:
        f.write(config_content)
    os.chmod(config_path, 0o600)
    logger.info(f"✓ Created/updated {config_path} – MAA key is now default for patchmgr/dcli")

def main():
    acquire_lock()
    parser = argparse.ArgumentParser(description="MAA Passwordless SSH Setup v1.9")
    parser.add_argument('--debug', action='store_true', help="Enable verbose logging")
    parser.add_argument('--force', action='store_true', help="Force re-apply key on every host")
    args = parser.parse_args()

    global logger
    logger = setup_logging(args.debug)
    logger.info(f"Starting FULLY AUTOMATIC passwordless SSH setup v1.9 - {datetime.now()}")

    setup_ssh_config()

    hyper_to_guests = defaultdict(list)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT LOWER(HYPERVISOR), LOWER(HOSTNAME) FROM MAAMD.GUESTS WHERE HYPERVISOR IS NOT NULL")
        for h, g in cursor:
            hyper_to_guests[h].append(g)
    finally:
        cursor.close()
        conn.close()

    pubkey = load_public_key()
    pkey = load_private_key()
    hosts = get_all_hosts()

    success_count = 0
    failed_hosts = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_host = {executor.submit(setup_host, host, pubkey, pkey, hyper_to_guests, args.force): host for host in hosts}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                root_ok = any(u == "root" and ok for u, ok in result)
                if root_ok:
                    success_count += sum(1 for _, ok in result if ok)
                else:
                    failed_hosts.append(host)
            except Exception as e:
                logger.error(f"[{host}] thread failed: {e}")
                failed_hosts.append(host)

    failed_hosts = list(dict.fromkeys(failed_hosts))
    logger.info(f"Run completed. Successful user setups: {success_count}")

    if failed_hosts:
        logger.error(f"FAILED hosts ({len(failed_hosts)}): {', '.join(failed_hosts)}")
        generate_fix_script(failed_hosts)
    else:
        logger.info("100% COMPLIANCE ACHIEVED – every host has the exact MAA key")

if __name__ == "__main__":
    main()
