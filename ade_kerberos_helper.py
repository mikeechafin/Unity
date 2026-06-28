import subprocess
import time
import shutil
import socket
import os
import re
import getpass
from maa_libraries import logger, get_db_pool_connection, release_db_connection, get_credential_silent

try:
    import pexpect
except ImportError:
    pexpect = None
    logger.warning("[ADE v2.2] pexpect not installed - Kerberos auto re-init will be SKIPPED")

ADE_REMOTE_HOST = "phoenix95023.dev3sub2phx.databasede3phx.oraclevcn.com"
ADE_REMOTE_USER = "mchafin"
ADE_SSH_KEY = "/home/maatest/.ssh/id_ed25519_maa"

def get_current_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

def get_ade_password(pool):
    if not pool:
        logger.warning("[ADE v2.2 Kerberos] No DB pool provided to get_ade_password")
        return None
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        candidates = [
            ('ADE', 'default', 'mchafin'),
            ('ADE', 'ade', 'mchafin'),
            ('STAGING', 'default', 'mchafin'),
            ('STAGING', 'ade', 'mchafin'),
            ('GLOBAL', 'default', 'mchafin'),
            ('PHYSICAL_HOST', 'default', 'mchafin'),
            ('ADE', 'staging', 'mchafin'),
            ('STAGING', 'staging', 'mchafin'),
            ('ADE', 'main', 'mchafin'),
        ]
        for ctype, cname, user in candidates:
            pwd = get_credential_silent(cursor, ctype, cname, user)
            if pwd:
                logger.info(f"[ADE v2.2 Kerberos] SUCCESS (exact): Found password for {user} under {ctype}/{cname}")
                return pwd

        logger.info("[ADE v2.2 Kerberos] No exact match — running BROADEST query for mchafin")
        cursor.execute("""
            SELECT CREDENTIAL_TYPE, CREDENTIAL_NAME, USERNAME 
            FROM ACCESS_CREDENTIALS 
            WHERE UPPER(USERNAME) = 'MCHAFIN'
            ORDER BY CREDENTIAL_TYPE, CREDENTIAL_NAME
        """)
        rows = cursor.fetchall()
        for row in rows:
            pwd = get_credential_silent(cursor, row[0], row[1], row[2])
            if pwd:
                logger.info(f"[ADE v2.2 Kerberos] BROAD SUCCESS: Found password under {row[0]}/{row[1]}")
                return pwd
        return None
    finally:
        cursor.close()
        release_db_connection(conn, pool)

def clean_ssh_warnings(text):
    if not text:
        return ""
    text = re.sub(r'Warning: Permanently added .* to the list of known hosts\.', '', text)
    text = re.sub(r'Warning: .* known hosts\.', '', text)
    text = re.sub(r'Pseudo-terminal will not be allocated because stdin is not a terminal\.', '', text)
    return text.strip()

def run_ade_command(cmd, pool=None, max_retries=2, timeout=120):
    current_host = get_current_hostname()
    is_exadata_cell = 'scaqaa' in current_host.lower() or 'celadm' in current_host.lower()
    ade_local_path = shutil.which('ade') if not is_exadata_cell else None
    use_remote = is_exadata_cell or (ade_local_path is None)

    effective_user = getpass.getuser()
    try:
        effective_uid = os.getuid()
    except Exception:
        effective_uid = -1
    key_readable = os.access(ADE_SSH_KEY, os.R_OK) if os.path.exists(ADE_SSH_KEY) else False

    logger.info(f"[ADE v2.2] Host={current_host} | effective_user={effective_user} (uid={effective_uid}) | key_readable={key_readable} | use_remote={use_remote}")

    if not cmd or not cmd.strip():
        err = f"CRITICAL: Empty or invalid ADE command: {repr(cmd)}"
        logger.error(f"[ADE v2.2] {err}")
        return "", err, 1

    if use_remote and not key_readable:
        err = f"CRITICAL: SSH key {ADE_SSH_KEY} not readable by effective user {effective_user}"
        logger.error(f"[ADE v2.2] {err}")
        return "", err, 1

    for attempt in range(max_retries + 1):
        try:
            logger.info(f"[ADE v2.2] Attempt {attempt+1}: {cmd}")

            if use_remote:
                # v2.3: Pass command directly to SSH (remote login shell handles it). Avoids quoting issues with extra bash -c wrapper.
                ssh_cmd = [
                    'ssh', '-T', '-i', ADE_SSH_KEY,
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'ConnectTimeout=30',
                    '-o', 'BatchMode=yes',
                    f'{ADE_REMOTE_USER}@{ADE_REMOTE_HOST}',
                    cmd
                ]
                logger.info(f"[ADE v2.3] Remote command being sent: {cmd}")
                logger.info(f"[ADE v2.3] Full SSH argv: {ssh_cmd}")
                result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(
                    ['/bin/bash', '-l', '-c', cmd],
                    capture_output=True, text=True, timeout=timeout
                )

            stdout = clean_ssh_warnings(result.stdout or "")
            stderr = clean_ssh_warnings(result.stderr or "")
            rc = result.returncode

            logger.info(f"[ADE v2.2] rc={rc} | stdout[:300]={stdout[:300]!r} | stderr[:300]={stderr[:300]!r}")

            if rc == 0:
                return stdout, stderr, 0

            is_kerberos_error = "Initial Kerberos ticket required" in (stdout + stderr)

            if is_kerberos_error and attempt < max_retries:
                logger.warning("[ADE v2.2] Kerberos ticket expired - attempting auto re-init...")
                pwd = get_ade_password(pool)
                if not pwd:
                    err = "CRITICAL: No mchafin password in ACCESS_CREDENTIALS. Run 'ade okinit' manually on phoenix95023 as mchafin."
                    logger.error(err)
                    return stdout, err, 1

                if pexpect is None:
                    return stdout, "pexpect not installed - run 'ade okinit' manually on phoenix95023 as mchafin.", rc

                try:
                    if use_remote:
                        okinit_args = [
                            'ssh', '-t', '-i', ADE_SSH_KEY,
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'UserKnownHostsFile=/dev/null',
                            f'{ADE_REMOTE_USER}@{ADE_REMOTE_HOST}',
                            'ade', 'okinit'
                        ]
                        child = pexpect.spawn(okinit_args[0], okinit_args[1:], timeout=45, encoding='utf-8')
                    else:
                        child = pexpect.spawn('ade okinit', timeout=45, encoding='utf-8')

                    i = child.expect(['Password for .*@.*:', pexpect.EOF, pexpect.TIMEOUT], timeout=20)
                    if i == 0:
                        child.sendline(pwd)
                        child.expect(pexpect.EOF, timeout=30)
                        child.close()
                        logger.info("[ADE v2.2] okinit SUCCESS")
                        time.sleep(5)
                        continue
                    else:
                        child.close()
                        return stdout, "okinit did not prompt for password", 1
                except Exception as e:
                    logger.error(f"[ADE v2.2] okinit exception: {e}")
                    return stdout, f"Kerberos re-init failed: {str(e)}", 1
            else:
                return stdout, stderr, rc

        except subprocess.TimeoutExpired:
            return "", f"ADE command timed out after {timeout}s", 1
        except Exception as e:
            logger.error(f"[ADE v2.2] Unexpected error: {e}", exc_info=True)
            return "", str(e), 1

    return "", "Max retries exceeded", 1

if __name__ == "__main__":
    print("ade_kerberos_helper.py v2.2 - PTY handling fixed")
