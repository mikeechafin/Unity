#!/usr/bin/env python3
import os
import re
import sys
import time
import logging
import hashlib
import paramiko
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue, Empty
import argparse
import shutil
from threading import Lock, Thread
from maa_libraries import get_db_connection_standalone, get_credential_silent
"""
Version: 2026-04-02 v1.0.9
Changes: Removed release_db_connection import and all calls (replaced with direct conn.close() for standalone connections). Fixes NameError in get_client fallback + main finally. Parser now completes cleanly.
"""
# Constants
REMOTE_USERS = ["oracle", "root"]
SSH_KEY_PATHS = [
    ("/home/maatest/.ssh/id_rsa", "rsa"),
    ("/home/maatest/.ssh/id_ecdsa", "ecdsa"),
    ("/home/maatest/.ssh/id_ed25519", "ed25519")
]
SSH_TIMEOUT = 15
SSH_BANNER_TIMEOUT = 5
SSH_RETRIES = 2
SSH_COMMAND_TIMEOUT = 1200
MAX_LOG_SIZE_MB = 1000
SMALL_FILE_SIZE_MB = 10
DB_BATCH_SIZE = 20000
TEMP_DIR = '/tmp/temp_logs'
LOG_FILE_PATTERN = r'^(gcagent\.log|gcagent_sdk\.trc|gcagent_errors\.log|emagent\.log|emctl\.log|emdctlj\.log|xa_analytics_.*\.log|\w+\.trc|\w+\.out|OraInstallNG.*\.log)(\.\d+)?$'

import config

log_dir = config.OUTPUT_DIR
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(os.path.join(log_dir, "parse_agent_logs.log"))]
)
logger = logging.getLogger(__name__)
logger.info("=== MAA WORLD-CLASS AGENT LOG PARSER STARTED (v1.0.9) ===")

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true')
parser.add_argument('--test-host', type=str, default=None)
args = parser.parse_args()
DEBUG_MODE = args.debug
TEST_HOST = args.test_host

ERROR_QUEUE = Queue()
ERROR_PATTERNS = [
    re.compile(r'ERROR:\s*(.*)'),
    re.compile(r'WARNING:\s*(.*)'),
    re.compile(r'Exception:\s*(.*)'),
    re.compile(r'Failed:\s*(.*)'),
    re.compile(r'ORA-\d+:\s*(.*)')
]
EXCLUDE_PATTERNS = [
    re.compile(r'INFO:\s*(.*)'),
    re.compile(r'DEBUG:\s*(.*)'),
    re.compile(r'Successfully.*')
]

class SSHConnectionPool:
    def __init__(self, max_size=50):
        self.pool = Queue(maxsize=max_size)
        self.lock = Lock()
    def get_client(self, hostname, component_type="GUEST"):
        with self.lock:
            try:
                client = self.pool.get_nowait()
                if client.get_transport() and client.get_transport().is_active():
                    return client
                client.close()
            except:
                pass
            for attempt in range(SSH_RETRIES):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connected = False
                for username in REMOTE_USERS:
                    for pkey, _ in SSH_KEYS:
                        try:
                            client.connect(hostname, username=username, pkey=pkey, timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT)
                            connected = True
                            break
                        except:
                            pass
                    if connected:
                        break
                    conn = get_db_connection_standalone()
                    cursor = conn.cursor()
                    try:
                        password = get_credential_silent(cursor, component_type, hostname, username)
                        if not password:
                            password = get_credential_silent(cursor, component_type, "default", username)
                        if password:
                            client.connect(hostname, username=username, password=password, timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT)
                            connected = True
                            break
                    finally:
                        cursor.close()
                        conn.close()  # standalone - use close()
                if connected:
                    client.get_transport().set_keepalive(30)
                    return client
                client.close()
            return None
    def release_client(self, client):
        with self.lock:
            if client and self.pool.qsize() < self.pool.maxsize and client.get_transport().is_active():
                self.pool.put(client)
            elif client:
                client.close()

SSH_POOL = SSHConnectionPool()
SSH_KEYS = []
for path, key_type in SSH_KEY_PATHS:
    if os.path.isfile(path):
        try:
            if key_type == "rsa":
                key = paramiko.RSAKey.from_private_key_file(path)
            elif key_type == "ecdsa":
                key = paramiko.ECDSAKey.from_private_key_file(path)
            else:
                key = paramiko.Ed25519Key.from_private_key_file(path)
            SSH_KEYS.append((key, os.path.basename(path)))
        except Exception as e:
            logger.warning(f"Failed to load key {path}: {e}")

def db_writer():
    batch = []
    while True:
        try:
            item = ERROR_QUEUE.get(timeout=1)
            if item is None:
                if batch:
                    insert_batch(batch)
                return
            batch.append(item)
            if len(batch) >= DB_BATCH_SIZE:
                insert_batch(batch)
                batch = []
        except Empty:
            if batch:
                insert_batch(batch)
                batch = []
            continue

def insert_batch(batch):
    conn = None
    try:
        conn = get_db_connection_standalone()
        cursor = conn.cursor()
        for item in batch:
            cursor.execute("""
                MERGE INTO maamd.agent_errors dest
                USING (SELECT :1 hostname, :2 port, TO_DATE(:3,'YYYY-MM-DD"T"HH24:MI:SS') timestamp,
                       :4 error_message, :5 error_message_trunc, :6 error_type, :7 error_hash FROM dual) src
                ON (dest.hostname = src.hostname AND dest.error_hash = src.error_hash)
                WHEN MATCHED THEN UPDATE SET occurrence_count = occurrence_count + 1, last_updated = SYSDATE
                WHEN NOT MATCHED THEN INSERT (hostname,port,timestamp,error_message,error_message_trunc,error_type,error_hash,occurrence_count,last_updated)
                VALUES (src.hostname,src.port,src.timestamp,src.error_message,src.error_message_trunc,src.error_type,src.error_hash,1,SYSDATE)
            """, item)
        conn.commit()
        logger.debug(f"Committed batch of {len(batch)} errors")
    finally:
        if conn:
            conn.close()  # standalone - use close()

def process_host(hostname, agent_home, port=None):
    client = None
    errors = []
    files_processed = 0
    try:
        client = SSH_POOL.get_client(hostname)
        if not client:
            logger.error(f"Failed SSH to {hostname}")
            return [], 0
        find_cmd = f"find {shlex.quote(agent_home + '/sysman/log/')} -type f -regextype posix-egrep -regex '{LOG_FILE_PATTERN}' -printf '%s\\t%p\\n' 2>/dev/null"
        _, stdout, _ = client.exec_command(find_cmd, timeout=SSH_COMMAND_TIMEOUT)
        log_files = []
        for line in stdout:
            size, path = line.strip().split('\t', 1)
            log_files.append((int(size), path))
        logger.info(f"Found {len(log_files)} log files on {hostname}:{agent_home}")
        for size, log_path in log_files:
            if size > MAX_LOG_SIZE_MB * 1024 * 1024:
                continue
            files_processed += 1
            logger.info(f"Processing {os.path.basename(log_path)} ({size//1024} KB) on {hostname}")
            if size < SMALL_FILE_SIZE_MB * 1024 * 1024:
                _, stdout, _ = client.exec_command(f"cat {shlex.quote(log_path)}", timeout=SSH_COMMAND_TIMEOUT)
                lines = stdout.readlines()
            else:
                local_path = os.path.join(TEMP_DIR, os.path.basename(log_path))
                os.makedirs(TEMP_DIR, exist_ok=True)
                with client.open_sftp() as sftp:
                    sftp.get(log_path, local_path)
                with open(local_path, 'r') as f:
                    lines = f.readlines()
                os.remove(local_path)
            logger.debug(f"Processed {len(lines)} lines from {log_path} on {hostname}")
            for line in lines:
                line = line.strip()
                for pattern in ERROR_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        error_msg = match.group(1).strip()
                        if any(ex.search(error_msg) for ex in EXCLUDE_PATTERNS):
                            continue
                        error_hash = hashlib.md5((error_msg + "ERROR").encode()).hexdigest()
                        errors.append((hostname, port, datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), error_msg, error_msg[:4000], "ERROR", error_hash))
                        break
        return errors, files_processed
    finally:
        if client:
            SSH_POOL.release_client(client)

def main():
    start_time = time.time()
    logger.info("Starting world-class parser - heavy logging enabled")
    db_thread = Thread(target=db_writer)
    db_thread.start()
    conn = get_db_connection_standalone()
    try:
        cursor = conn.cursor()
        if TEST_HOST:
            cursor.execute("SELECT hostname, agent_home, port FROM maamd.agent_home_info WHERE hostname = :1", (TEST_HOST,))
        else:
            cursor.execute("SELECT hostname, agent_home, port FROM maamd.agent_home_info")
        agent_homes = cursor.fetchall()
        logger.info(f"Processing {len(agent_homes)} agent homes from agent_home_info table (maamd user)")
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_host = {executor.submit(process_host, h[0], h[1], h[2]): h for h in agent_homes}
            total_files = 0
            for i, future in enumerate(as_completed(future_to_host), 1):
                hostname, agent_home = future_to_host[future][0], future_to_host[future][1]
                errors, files_processed = future.result()
                total_files += files_processed
                for e in errors:
                    ERROR_QUEUE.put(e)
                try:
                    inventory_conn = get_db_connection_standalone()
                    inv_cursor = inventory_conn.cursor()
                    inv_cursor.execute("""
                        MERGE INTO maamd.AGENT_LOG_INVENTORY dest
                        USING (SELECT :1 hostname, :2 agent_home, SYSDATE parsed_date FROM dual) src
                        ON (dest.hostname = src.hostname AND dest.agent_home = src.agent_home)
                        WHEN MATCHED THEN UPDATE SET dest.parsed_date = src.parsed_date
                        WHEN NOT MATCHED THEN INSERT (hostname, agent_home, parsed_date)
                        VALUES (src.hostname, src.agent_home, src.parsed_date)
                    """, (hostname, agent_home))
                    inventory_conn.commit()
                    inventory_conn.close()
                    logger.info(f"[{i}/{len(agent_homes)}] {hostname}:{agent_home} → {files_processed} files tracked")
                except Exception as e:
                    logger.error(f"Inventory update failed for {hostname}:{agent_home}: {e}")
    finally:
        conn.close()
    ERROR_QUEUE.put(None)
    db_thread.join()
    logger.info(f"Parser finished in {time.time()-start_time:.1f}s - TOTAL {total_files} files tracked across fleet")
    print("Parser completed - check parse_agent_logs.log for full details")

if __name__ == "__main__":
    main()
