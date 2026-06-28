#!/usr/bin/env python3
import subprocess
import csv
import json
import os
import hashlib
import logging
import paramiko
import re
import time
import socket
import sys
import atexit
import oracledb
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, TimeoutError, as_completed
from paramiko import SSHClient, AutoAddPolicy, RSAKey, ECDSAKey, Transport
from paramiko.ssh_exception import SSHException, AuthenticationException
from scp import SCPClient
from urllib.parse import unquote
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict
from flask import flash
import ipaddress
from cryptography.fernet import Fernet
import pexpect
import secrets
import string
import bcrypt
from apscheduler.triggers.cron import CronTrigger
from maa_db_pool import (
    get_db_pool_connection as _central_pool_acquire,
    release_db_pool_connection as _central_pool_release,
    db_pool_context,
)
import config

logger = logging.getLogger(__name__)
agent_status = defaultdict(lambda: {"status": "unknown", "last_checked": None})
status_lock = threading.Lock()
monitoring_thread = None
stop_monitoring = threading.Event()

# ====================== GLOBAL SSH POOL FOR AGENT LOG PARSER (fixes import error) ======================
SSH_POOL = ThreadPoolExecutor(max_workers=80, thread_name_prefix="SSH_Parser")
SSH_POOL_LOCK = threading.Lock()
MAX_SSH_WORKERS = 80

def get_ssh_pool():
    """Return shared SSH pool (lazy + thread-safe)."""
    global SSH_POOL
    with SSH_POOL_LOCK:
        if SSH_POOL is None or not isinstance(SSH_POOL, ThreadPoolExecutor):
            SSH_POOL = ThreadPoolExecutor(max_workers=MAX_SSH_WORKERS, thread_name_prefix="SSH_Parser")
        return SSH_POOL

# === MAA AGENT LOG PARSER HELPERS (required by maa_agent_log_parser.core) ===
def normalize_error_message(msg: str) -> str:
    """Normalize for cross-host deduplication and fingerprinting (tuned on your CRSeOns/InventoryException samples)."""
    if not msg:
        return ""
    norm = msg
    patterns = [
        (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP]'),
        (re.compile(r'scaqal\d+adm\d+vm\d+\.us\.oracle\.com'), '[HOST]'),
        (re.compile(r'/u01/app/oracle/em/agent_vm\d+/[^ ]+'), '[AGENT_PATH]'),
        (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'), '[TS]'),
        (re.compile(r'subscriberId=\d+'), '[SUB_ID]'),
        (re.compile(r'TargetGuid=\w+'), '[GUID]'),
        (re.compile(r'(\d+) occurrences'), 'N occurrences'),
        (re.compile(r'\d+'), 'N'),
        (re.compile(r'https?://[^\s]+'), '[URL]'),
    ]
    for pat, repl in patterns:
        norm = pat.sub(repl, norm)
    return norm.strip()[:4000]

def classify_error_type(msg: str) -> str:
    """Classify based on your attached logs (CRSeOns, HTTP probes, InventoryException, etc.)."""
    lower = msg.lower()
    if 'crseons' in lower or 'ons' in lower and 'proxy' in lower:
        return 'CRSEONS_SUBSCRIPTION'
    if 'does not service request' in lower or 'http listener' in lower:
        return 'HTTP_PROBE'
    if 'inventoryexception' in lower or 'jaxb' in lower:
        return 'INVENTORY_PARSE'
    if 'heartbeat' in lower or 'upload' in lower and 'timeout' in lower:
        return 'HEARTBEAT_TIMEOUT'
    if 'ora-' in lower:
        return 'ORA_ERROR'
    return 'OTHER'

def compute_fingerprint(msg: str, error_type: str = None) -> str:
    """SHA256 fingerprint for same-root-cause grouping across the fleet."""
    norm = normalize_error_message(msg)
    et = error_type or classify_error_type(msg)
    combined = f"{norm}|{et}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def get_active_agents():
    """Return active EM agents (DB + guests only) as (hostname, agent_home) list."""
    try:
        conn = get_db_connection_standalone()
        targets = get_em_agent_targets(conn)
        conn.close()
        return [(t, "/u01/app/oracle/em/agent_vm04") for t in targets]
    except Exception as e:
        logger.error(f"Failed to get active agents: {e}")
        return []

key_file = config.ENCRYPTION_KEY_FILE
if os.path.exists(key_file):
    with open(key_file, 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(ENCRYPTION_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY)
SSH_KEY = "/home/maatest/.ssh/id_rsa"
DB_TIMEOUT = 30
SSH_TIMEOUT = 60
SSH_RETRIES = 1
SWITCH_WORKERS = 20
SYSTEM_WORKERS = 20
SFTP_SERVER = "scaqaa04celadm12.us.oracle.com"
SFTP_USER = "root"
SFTP_DIR = "/home/exports/"
csv.field_size_limit(1048576)
DNS_RETRIES = 2
DNS_RETRY_DELAY = 1
def encrypt_data(data):
    if data:
        try:
            encrypted = cipher_suite.encrypt(data.encode())
            logger.debug(f"Data encrypted successfully: {len(encrypted)} bytes")
            return encrypted
        except Exception as e:
            logger.error(f"Failed to encrypt data: {str(e)}")
            raise
    logger.warning("No data provided for encryption")
    return None
def decrypt_data(encrypted_data):
    if not encrypted_data:
        logger.warning("No encrypted data provided for decryption")
        return None
    try:
        if isinstance(encrypted_data, bytes):
            decrypted = cipher_suite.decrypt(encrypted_data).decode()
            logger.debug("Data decrypted successfully")
            return decrypted
        else:
            logger.error(f"Encrypted data is not in bytes format: {type(encrypted_data)}")
            return None
    except Exception as e:
        logger.error(f"Failed to decrypt data: {str(e)}")
        return None
def validate_cron_schedule(cron_schedule):
    """Validate a cron schedule string."""
    try:
        CronTrigger.from_crontab(cron_schedule, timezone='UTC')
        return True, ""
    except ValueError as e:
        return False, str(e)
def get_db_connection(username, password, dsn, timeout=None):
    try:
        connect_params = {
            "user": username,
            "password": password,
            "dsn": dsn
        }
        if timeout is not None:
            connect_params["tcp_connect_timeout"] = timeout
        logger.debug(f"Attempting to connect to database with username={username}, dsn={dsn}, timeout={timeout}")
        conn = oracledb.connect(**connect_params)
        logger.debug(f"Database connection established for user {username}")
        return conn
    except oracledb.Error as e:
        logger.error(f"Database connection failed: {e}, connect_params={connect_params}")
        raise
def acquire_pool_connection(pool=None):
    """Acquire a connection from the central pool, or a legacy pool object if passed."""
    try:
        if pool is not None:
            conn = pool.acquire()
        else:
            conn = _central_pool_acquire()
        logger.debug("Database pool connection acquired")
        return conn
    except oracledb.Error as e:
        logger.error(f"Database pool connection failed: {e}")
        raise


def release_pool_connection(conn, pool=None):
    """Release connection back to central or legacy pool."""
    if not conn:
        return
    try:
        if pool is not None:
            pool.release(conn)
        else:
            _central_pool_release(conn)
        logger.debug("Database pool connection released")
    except oracledb.Error as e:
        logger.error(f"Failed to release database pool connection: {e}")
        try:
            conn.close()
        except Exception:
            pass


# Backward-compatible aliases (prefer acquire_pool_connection / release_pool_connection)
get_db_pool_connection = acquire_pool_connection
release_db_connection = release_pool_connection
def get_confluence_page_content(space_key, page_title, confluence_url, headers):
    url = f"{confluence_url}/content?title={page_title}&spaceKey={space_key}&expand=body.storage"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Confluence page: {e}")
        return None
    data = response.json()
    if data["results"]:
        logger.info("Successfully fetched Confluence page content.")
        return data["results"][0]["body"]["storage"]["value"]
    else:
        logger.warning("Confluence page not found.")
        return None
def extract_confluence_table_data(html_content, table_index, status):
    soup = BeautifulSoup(html_content, "html.parser")
    tables = soup.find_all("table")
    if len(tables) <= table_index:
        logger.warning(f"Table at index {table_index} not found on the Confluence page.")
        return None, None
    target_table = tables[table_index]
    headers = [th.get_text(strip=True) for th in target_table.find_all("th")]
    logger.info(f"Headers for table {table_index} (status: {status}): {headers}")
    expected_columns = 9 if status == "In Progress" else 8
    if len(headers) != expected_columns:
        logger.error(f"Unexpected number of columns in table {table_index}. Expected {expected_columns}, but found {len(headers)}: {headers}")
        return None, None
    max_lengths = {0: 500, 1: 200, 2: 200, 3: 200, 4: 200, 5: 200, 6: 200, 7: 1000 if status == "In Progress" else 100, 8: 100 if status == "In Progress" else 100}
    rows = []
    for tr in target_table.find_all("tr")[1:]:
        cells = []
        for td in tr.find_all("td"):
            link = td.find("a")
            if link and link.get("href"):
                cell_content = str(link)
            else:
                cell_content = td.get_text(strip=True)
            max_len = max_lengths.get(len(cells), 1000)
            if isinstance(cell_content, str) and '<a' not in cell_content and len(cell_content) > max_len:
                logger.warning(f"Truncating value in column {len(cells)} from length {len(cell_content)} to {max_len}: {cell_content}")
                cell_content = cell_content[:max_len]
            cells.append(cell_content)
        if len(cells) > expected_columns:
            logger.warning(f"Row in table {table_index} has {len(cells)} columns, trimming to {expected_columns}: {cells}")
            cells = cells[:expected_columns]
        elif len(cells) < expected_columns:
            logger.warning(f"Row in table {table_index} has {len(cells)} columns, padding to {expected_columns}: {cells}")
            cells.extend([''] * (expected_columns - len(cells)))
        cells.append(status)
        logger.info(f"Row extracted for table {table_index} (status: {status}): {cells}")
        rows.append(cells)
    return headers, rows
def store_confluence_data_in_db(headers, in_progress_rows, completed_rows, pool):
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM MAAMD.CERTIFICATION_PROJECTS")
        logger.info("Cleared existing data from CERTIFICATION_PROJECTS table.")
        insert_query = "INSERT INTO MAAMD.CERTIFICATION_PROJECTS (CERTIFICATION_NAME, CERTIFICATION_TYPE, MAA_MANAGER, ENTERPRISE_MANAGER_13_5, ENTERPRISE_MANAGER_24_1, ASR, PLATINUM, NOTES, RELEASE_DATE, STATUS) VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10)"
        for row in in_progress_rows:
            cleaned_row = [BeautifulSoup(cell, "html.parser").get_text(strip=True) if '<a' in str(cell) else cell for cell in row]
            logger.debug(f"Inserting 'In Progress' row: {cleaned_row}")
            cursor.execute(insert_query, cleaned_row)
        logger.info(f"Inserted {len(in_progress_rows)} rows into CERTIFICATION_PROJECTS for 'In Progress' status.")
        for row in completed_rows:
            cleaned_row = [BeautifulSoup(cell, "html.parser").get_text(strip=True) if '<a' in str(cell) else cell for cell in row]
            padded_row = cleaned_row[:4] + [''] + cleaned_row[4:]
            logger.debug(f"Inserting 'Recently Completed' row (padded): {padded_row}")
            cursor.execute(insert_query, padded_row)
        logger.info(f"Inserted {len(completed_rows)} rows into CERTIFICATION_PROJECTS for 'Recently Completed' status.")
        conn.commit()
    except oracledb.Error as e:
        logger.error(f"Error storing Confluence data in database: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        release_db_connection(conn, pool)
def fetch_certification_projects(pool):
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT CERTIFICATION_NAME, CERTIFICATION_TYPE, MAA_MANAGER, ENTERPRISE_MANAGER_13_5, ENTERPRISE_MANAGER_24_1, ASR, PLATINUM, NOTES, RELEASE_DATE FROM MAAMD.CERTIFICATION_PROJECTS WHERE STATUS = 'In Progress' ORDER BY CERTIFICATION_NAME")
        in_progress_data = cursor.fetchall()
        in_progress_headers = ['Certification Name', 'Certification Type', 'MAA Manager', 'Enterprise Manager 13.5', 'Enterprise Manager 24.1', 'ASR', 'Platinum', 'Notes', 'Expected release date']
        cursor.execute("SELECT CERTIFICATION_NAME, CERTIFICATION_TYPE, MAA_MANAGER, ENTERPRISE_MANAGER_13_5, ENTERPRISE_MANAGER_24_1, ASR, PLATINUM, NOTES, RELEASE_DATE FROM MAAMD.CERTIFICATION_PROJECTS WHERE STATUS = 'Recently Completed' ORDER BY CERTIFICATION_NAME")
        completed_data = cursor.fetchall()
        completed_headers = ['Certification Name', 'Certification Type', 'MAA Manager', 'Enterprise Manager 13.5', 'Enterprise Manager 24.1', 'ASR', 'Platinum', 'Notes', 'Date released-cancelled']
        return (in_progress_headers, in_progress_data), (completed_headers, completed_data)
    except oracledb.Error as e:
        logger.error(f"Error fetching certification projects from database: {e}")
        return (['Error'], [['Unable to fetch data']]), (['Error'], [['Unable to fetch data']])
    finally:
        cursor.close()
        release_db_connection(conn, pool)
def get_agent_cpu_memory(ssh_client, pid, tm_pid, hostname):
    cpu_percent = None
    memory_mb = None
    try:
        if tm_pid:
            cmd = f"ps -p {tm_pid} -o %cpu,rss"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            output = stdout.read().decode().strip()
            lines = output.splitlines()
            if len(lines) > 1:
                try:
                    cpu, rss = lines[1].split()
                    cpu_percent = float(cpu)
                    memory_mb = round(float(rss) / 1024, 2) # Convert KB to MB
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse CPU/memory for TMMain PID {tm_pid} on {hostname}: {str(e)}")
        if not cpu_percent or not memory_mb:
            cmd = f"ps -p {pid} -o %cpu,rss"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            output = stdout.read().decode().strip()
            lines = output.splitlines()
            if len(lines) > 1:
                try:
                    cpu, rss = lines[1].split()
                    cpu_percent = float(cpu)
                    memory_mb = round(float(rss) / 1024, 2)
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse CPU/memory for PID {pid} on {hostname}: {str(e)}")
    except Exception as e:
        logger.error(f"Error collecting CPU/memory for PID {pid} on {hostname}: {str(e)}")
    return cpu_percent, memory_mb
def monitor_agent_status(agents, ssh_key_path, ssh_user, user_id, action, db_username, db_password, dsn):
    private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
    target_state = "stopped" if action == "shutdown" else "running"
    errors = []
    conn = get_db_connection(db_username, db_password, dsn)
    cursor = conn.cursor()
    try:
        all_complete = True
        for agent in agents:
            if agent.count(':') != 2:
                logger.error(f"Invalid agent format in monitor: {agent}, expected 'hostname:pid:agent_home'")
                errors.append(f"Monitoring failed for invalid agent: {agent}")
                continue
            try:
                hostname, pid, agent_home = agent.split(":")
                if not hostname or not pid or not agent_home:
                    logger.error(f"Empty component in agent: {agent}")
                    errors.append(f"Monitoring failed for invalid agent: {agent}. Components cannot be empty.")
                    continue
                int(pid) # Ensure pid is numeric
            except ValueError as e:
                logger.error(f"Failed to parse agent: {agent}, error: {str(e)}")
                errors.append(f"Monitoring failed for invalid agent: {agent}. PID must be numeric.")
                continue
            key = f"{hostname}:{agent_home}"
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh_client.connect(hostname, username=ssh_user, pkey=private_key, timeout=10)
                check_cmd = f"{agent_home}/bin/emctl status agent"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                status_output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()
                logger.debug(f"Monitor status for {key}: stdout={status_output}, stderr={error_output}")
                with status_lock:
                    if "Agent is Running and Ready" in status_output:
                        agent_status[key]["status"] = "running"
                    elif "Agent is Running but Not Ready" in status_output:
                        agent_status[key]["status"] = "running_not_ready"
                    elif "Agent is Not Running" in status_output:
                        agent_status[key]["status"] = "stopped"
                    else:
                        agent_status[key]["status"] = "unknown"
                    agent_status[key]["last_checked"] = datetime.now().isoformat()
                cursor.execute("UPDATE maamd.agent_home_info SET AGENT_STATUS = :1 WHERE hostname = :2 AND pid = :3 AND agent_home = :4", (agent_status[key]["status"], hostname, pid, agent_home))
                conn.commit()
                logger.info(f"Monitored {key} - Status: {agent_status[key]['status']} by {user_id}")
                if agent_status[key]["status"] != target_state and agent_status[key]["status"] != "running_not_ready":
                    all_complete = False
                    errors.append(f"Agent {key} is in state {agent_status[key]['status']}, expected {target_state}")
            except paramiko.SSHException as e:
                with status_lock:
                    agent_status[key]["status"] = f"error: {str(e)}"
                    agent_status[key]["last_checked"] = datetime.now().isoformat()
                cursor.execute("UPDATE maamd.agent_home_info SET AGENT_STATUS = :1 WHERE hostname = :2 AND pid = :3 AND agent_home = :4", (agent_status[key]["status"], hostname, pid, agent_home))
                conn.commit()
                logger.error(f"SSH error monitoring {key} by {user_id}: {str(e)}")
                errors.append(f"SSH error monitoring {key}: {str(e)}")
                all_complete = False
            finally:
                ssh_client.close()
        if all_complete:
            logger.info(f"All agents reached target state '{target_state}' for {action} by {user_id}")
            return True, f"All agents reached target state '{target_state}' for {action}"
        else:
            logger.warning(f"Not all agents reached target state '{target_state}' for {action} by {user_id}")
            return False, "; ".join(errors) if errors else f"Some agents did not reach target state '{target_state}'"
    except oracledb.Error as e:
        logger.error(f"Database error in monitor_agent_status by {user_id}: {e}")
        errors.append(f"Database error in monitor_agent_status: {str(e)}")
        conn.rollback()
        return False, "; ".join(errors)
    finally:
        cursor.close()
        conn.close()
def delete_agent(agent, conn, private_key, ssh_user, user_id):
    try:
        if agent.count(':') != 2:
            logger.error(f"Invalid agent format: {agent}, expected 'hostname:pid:agent_home'")
            return False, f"Invalid agent format: {agent}"
        hostname, pid, agent_home = agent.split(":")
        if not hostname or not pid or not agent_home:
            logger.error(f"Empty component in agent: {agent}")
            return False, f"Invalid agent: {agent}. Components cannot be empty."
        try:
            int(pid) # Ensure pid is numeric
        except ValueError:
            logger.error(f"Invalid pid in agent: {agent}")
            return False, f"Invalid agent: {agent}. PID must be numeric."
        logger.info(f"Attempting to delete agent on {hostname} (PID: {pid}, Home: {agent_home}) by {user_id}")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(hostname, username=ssh_user, pkey=private_key, timeout=15)
            logger.info(f"Connected to {hostname} for agent deletion by {user_id}")
            # Step 1: Stop the agent
            stop_cmd = f"nohup {agent_home}/bin/emctl stop agent > /tmp/emctl_stop_{pid}.log 2>&1 &"
            stdin, stdout, stderr = ssh_client.exec_command(stop_cmd)
            exit_status = stdout.channel.recv_exit_status()
            error_output = stderr.read().decode().strip()
            stdout_output = stdout.read().decode().strip()
            logger.debug(f"Stop agent on {hostname}: stdout={stdout_output}, stderr={error_output}, exit_status={exit_status}")
            # Poll agent status to confirm stopped (up to 60 seconds)
            start_time = time.time()
            while time.time() - start_time < 60:
                check_cmd = f"{agent_home}/bin/emctl status agent"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                status_output = stdout.read().decode().strip()
                status_error = stderr.read().decode().strip()
                logger.debug(f"Status check on {hostname}: stdout={status_output}, stderr={status_error}")
                if "Agent is Not Running" in status_output:
                    logger.info(f"Agent stopped successfully on {hostname} (PID: {pid})")
                    break
                elif "Agent is Running" in status_output:
                    logger.debug(f"Agent still running on {hostname} (PID: {pid}), continuing to poll")
                else:
                    logger.warning(f"Unexpected status output on {hostname} (PID: {pid}): {status_output}")
                time.sleep(5)
            else:
                logger.error(f"Failed to stop agent on {hostname} (PID: {pid}): status_output={status_output}")
                return False, f"Failed to stop agent on {hostname} (PID: {pid}): Timeout after 60 seconds"
            # Step 2: Deinstall the agent using AgentDeinstall.pl
            deinstall_cmd = f"{agent_home}/perl/bin/perl {agent_home}/sysman/install/AgentDeinstall.pl -agentHome {agent_home}"
            stdin, stdout, stderr = ssh_client.exec_command(deinstall_cmd)
            exit_status = stdout.channel.recv_exit_status()
            error_output = stderr.read().decode().strip()
            stdout_output = stdout.read().decode().strip()
            logger.debug(f"Deinstall agent on {hostname}: stdout={stdout_output}, stderr={error_output}, exit_status={exit_status}")
            if exit_status != 0:
                logger.error(f"Agent deinstallation failed on {hostname} (PID: {pid}): {error_output}")
                return False, f"Failed to deinstall agent on {hostname} (PID: {pid}): {error_output}"
            logger.info(f"Agent deinstallation executed on {hostname} (PID: {pid})")
            # Step 3: Verify agent home directory is removed
            check_cmd = f"[ -d {agent_home} ] && echo 'exists' || echo 'not found'"
            stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
            dir_exists = stdout.read().decode().strip() == 'exists'
            if dir_exists:
                logger.error(f"Agent home {agent_home} still exists on {hostname} after deinstallation")
                return False, f"Failed to deinstall agent on {hostname} (PID: {pid}): Agent home directory still exists"
            logger.info(f"Verified agent home {agent_home} removed on {hostname}")
            # Step 4: Manually remove agent base directory if residuals remain
            agent_base_dir = os.path.dirname(agent_home)
            if not agent_base_dir.startswith('/u01/app/oracle') or len(agent_base_dir) < 20:
                logger.warning(f"Agent base directory {agent_base_dir} on {hostname} looks unsafe to delete, skipping")
            else:
                check_cmd = f"[ -d {agent_base_dir} ] && echo 'exists' || echo 'not found'"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                dir_exists = stdout.read().decode().strip() == 'exists'
                if dir_exists:
                    remove_cmd = f"rm -rf {agent_base_dir}"
                    stdin, stdout, stderr = ssh_client.exec_command(remove_cmd)
                    exit_status = stdout.channel.recv_exit_status()
                    error_output = stderr.read().decode().strip()
                    stdout_output = stdout.read().decode().strip()
                    logger.debug(f"Remove agent base dir on {hostname}: stdout={stdout_output}, stderr={error_output}, exit_status={exit_status}")
                    if exit_status != 0:
                        logger.warning(f"Failed to remove agent base directory {agent_base_dir} on {hostname}: {error_output}")
                    else:
                        logger.info(f"Removed agent base directory {agent_base_dir} on {hostname}")
            # Step 5: Delete from database (only after verification)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "DELETE FROM maamd.agent_home_info WHERE hostname = :1 AND pid = :2 AND agent_home = :3",
                    (hostname, pid, agent_home)
                )
                if cursor.rowcount == 0:
                    logger.warning(f"No database entry found for agent on {hostname} (PID: {pid}, Home: {agent_home})")
                conn.commit()
                logger.info(f"Deleted database entry for agent on {hostname} (PID: {pid}, Home: {agent_home})")
            finally:
                cursor.close()
            # Step 6: Clean up temporary files
            cleanup_cmd = f"rm -f /tmp/emctl_start_{pid}.log /tmp/emctl_stop_{pid}.log"
            stdin, stdout, stderr = ssh_client.exec_command(cleanup_cmd)
            logger.debug(f"Cleaned up temporary files on {hostname}: {cleanup_cmd}")
            return True, f"Successfully deleted and deinstalled agent on {hostname} (PID: {pid}, Home: {agent_home})"
        except (paramiko.SSHException, TimeoutError) as e:
            logger.error(f"SSH error deleting agent on {hostname}: {str(e)}")
            return False, f"Failed to delete agent on {hostname} (PID: {pid}): {str(e)}"
        finally:
            ssh_client.close()
    except ValueError as e:
        logger.error(f"Invalid agent format: {agent}, error: {str(e)}")
        return False, f"Invalid agent format: {agent}"
    except oracledb.Error as e:
        logger.error(f"Database error deleting agent on {hostname}: {str(e)}")
        return False, f"Failed to delete agent on {hostname} (PID: {pid}): Database error: {str(e)}"
def shutdown_agent(agent, private_key, ssh_user, user_id):
    try:
        if agent.count(':') != 2:
            logger.error(f"Invalid agent format: {agent}, expected 'hostname:pid:agent_home'")
            return False, f"Invalid agent format: {agent}"
        hostname, pid, agent_home = agent.split(":")
        if not hostname or not pid or not agent_home:
            logger.error(f"Empty component in agent: {agent}")
            return False, f"Invalid agent: {agent}. Components cannot be empty."
        try:
            pid = int(pid) # Ensure pid is numeric
        except ValueError:
            logger.error(f"Invalid pid in agent: {agent}")
            return False, f"Invalid agent: {agent}. PID must be numeric."
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(hostname, username=ssh_user, pkey=private_key, timeout=10)
            logger.info(f"Connected to {hostname} for agent shutdown by {user_id}")
            # Run stop command in background
            stop_cmd = f"nohup {agent_home}/bin/emctl stop agent > /tmp/emctl_stop_{pid}.log 2>&1 &"
            stdin, stdout, stderr = ssh_client.exec_command(stop_cmd)
            exit_status = stdout.channel.recv_exit_status()
            error_output = stderr.read().decode().strip()
            stdout_output = stdout.read().decode().strip()
            logger.debug(f"Shutdown agent on {hostname}: stdout={stdout_output}, stderr={error_output}, exit_status={exit_status}")
            # Poll agent status for up to 60 seconds
            start_time = time.time()
            while time.time() - start_time < 60:
                check_cmd = f"{agent_home}/bin/emctl status agent"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                status_output = stdout.read().decode().strip()
                status_error = stderr.read().decode().strip()
                logger.debug(f"Status check on {hostname}: stdout={status_output}, stderr={status_error}")
                if "Agent is Not Running" in status_output:
                    logger.info(f"Agent stopped successfully on {hostname} (PID: {pid}, Home: {agent_home}) by {user_id}")
                    return True, f"Agent stopped successfully on {hostname} (PID: {pid})"
                elif "Agent is Running" in status_output:
                    logger.debug(f"Agent still running on {hostname} (PID: {pid}), continuing to poll")
                else:
                    logger.warning(f"Unexpected status output on {hostname} (PID: {pid}): {status_output}")
                time.sleep(5) # Wait 5 seconds before next check
            # Timeout reached
            check_cmd = f"{agent_home}/bin/emctl status agent"
            stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
            status_output = stdout.read().decode().strip()
            status_error = stderr.read().decode().strip()
            logger.error(f"Agent shutdown timed out on {hostname} (PID: {pid}): status_output={status_output}")
            return False, f"Shutdown failed on {hostname} (PID: {pid}): Operation timed out after 60 seconds"
        except paramiko.SSHException as e:
            logger.error(f"SSH error shutting down agent on {hostname} (PID: {pid}) by {user_id}: {str(e)}")
            return False, f"SSH error shutting down agent on {hostname} (PID: {pid}): {str(e)}"
        finally:
            ssh_client.close()
    except ValueError as e:
        logger.error(f"Invalid agent format: {agent}, error: {str(e)}")
        return False, f"Invalid agent format: {agent}"
def startup_agent(agent, private_key, ssh_user, user_id):
    try:
        if agent.count(':') != 2:
            logger.error(f"Invalid agent format: {agent}, expected 'hostname:pid:agent_home'")
            return False, f"Invalid agent format: {agent}"
        hostname, pid, agent_home = agent.split(":")
        if not hostname or not pid or not agent_home:
            logger.error(f"Empty component in agent: {agent}")
            return False, f"Invalid agent: {agent}. Components cannot be empty."
        try:
            pid = int(pid) # Ensure pid is numeric
        except ValueError:
            logger.error(f"Invalid pid in agent: {agent}")
            return False, f"Invalid agent: {agent}. PID must be numeric."
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(hostname, username=ssh_user, pkey=private_key, timeout=10)
            logger.info(f"Connected to {hostname} for agent startup by {user_id}")
            # Run start command in background
            start_cmd = f"nohup {agent_home}/bin/emctl start agent > /tmp/emctl_start_{pid}.log 2>&1 &"
            stdin, stdout, stderr = ssh_client.exec_command(start_cmd)
            exit_status = stdout.channel.recv_exit_status()
            error_output = stderr.read().decode().strip()
            stdout_output = stdout.read().decode().strip()
            logger.debug(f"Start agent on {hostname}: stdout={stdout_output}, stderr={error_output}, exit_status={exit_status}")
            # Poll agent status for up to 60 seconds
            start_time = time.time()
            while time.time() - start_time < 60:
                check_cmd = f"{agent_home}/bin/emctl status agent"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                status_output = stdout.read().decode().strip()
                status_error = stderr.read().decode().strip()
                logger.debug(f"Status check on {hostname}: stdout={status_output}, stderr={status_error}")
                if "Agent is Running and Ready" in status_output or "Agent is Running but Not Ready" in status_output:
                    logger.info(f"Agent started successfully on {hostname} (PID: {pid}, Home: {agent_home}) by {user_id}")
                    return True, f"Agent started successfully on {hostname} (PID: {pid})"
                elif "Agent is Not Running" in status_output:
                    logger.debug(f"Agent not yet running on {hostname} (PID: {pid}), continuing to poll")
                else:
                    logger.warning(f"Unexpected status output on {hostname} (PID: {pid}): {status_output}")
                time.sleep(5) # Wait 5 seconds before next check
            # Timeout reached
            check_cmd = f"{agent_home}/bin/emctl status agent"
            stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
            status_output = stdout.read().decode().strip()
            status_error = stderr.read().decode().strip()
            logger.error(f"Agent startup timed out on {hostname} (PID: {pid}): status_output={status_output}")
            return False, f"Startup failed on {hostname} (PID: {pid}): Operation timed out after 60 seconds"
        except paramiko.SSHException as e:
            logger.error(f"SSH error starting agent on {hostname} (PID: {pid}) by {user_id}: {str(e)}")
            return False, f"SSH error starting agent on {hostname} (PID: {pid}): {str(e)}"
        finally:
            ssh_client.close()
    except ValueError as e:
        logger.error(f"Invalid agent format: {agent}, error: {str(e)}")
        return False, f"Invalid agent format: {agent}"
def refresh_agent_status(agent, private_key, ssh_user, user_id, conn):
    try:
        if agent.count(':') != 2:
            logger.error(f"Invalid agent format: {agent}, expected 'hostname:pid:agent_home'")
            return False, f"Invalid agent format: {agent}"
        hostname, pid, agent_home = agent.split(":")
        if not hostname or not pid or not agent_home:
            logger.error(f"Empty component in agent: {agent}")
            return False, f"Invalid agent: {agent}. Components cannot be empty."
        try:
            int(pid) # Ensure pid is numeric
        except ValueError:
            logger.error(f"Invalid pid in agent: {agent}")
            return False, f"Invalid agent: {agent}. PID must be numeric."
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(hostname, username=ssh_user, pkey=private_key, timeout=15)
            logger.info(f"Connected to {hostname} for status refresh by {user_id}")
            # Check agent status
            check_cmd = f"{agent_home}/bin/emctl status agent"
            stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
            status_output = stdout.read().decode().strip()
            error_output = stderr.read().decode().strip()
            logger.debug(f"Refresh status on {hostname}: stdout={status_output}, stderr={error_output}")
            if error_output:
                logger.error(f"Error running emctl status agent on {hostname} (PID: {pid}): {error_output}")
                raise paramiko.SSHException(f"emctl status agent failed: {error_output}")
            initial_status = "unknown" # Default value
            if "Agent is Running and Ready" in status_output:
                initial_status = "running"
            elif "Agent is Running but Not Ready" in status_output:
                initial_status = "running_not_ready"
            elif "Agent is Not Running" in status_output:
                initial_status = "stopped"
            logger.info(f"Agent status for {hostname} (PID: {pid}): {initial_status}, output: {status_output}")
            # Find TMMain PID if running
            tm_pid = None
            if initial_status in ["running", "running_not_ready"]:
                for line in status_output.splitlines():
                    if "TMMain" in line:
                        try:
                            tm_pid = line.split()[0]
                            logger.info(f"Found TMMain PID {tm_pid} for agent on {hostname} (PID: {pid})")
                            break
                        except IndexError:
                            logger.warning(f"Could not parse TMMain PID from line: {line}")
            # Collect CPU and memory usage
            cpu_percent, memory_mb = get_agent_cpu_memory(ssh_client, pid, tm_pid, hostname)
            # Update database
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    UPDATE maamd.agent_home_info
                    SET AGENT_STATUS = :1, CPU_USAGE_PERCENT = :2, MEMORY_USAGE_MB = :3
                    WHERE hostname = :4 AND pid = :5 AND agent_home = :6
                    """,
                    (initial_status, cpu_percent, memory_mb, hostname, pid, agent_home)
                )
                if cursor.rowcount == 0:
                    logger.warning(f"No rows updated for agent on {hostname} (PID: {pid}, agent_home: {agent_home})")
                conn.commit()
                logger.info(f"Updated AGENT_STATUS={initial_status}, CPU_USAGE_PERCENT={cpu_percent}, MEMORY_USAGE_MB={memory_mb} for agent on {hostname} (PID: {pid})")
            finally:
                cursor.close()
            return True, f"Status refreshed for agent on {hostname} (PID: {pid}, Status: {initial_status}, CPU: {cpu_percent or 'N/A'}%, Memory: {memory_mb or 'N/A'} MB)"
        except (paramiko.SSHException, TimeoutError) as e:
            logger.error(f"SSH error refreshing status on {hostname}: {str(e)}")
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    UPDATE maamd.agent_home_info
                    SET AGENT_STATUS = :1, CPU_USAGE_PERCENT = NULL, MEMORY_USAGE_MB = NULL
                    WHERE hostname = :2 AND pid = :3 AND agent_home = :4
                    """,
                    (f"error: {str(e)}", hostname, pid, agent_home)
                )
                if cursor.rowcount == 0:
                    logger.warning(f"No rows updated for agent on {hostname} (PID: {pid}, agent_home: {agent_home})")
                conn.commit()
                logger.info(f"Updated AGENT_STATUS=error:{str(e)}, CPU_USAGE_PERCENT=NULL, MEMORY_USAGE_MB=NULL for agent on {hostname} (PID: {pid})")
            finally:
                cursor.close()
            return False, f"Failed to refresh status on {hostname} (PID: {pid}): {str(e)}"
        finally:
            ssh_client.close()
    except ValueError as e:
        logger.error(f"Invalid agent format: {agent}, error: {str(e)}")
        return False, f"Invalid agent format: {agent}"
def is_valid_fqdn(hostname):
    if not hostname or not isinstance(hostname, str):
        return False
    if hostname.lower() == "default":
        return True
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return (re.match(pattern, hostname) and ".." not in hostname and not hostname.startswith(('-', '.')) and not hostname.endswith(('-', '.')))
def classify_host(hostname):
    if '-c' in hostname or '-ilom' in hostname:
        return 'ilom'
    if 'vm' in hostname or 'client' in hostname:
        return 'vm'
    if 'adm' in hostname and 'celadm' not in hostname:
        return 'database_server'
    if 'celadm' in hostname:
        return 'storage_server'
    return 'unknown'
def fetch_host_details(cursor, hostname):
    cursor.execute("SELECT hostname, ilom_ip FROM MAAMD.ilom_hosts WHERE LOWER(hostname) = LOWER(:1)", (hostname,))
    host = cursor.fetchone()
    if not host:
        return None, None, None
    cursor.execute("SELECT s.alert_id, s.version, s.destination_ip, s.community_string, s.username, s.status, s.port FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1)", (hostname,))
    alerts = cursor.fetchall()
    logger.info(f"Fetched {len(alerts)} SNMP alerts for host {hostname}: {alerts}")
    users = cursor.execute("SELECT u.username, u.authentication_protocol, u.access_level FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)).fetchall()
    logger.info(f"Fetched {len(users)} SNMP users for host {hostname}: {users}")
    available_users = [str(row[0]) for row in cursor.execute("SELECT DISTINCT u.username FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)).fetchall() if row[0] is not None] or ['No users available']
    logger.info(f"Available users for host {hostname}: {available_users}")
    user_data = {'users': users, 'available_users': available_users}
    return host, alerts, user_data
def get_credential(cursor, component_type, component_name, username, credential_type='password'):
    column = 'ENCRYPTED_PASSWORD' if credential_type == 'password' else 'ENCRYPTED_KEY'
    query = f"SELECT {column} FROM MAAMD.ACCESS_CREDENTIALS WHERE COMPONENT_TYPE = :1 AND COMPONENT_NAME = :2 AND USERNAME = :3"
    try:
        cursor.execute(query, (component_type, component_name, username))
        result = cursor.fetchone()
        if result and result[0]:
            lob_data = result[0].read()
            logger.debug(f"Raw {credential_type} data for {component_type}:{component_name}:{username}: {lob_data.hex()}")
            decrypted = decrypt_data(lob_data)
            if decrypted:
                logger.info(f"Retrieved and decrypted {credential_type} for {component_type}:{component_name}:{username}")
                return decrypted
            else:
                logger.warning(f"Failed to decrypt {credential_type} for {component_type}:{component_name}:{username}")
                return None
        else:
            logger.warning(f"No {credential_type} found for {component_type}:{component_name}:{username}")
            return None
    except oracledb.Error as e:
        logger.error(f"Database error retrieving {credential_type} for {component_type}:{component_name}:{username}: {e}")
        raise
def fetch_access_credentials(cursor):
    query = "SELECT COMPONENT_TYPE, COMPONENT_NAME, USERNAME FROM MAAMD.ACCESS_CREDENTIALS ORDER BY COMPONENT_TYPE, COMPONENT_NAME, USERNAME"
    try:
        cursor.execute(query)
        credentials = cursor.fetchall()
        logger.info(f"Fetched {len(credentials)} access credentials")
        return credentials
    except oracledb.Error as e:
        logger.error(f"Error fetching access credentials: {e}")
        raise
def get_components(cursor):
    try:
        cursor.execute("SELECT 'PHYSICAL_HOST' AS component_type, SYSTEM_NAME AS component_name FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME LIKE '%adm%' UNION SELECT 'SWITCH' AS component_type, SYSTEM_NAME AS component_name FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME LIKE '%switch%' UNION SELECT 'GUEST' AS component_type, SYSTEM_NAME AS component_name FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME LIKE '%vm%' OR SYSTEM_NAME LIKE '%client%' UNION SELECT 'ILOM' AS component_type, ILOM_NAME AS component_name FROM MAAMD.SYSTEM_ALLOCATIONS WHERE ILOM_NAME IS NOT NULL ORDER BY component_type, component_name")
        components = cursor.fetchall()
        logger.info(f"Fetched {len(components)} components for Access Management")
        return components
    except oracledb.Error as e:
        logger.error(f"Error fetching components: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error fetching components: {e}")
        return []
def add_credential(cursor, component_type, component_name, username, password, key, created_by):
    encrypted_password = encrypt_data(password) if password else None
    encrypted_key = encrypt_data(key) if key else None
    created_date = datetime.now()
    try:
        query = "INSERT INTO MAAMD.ACCESS_CREDENTIALS (COMPONENT_TYPE, COMPONENT_NAME, USERNAME, ENCRYPTED_PASSWORD, ENCRYPTED_KEY, CREATED_BY, CREATED_DATE) VALUES (:1, :2, :3, :4, :5, :6, :7)"
        cursor.execute(query, (component_type, component_name, username, encrypted_password, encrypted_key, created_by, created_date))
        logger.info(f"Added credential for {component_type}:{component_name}:{username} by {created_by}")
    except oracledb.Error as e:
        logger.error(f"Error adding credential for {component_type}:{component_name}:{username}: {e}")
        raise
def fetch_all_credentials(conn):
    credentials = {}
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COMPONENT_TYPE, COMPONENT_NAME, USERNAME, ENCRYPTED_PASSWORD FROM MAAMD.ACCESS_CREDENTIALS")
        for row in cursor.fetchall():
            component_type, component_name, username, encrypted_password = row
            key = (component_type, component_name, username)
            if encrypted_password:
                decrypted = decrypt_data(encrypted_password.read())
                if decrypted:
                    credentials[key] = decrypted
                else:
                    logger.warning(f"Failed to decrypt password for {key}")
            else:
                logger.info(f"No password for {key}")
    except oracledb.Error as e:
        logger.error(f"Error fetching credentials: {e}")
    finally:
        cursor.close()
    return credentials
def execute_ssh_command(ssh, command, interactive=False, heredoc=None, timeout=30):
    try:
        if heredoc:
            command = f"{command} << 'EOF'\n{heredoc}\nEOF"
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        if interactive and not heredoc:
            stdin.write("y\n")
            stdin.flush()
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        logger.info(f"SSH command executed: {command}, Output: {output}, Error: {error}, Exit Status: {exit_status}")
        return output
    except Exception as e:
        logger.error(f"Failed to execute SSH command: {command}, Error: {str(e)}")
        raise
def set_alert_v2c(ssh, alert_id, destination_ip, port, community_string, status):
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} type=snmptrap")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} snmp_version=2c")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} destination={destination_ip}")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} destination_port={port}")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} community_or_username={community_string}")
    level = 'disable' if status == 'disable' else status
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} level={level}")
def set_alert_v3(ssh, alert_id, destination_ip, port, username, status):
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} type=snmptrap")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} snmp_version=3")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} destination={destination_ip}")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} destination_port={port}")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} community_or_username={username}")
    level = 'disable' if status == 'disable' else status
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} level={level}")
def reset_alert_to_default(ssh, alert_id):
    check_cmd = f"show /SP/alertmgmt/rules/{alert_id}"
    try:
        output = execute_ssh_command(ssh, check_cmd)
        logger.info(f"Rule {alert_id} current state: {output}")
        if "level = disable" in output and "destination = 0.0.0.0" in output and "destination_port = 0" in output:
            logger.info(f"Rule {alert_id} is already in the desired state, skipping reset.")
            return
    except Exception as e:
        logger.error(f"Failed to check rule {alert_id}: {str(e)}")
        raise Exception(f"Rule {alert_id} does not exist or cannot be accessed: {str(e)}")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} level=disable")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} type=snmptrap")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} snmp_version=2c")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} destination=0.0.0.0")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} destination_port=0")
    execute_ssh_command(ssh, f"set /SP/alertmgmt/rules/{alert_id} community_or_username=public")
def create_snmp_user(ssh, username, authentication_protocol, privacy_protocol, access_level, authentication_password, privacy_password):
    command = f"create /SP/services/snmp/users/{username} authentication_protocol={authentication_protocol} privacy_protocol={privacy_protocol} access_level={access_level} authentication_password={authentication_password} privacy_password={privacy_password}"
    execute_ssh_command(ssh, command, interactive=True)
def get_slot_counts(ssh, hostname):
    stdin, stdout, stderr = ssh.exec_command("show /SP/services/snmp/users")
    output = stdout.read().decode()
    user_count = len([line for line in output.splitlines() if line.strip().startswith("user")])
    users_full = user_count >= 10
    stdin, stdout, stderr = ssh.exec_command("show /SP/alertmgmt/rules")
    output = stdout.read().decode()
    alert_count = len([line for line in output.splitlines() if line.strip().startswith("rule")])
    alerts_full = alert_count >= 15
    return {'alerts_full': alerts_full, 'users_full': users_full}
def parse_csv(csv_file, conn):
    allocations = []
    guests_data = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        logger.info(f"CSV headers: {reader.fieldnames}")
        if 'COMPONENT' not in reader.fieldnames:
            logger.error("CSV does not contain 'COMPONENT' header")
            raise KeyError("CSV does not contain 'COMPONENT' header")
        reachable = check_hosts_reachability([row['COMPONENT'] for row in rows])
        logger.info(f"Filtered {sum(1 for r in reachable.values() if not r)} unreachable systems out of {len(rows)} total systems")
        reachable_rows = [row for row in rows if reachable.get(row['COMPONENT'], False)]
        hypervisor_map = {}
        for row in reachable_rows:
            try:
                hypervisor_map[row['COMPONENT']] = is_hypervisor(row['COMPONENT'], conn)
            except Exception as e:
                logger.error(f"Failed to check if {row['COMPONENT']} is hypervisor: {e}")
                hypervisor_map[row['COMPONENT']] = False
        with ProcessPoolExecutor(max_workers=SYSTEM_WORKERS) as executor:
            futures = [executor.submit(process_system, row, hypervisor_map, conn) for row in reachable_rows]
            for future in as_completed(futures):
                try:
                    allocation, guests = future.result()
                    if allocation:
                        allocations.append(allocation)
                    guests_data.extend(guests)
                except Exception as e:
                    logger.error(f"Error processing system: {e}")
    return allocations, guests_data
def fix_json_start(json_str):
    json_str = json_str.strip()
    if json_str.startswith("{'current'") and not json_str.startswith("{'current':"):
        json_str = json_str.replace("{'current'", "{'current':", 1)
    json_str = re.sub(r'(\{\s*"\w+?")\s*([\{\[\w"])', r'\1:\2', json_str)
    return json_str
def clean_for_json(json_str):
    json_str = json_str.strip('"').strip("'")
    if json_str.startswith('"""') and json_str.endswith('"""'):
        json_str = json_str[3:-3]
    json_str = json_str.replace('""Terry\'s ARK""', '"Terry\'s ARK"')
    json_str = json_str.replace('None', 'null').replace('True', 'true').replace('False', 'false')
    json_str = re.sub(r"(\{|\,)\s*'([^']+?)'\s*:", r'\1 "\2":', json_str)
    json_str = re.sub(r":\s*'([^'\\]*(?:\\.[^'\\]*)*)'", r': "\1"', json_str)
    json_str = re.sub(r'"\b(\d+)\b"', r'\1', json_str)
    json_str = re.sub(r',\s*([\]\}])', r'\1', json_str)
    json_str = re.sub(r'\\(["\'])', r'\1', json_str)
    return json_str
def expand_host_range(system_name, component, domain=".us.oracle.com"):
    hosts = []
    ranges = system_name.split(',')
    component_base = component.split('.')[0]
    component_domain = '.'.join(component.split('.')[1:]) if '.' in component else 'us.oracle.com'
    component_prefix = re.sub(r'(adm|celadm|vm|dv)\d*$', '', component_base, flags=re.IGNORECASE)
    if not component_prefix:
        logger.warning(f"No valid prefix extracted from component {component}, using system_name")
        component_prefix = re.sub(r'(adm|celadm|vm|dv)\d*$', '', system_name.split('.')[0], flags=re.IGNORECASE)
        if not component_prefix:
            component_prefix = system_name.split('.')[0]
    for rng in ranges:
        match = re.match(r'^(?:[a-z0-9]+)?(?:adm|celadm|vm|dv)(\d+)-(\d+)$', rng, re.IGNORECASE)
        if match:
            type_suffix = re.search(r'(adm|celadm|vm|dv)', rng, re.IGNORECASE).group(1).lower()
            start_str, end_str = match.groups()
            try:
                start = int(start_str)
                end = int(end_str)
                for i in range(start, end + 1):
                    host = f"{component_prefix}{type_suffix}{str(i).zfill(2)}.{component_domain}"
                    hosts.append(host)
            except ValueError:
                logger.warning(f"Invalid range format in {rng}, treating as single host")
                host = f"{component_prefix}{rng}.{component_domain}" if not rng.endswith(component_domain) else rng
                hosts.append(host)
        else:
            if 'adm' in rng.lower() or 'celadm' in rng.lower() or 'vm' in rng.lower() or 'dv' in rng.lower():
                host = rng if '.' in rng else f"{rng}.{component_domain}"
                hosts.append(host)
            else:
                host = component if '.' in component else f"{component}.{component_domain}"
                hosts.append(host)
    return sorted(list(set(hosts)))
def is_fqdn_resolvable(fqdn, conn=None, retries=DNS_RETRIES, delay=DNS_RETRY_DELAY):
    logger.debug(f"Attempting to resolve FQDN {fqdn}")
    for attempt in range(retries):
        try:
            ip = socket.gethostbyname(fqdn)
            logger.debug(f"FQDN {fqdn} resolved to {ip} on attempt {attempt + 1}/{retries}")
            return True
        except socket.gaierror as e:
            logger.debug(f"FQDN {fqdn} resolution failed on attempt {attempt + 1}/{retries}: {str(e)}")
            if attempt + 1 < retries:
                time.sleep(delay)
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME = :fqdn OR ILOM_NAME = :fqdn",
                {'fqdn': fqdn}
            )
            result = cursor.fetchone() is not None
            logger.debug(f"FQDN {fqdn} {'found' if result else 'not found'} in SYSTEM_ALLOCATIONS")
            return result
        except oracledb.Error as e:
            logger.error(f"Database check for FQDN {fqdn} failed: {str(e)}")
        finally:
            cursor.close()
    logger.warning(f"FQDN {fqdn} could not be resolved after {retries} attempts")
    return False
def search_vm_indicators(data, vm_patterns, fields_checked=None):
    if fields_checked is None:
        fields_checked = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                search_vm_indicators(value, vm_patterns, fields_checked)
            elif isinstance(value, str):
                fields_checked.append(f"{key}: {value[:50]}...")
                for pat in vm_patterns:
                    if pat.search(value.lower()):
                        return True, fields_checked
    elif isinstance(data, list):
        for item in data:
            found, fields_checked = search_vm_indicators(item, vm_patterns, fields_checked)
            if found:
                return True, fields_checked
    return False, fields_checked
def parse_csv_local(csv_file, conn):
    logger.info("Starting CSV parsing")
    allocations = []
    csv_guests_data = []
    failed_rows = []
    processed_hosts = set()
    vm_check_failures = []
    invalid_rack_names = []
    potential_vm_rows = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            logger.debug(f"CSV headers: {reader.fieldnames}")
            if 'COMPONENT' not in reader.fieldnames:
                logger.error("CSV file missing required COMPONENT column")
                raise ValueError("CSV file missing required COMPONENT column")
            allocations_key = 'ALLOCATIONS' if 'ALLOCATIONS' in reader.fieldnames else 'MY_ALLOCATION' if 'MY_ALLOCATION' in reader.fieldnames else None
            for row_index, row in enumerate(reader, start=1):
                component = row.get('HOSTNAME', row.get('SYSTEM_NAME', row.get('COMPONENT', ''))).strip()
                allocations_json = row.get(allocations_key, '') if allocations_key else ''
                role = row.get('ROLE', '').strip()
                rack_id = row.get('RACK_ID', '').strip()
                model = row.get('MODEL', '').strip()
                if not component or not allocations_json:
                    logger.debug(f"Skipping empty component or allocation in row {row_index}: {row}")
                    failed_rows.append((row_index, component, "Empty component or allocation"))
                    continue
                try:
                    system_hosts = expand_host_range(component, component)
                    if not system_hosts:
                        logger.warning(f"No valid hosts derived for component {component} in row {row_index}")
                        failed_rows.append((row_index, component, "No valid hosts derived"))
                        continue
                    system_name = system_hosts[0]
                    if system_name in processed_hosts:
                        logger.debug(f"Skipping duplicate system {system_name} in row {row_index}")
                        continue
                    processed_hosts.add(system_name)
                    cleaned_json = clean_for_json(fix_json_start(allocations_json))
                    allocation_data = json.loads(cleaned_json)
                    current = allocation_data.get('current', [{}])[0]
                    rack_name = derive_rack_name(system_name)
                    if not re.match(r'^[a-z0-9-]{1,20}$', rack_name) or rack_name.lower().endswith('sw'):
                        logger.debug(f"Invalid rack name derived for {system_name}: {rack_name}")
                        invalid_rack_names.append((row_index, system_name, rack_name))
                        rack_name = 'unknown'
                    ilom_name = derive_ilom_name(system_name)
                    allocation = (
                        system_name,
                        current.get('description', 'Unknown'),
                        current.get('start_date', ''),
                        current.get('end_date', ''),
                        current.get('allocator', {}).get('username', 'Unknown'),
                        None,
                        datetime.now(),
                        rack_name,
                        ilom_name,
                        None,
                        current.get('allocation_type', {}).get('label', 'Unknown'),
                        ', '.join(user.get('username', '') for user in current.get('allocatees', {}).get('users', []))[:500],
                        None,
                        None,
                        current.get('notes', None)
                    )
                    allocations.append(allocation)
                    vm_patterns = [re.compile(p) for p in [r'\bvm\b', r'\bclient\b', r'\bdv\b']]
                    is_vm, fields_checked = search_vm_indicators(allocation_data, vm_patterns)
                    if is_vm or 'vm' in system_name.lower() or 'client' in system_name.lower():
                        hypervisor = derive_hypervisor_name(system_name)
                        if hypervisor and is_fqdn_resolvable(hypervisor, conn):
                            csv_guests_data.append((system_name, hypervisor))
                            logger.debug(f"Identified guest {system_name} with hypervisor {hypervisor} in row {row_index}")
                        else:
                            logger.debug(f"Potential VM {system_name} in row {row_index}, but hypervisor {hypervisor} not resolvable")
                            potential_vm_rows.append((row_index, system_name, fields_checked))
                    logger.debug(f"Processed row {row_index} for system {system_name}")
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parsing failed for row {row_index}, component {component}: {e}")
                    failed_rows.append((row_index, component, f"JSON parsing error: {e}"))
                except Exception as e:
                    logger.error(f"Error processing row {row_index}, component {component}: {e}")
                    failed_rows.append((row_index, component, f"Processing error: {e}"))
        if failed_rows:
            logger.warning(f"Failed to process {len(failed_rows)} rows: {failed_rows}")
        if invalid_rack_names:
            logger.warning(f"Found {len(invalid_rack_names)} invalid rack names: {invalid_rack_names}")
        if potential_vm_rows:
            logger.info(f"Found {len(potential_vm_rows)} potential VMs: {potential_vm_rows}")
        logger.info(f"Parsed {len(allocations)} allocations and {len(csv_guests_data)} guests from CSV")
        return allocations, csv_guests_data
    except Exception as e:
        logger.error(f"Error parsing CSV file {csv_file}: {e}")
        raise
def configure_passwordless_ssh_with_creds(switch_hostname, is_infiniband, conn, keys, creds_list, ssh_setup_failures, timeout=SSH_TIMEOUT):
    logger.info(f"Configuring passwordless SSH for switch {switch_hostname}")
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout + 10)
    user = 'root' if is_infiniband else 'admin'
    BANNER_RETRIES = 3
    SESSION_RETRIES = 2
    PROTOCOL_RETRIES = 2
    try:
        pubkeys = {}
        key_paths = [
            ('/home/maatest/.ssh/id_rsa', 'ssh-rsa', '/home/maatest/.ssh/id_rsa.pub'),
            ('/home/maatest/.ssh/id_ecdsa', 'ecdsa-sha2-nistp256', '/home/maatest/.ssh/id_ecdsa.pub'),
            ('/home/maatest/.ssh/id_ed25519', 'ssh-ed25519', '/home/maatest/.ssh/id_ed25519.pub')
        ]
        for key_path, key_type, pubkey_path in key_paths:
            if os.path.exists(pubkey_path):
                with open(pubkey_path, 'r') as f:
                    pubkey_content = f.read().strip()
                    if not pubkey_content.startswith(key_type):
                        pubkey_content = f"{key_type} {pubkey_content.split()[1]}"
                    pubkeys[key_type] = pubkey_content
        if not keys:
            keys = [(paramiko.RSAKey.from_private_key_file('/home/maatest/.ssh/id_rsa'), 'ssh-rsa')]
        effective_timeout = timeout
        success = False
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for banner_attempt in range(BANNER_RETRIES):
            for key, key_type in keys:
                for attempt in range(SSH_RETRIES):
                    try:
                        logger.debug(f"Attempting key-based auth for {switch_hostname} with {user} ({key_type}, attempt {attempt + 1}/{SSH_RETRIES})")
                        client.connect(
                            switch_hostname,
                            username=user,
                            pkey=key,
                            timeout=effective_timeout + 10,
                            banner_timeout=30,
                            auth_timeout=effective_timeout
                        )
                        logger.info(f"Key-based connection succeeded for {switch_hostname} with {user} ({key_type})")
                        success = True
                        break
                    except paramiko.AuthenticationException:
                        logger.debug(f"Key-based auth failed for {switch_hostname} with {user} ({key_type}): Authentication failed")
                        break
                    except paramiko.SSHException as e:
                        logger.debug(f"Key-based auth failed for {switch_hostname} with {user} ({key_type}): {e}")
                        if "No existing session" in str(e):
                            logger.error(f"No existing session for {switch_hostname} with {user} ({key_type}), skipping")
                            break
                        if "Error reading SSH protocol banner" in str(e) and banner_attempt < BANNER_RETRIES - 1:
                            logger.info(f"Retrying due to banner error for {switch_hostname}")
                            time.sleep(2)
                            continue
                        break
                    except Exception as e:
                        logger.debug(f"Key-based auth failed for {switch_hostname} with {user} ({key_type}): {e}")
                        if attempt < SSH_RETRIES - 1:
                            time.sleep(2)
                    finally:
                        client.close()
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if success or "No existing session" in str(e):
                    break
            if success:
                break
        if not success:
            if not creds_list:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        """
                        SELECT USERNAME, ENCRYPTED_PASSWORD, COMPONENT_NAME
                        FROM MAAMD.ACCESS_CREDENTIALS
                        WHERE COMPONENT_TYPE = 'SWITCH'
                          AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
                          AND USERNAME = :username
                        ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END
                        """,
                        {'hostname': switch_hostname, 'username': user}
                    )
                    creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None, row[2]) for row in cursor.fetchall()]
                    creds_list.extend([{'username': username, 'password': password, 'component_name': comp} for username, password, comp in creds if username and password])
                    if not creds_list:
                        cursor.execute(
                            """
                            SELECT USERNAME, ENCRYPTED_PASSWORD
                            FROM MAAMD.ACCESS_CREDENTIALS
                            WHERE COMPONENT_TYPE = 'SWITCH'
                              AND COMPONENT_NAME = 'default'
                              AND USERNAME = :username
                            """,
                            {'username': user}
                        )
                        default_creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None) for row in cursor.fetchall()]
                        for username, password in default_creds:
                            if password:
                                add_credential(cursor, 'SWITCH', switch_hostname, username, password, None, 'script')
                                creds_list.append({'username': username, 'password': password, 'component_name': 'default'})
                                logger.info(f"Added default credentials for {switch_hostname} ({username})")
                        conn.commit()
                    if not creds_list:
                        logger.error(f"No valid credentials found for {switch_hostname} (username={user})")
                        ssh_setup_failures['SWITCH'].append(switch_hostname)
                        return False
                finally:
                    cursor.close()
            for cred in creds_list:
                username = cred['username']
                password = cred['password']
                component_name = cred['component_name']
                if not password:
                    logger.warning(f"No password for {username} on {switch_hostname} (component={component_name})")
                    continue
                if is_infiniband and username != 'root':
                    logger.debug(f"Skipping {username} for IB switch {switch_hostname}; only root allowed")
                    continue
                if not is_infiniband and username != 'admin':
                    logger.debug(f"Skipping {username} for Cisco/admin switch {switch_hostname}; only admin allowed")
                    continue
                for session_attempt in range(SESSION_RETRIES):
                    for attempt in range(3):
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        try:
                            logger.debug(f"Attempting password auth for {switch_hostname} with {username} (attempt {attempt + 1}/3)")
                            client.connect(
                                switch_hostname,
                                username=username,
                                password=password,
                                timeout=effective_timeout + 10,
                                banner_timeout=30,
                                auth_timeout=effective_timeout
                            )
                            logger.info(f"Password-based connection succeeded for {switch_hostname} with {username}")
                            is_admin_switch = '-adm0' in switch_hostname.lower()
                            is_ios = False
                            if is_admin_switch and not is_infiniband:
                                stdin, stdout, stderr = client.exec_command("show version", timeout=30)
                                output = stdout.read().decode().strip()
                                logger.debug(f"Switch {switch_hostname} version info: {output}")
                                if 'IOS' in output.upper():
                                    is_ios = True
                                    logger.debug(f"Detected IOS on admin switch {switch_hostname}")
                            if is_infiniband:
                                commands = [
                                    "mkdir -p /conf/ssh/authorized_keys",
                                    "chmod 700 /conf/ssh/authorized_keys",
                                    f"echo '{pubkeys.get('ssh-rsa', '')}' >> /conf/ssh/authorized_keys/root",
                                    f"echo '{pubkeys.get('ecdsa-sha2-nistp256', '')}' >> /conf/ssh/authorized_keys/root",
                                    f"echo '{pubkeys.get('ssh-ed25519', '')}' >> /conf/ssh/authorized_keys/root",
                                    "chmod 600 /conf/ssh/authorized_keys/root"
                                ]
                                for cmd in commands:
                                    stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
                                    error = stderr.read().decode().strip()
                                    if error:
                                        logger.error(f"Failed to execute '{cmd}' on {switch_hostname}: {error}")
                                        return False
                                    logger.info(f"Successfully executed '{cmd}' on {switch_hostname} for root")
                                logger.info(f"Installed RSA, ECDSA, and ED25519 keys for root on {switch_hostname} (IB)")
                            else:
                                shell = client.invoke_shell()
                                time.sleep(1)
                                shell.send("configure terminal\n")
                                time.sleep(1)
                                if is_ios:
                                    shell.send("ip ssh pubkey-chain\n")
                                    time.sleep(1)
                                    shell.send(f"username {username}\n")
                                    time.sleep(1)
                                    shell.send(f"key-string\n")
                                    time.sleep(1)
                                    for key_type in ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519']:
                                        if key_type in pubkeys:
                                            key_data = pubkeys[key_type].split()[1] if pubkeys[key_type].split()[0] == key_type else pubkeys[key_type]
                                            shell.send(f"{key_data}\n")
                                            time.sleep(1)
                                    shell.send("exit\n")
                                    time.sleep(1)
                                    shell.send("exit\n")
                                else:
                                    for key_type in ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519']:
                                        if key_type in pubkeys:
                                            shell.send(f"username {username} sshkey {pubkeys[key_type]}\n")
                                            time.sleep(1)
                                    shell.send("end\n")
                                time.sleep(1)
                                output = shell.recv(65535).decode().strip()
                                if "ERROR" in output.upper() or "FAILED" in output.upper():
                                    logger.error(f"Failed to set SSH keys on {switch_hostname}: {output}")
                                    shell.close()
                                    return False
                                shell.close()
                                logger.info(f"Installed RSA, ECDSA, and ED25519 keys for admin on {switch_hostname} (Cisco, {'IOS' if is_ios else 'NXOS'})")
                            client.close()
                            client = paramiko.SSHClient()
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            for key, key_type in keys:
                                for protocol_attempt in range(PROTOCOL_RETRIES):
                                    client = paramiko.SSHClient()
                                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                    try:
                                        logger.debug(f"Verifying key-based auth for {switch_hostname} with {user} ({key_type}, protocol attempt {protocol_attempt + 1}/{PROTOCOL_RETRIES})")
                                        client.connect(
                                            switch_hostname,
                                            username=user,
                                            pkey=key,
                                            timeout=effective_timeout + 10,
                                            banner_timeout=30,
                                            auth_timeout=effective_timeout
                                        )
                                        logger.info(f"Successfully configured SSH for {switch_hostname} with {user} ({key_type})")
                                        success = True
                                        break
                                    except paramiko.SSHException as e:
                                        logger.debug(f"Key-based verification failed for {switch_hostname} with {key_type}: {e}")
                                        if "No existing session" in str(e):
                                            logger.error(f"No existing session during verification for {switch_hostname} with {key_type}, skipping")
                                            break
                                        if "Protocol error" in str(e) and protocol_attempt < PROTOCOL_RETRIES - 1:
                                            logger.info(f"Retrying key-based verification for {switch_hostname} due to protocol error")
                                            time.sleep(2)
                                            continue
                                        break
                                    except Exception as e:
                                        logger.debug(f"Key-based verification failed for {switch_hostname} with {key_type}: {e}")
                                        break
                                    finally:
                                        client.close()
                            if success:
                                break
                            logger.error(f"Key-based verification failed for {switch_hostname} after key installation")
                            return False
                        except paramiko.AuthenticationException as e:
                            logger.warning(f"Password-based auth attempt {attempt + 1}/3 failed for {switch_hostname} with {username}: {e}")
                            if "Authentication type not permitted" in str(e):
                                logger.error(f"Switch {switch_hostname} only supports publickey authentication, skipping")
                                ssh_setup_failures['SWITCH'].append(switch_hostname)
                                return False
                            if attempt < 2:
                                time.sleep(2)
                        except paramiko.SSHException as e:
                            logger.warning(f"Password-based auth attempt {attempt + 1}/3 failed for {switch_hostname} with {username}: {e}")
                            if "No existing session" in str(e) and session_attempt < SESSION_RETRIES - 1:
                                logger.info(f"Retrying session for {switch_hostname} due to 'No existing session' error")
                                time.sleep(5)
                                continue
                            break
                        except Exception as e:
                            logger.error(f"Unexpected error during password-based SSH for {switch_hostname} with {username}: {e}")
                            break
                        finally:
                            client.close()
                    if success:
                        break
                if success:
                    break
        if not success:
            logger.error(f"All authentication attempts failed for {switch_hostname}")
            ssh_setup_failures['SWITCH'].append(switch_hostname)
            return False
        return True
    except Exception as e:
        logger.error(f"Error configuring SSH for {switch_hostname}: {e}")
        ssh_setup_failures['SWITCH'].append(switch_hostname)
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)
def generate_secure_password(length=16):
    """Generate a cryptographically secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password
def setup_iloms_ssh(iloms, conn):
    """Configure SSH access for ILOMs."""
    logger.info("Starting SSH setup for ILOMs")
    if not iloms:
        logger.info("No ILOMs to process, skipping SSH setup")
        return
    cursor = conn.cursor()
    try:
        start_time = time.time()
        ilom_credentials = {}
        for hostname, _ in iloms:
            username = 'root' # ILOMs typically use 'root'
            cursor.execute(
                """
                SELECT USERNAME, ENCRYPTED_PASSWORD, COMPONENT_NAME
                FROM MAAMD.ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = 'ILOM'
                  AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
                  AND USERNAME = :username
                ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END
                """,
                {'hostname': hostname, 'username': username}
            )
            creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None, row[2]) for row in cursor.fetchall()]
            ilom_credentials[hostname] = [
                {'username': username, 'password': password, 'component_name': comp}
                for username, password, comp in creds if username and password
            ]
            logger.debug(f"Credentials for {hostname}: {len(ilom_credentials[hostname])} found")
            if not ilom_credentials.get(hostname):
                cursor.execute(
                    """
                    SELECT USERNAME, ENCRYPTED_PASSWORD
                    FROM MAAMD.ACCESS_CREDENTIALS
                    WHERE COMPONENT_TYPE = 'ILOM'
                      AND COMPONENT_NAME = 'default'
                      AND USERNAME = :username
                    """,
                    {'username': username}
                )
                creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None) for row in cursor.fetchall()]
                for u, p in creds:
                    if p:
                        add_credential(cursor, 'ILOM', hostname, u, p, None, 'script')
                        ilom_credentials[hostname] = [{'username': u, 'password': p, 'component_name': 'default'}]
                        logger.info(f"Added default credentials for {hostname} ({u})")
        conn.commit()
        logger.info(f"Processed credentials for {len(iloms)} ILOMs in {time.time() - start_time:.2f} seconds")
        start_time = time.time()
        ilom_hostnames = [hostname for hostname, _ in iloms]
        reachable_iloms = check_hosts_reachability(ilom_hostnames)
        filtered_iloms = [
            (hostname, ilom_credentials.get(hostname, []))
            for hostname, _ in iloms
            if reachable_iloms.get(hostname, False)
        ]
        logger.info(f"Filtered to {len(filtered_iloms)} reachable ILOMs in {time.time() - start_time:.2f} seconds")
        start_time = time.time()
        failed_iloms = []
        SSH_SETUP_FAILURES = {'ILOM': []}
        for hostname, creds in filtered_iloms:
            try:
                success = configure_passwordless_ssh_with_creds(
                    hostname,
                    False, # ILOMs are not Infiniband
                    conn,
                    [],
                    creds,
                    SSH_SETUP_FAILURES,
                    SSH_TIMEOUT
                )
                if success:
                    logger.info(f"Successfully configured SSH for ILOM {hostname}")
                else:
                    logger.warning(f"Failed to configure SSH for ILOM {hostname}")
                    failed_iloms.append(hostname)
            except Exception as e:
                logger.error(f"Error configuring SSH for ILOM {hostname}: {e}")
                failed_iloms.append(hostname)
        logger.info(f"Completed SSH configuration for {len(filtered_iloms) - len(failed_iloms)}/{len(filtered_iloms)} ILOMs in {time.time() - start_time:.2f} seconds")
        if failed_iloms:
            logger.warning(f"Failed to configure SSH for {len(failed_iloms)} ILOMs: {failed_iloms}")
    except Exception as e:
        logger.error(f"Error during ILOM SSH setup: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
def setup_host_ssh(hostname, conn, ssh_keys, ssh_setup_failures, ssh_retries, ssh_auth_fail_limit, is_ilom=False, is_storage=False, is_guest=False, is_hypervisor=False, timeout=SSH_TIMEOUT):
    component_type = 'ILOM' if is_ilom else 'PHYSICAL_HOST' if not is_guest else 'GUEST'
    cursor = conn.cursor()
    try:
        if not is_host_reachable(hostname):
            ssh_setup_failures[component_type].add(hostname)
            return False
        users = ['root'] if is_storage or is_hypervisor or is_ilom else ['root', 'oracle']
        ssh_key_success = False
        successful_users = []
        pubkeys = {}
        key_paths = [
            ('/home/maatest/.ssh/id_rsa', 'ssh-rsa', '/home/maatest/.ssh/id_rsa.pub'),
            ('/home/maatest/.ssh/id_ecdsa', 'ecdsa-sha2-nistp256', '/home/maatest/.ssh/id_ecdsa.pub'),
            ('/home/maatest/.ssh/id_ed25519', 'ssh-ed25519', '/home/maatest/.ssh/id_ed25519.pub')
        ]
        for key_path, key_type, pubkey_path in key_paths:
            if os.path.exists(pubkey_path):
                with open(pubkey_path, 'r') as f:
                    pubkey_content = f.read().strip()
                    if not pubkey_content.startswith(key_type):
                        pubkey_content = f"{key_type} {pubkey_content.split()[1]}"
                    pubkeys[key_type] = pubkey_content
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        for key, key_type in ssh_keys:
            for username in users:
                for attempt in range(ssh_retries):
                    try:
                        client.connect(
                            hostname,
                            username=username,
                            pkey=key,
                            timeout=timeout + 10,
                            banner_timeout=30
                        )
                        stdin, stdout, stderr = client.exec_command("cat ~/.ssh/authorized_keys", timeout=60)
                        authorized_keys = stdout.read().decode().strip()
                        error = stderr.read().decode().strip()
                        if error:
                            break
                        key_present = any(pubkeys[key_type] in authorized_keys for key_type in pubkeys)
                        if key_present:
                            ssh_key_success = True
                            successful_users.append(username)
                            client.close()
                            return True
                        ssh_key_success = True
                        successful_users.append(username)
                        break
                    except paramiko.SSHException as e:
                        if "No existing session" in str(e):
                            break
                    except Exception as e:
                        if attempt < ssh_retries - 1:
                            time.sleep(2)
                    finally:
                        client.close()
                        client = SSHClient()
                        client.set_missing_host_key_policy(AutoAddPolicy())
                if ssh_key_success:
                    break
            if ssh_key_success:
                break
        if not ssh_key_success:
            for username in users:
                password = get_credential(cursor, component_type, hostname, username)
                if not password:
                    password = get_credential(cursor, component_type, 'default', username)
                    if not password:
                        password = generate_secure_password()
                        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                        encrypted_password = encrypt_data(hashed_password)
                        add_credential(cursor, component_type, hostname, username, hashed_password, None, 'script')
                        conn.commit()
                if not password:
                    continue
                for attempt in range(ssh_retries):
                    try:
                        client.connect(
                            hostname,
                            username=username,
                            password=password,
                            timeout=timeout + 10,
                            banner_timeout=30
                        )
                        successful_users.append(username)
                        break
                    except paramiko.AuthenticationException as e:
                        if "Bad authentication type" in str(e) or "publickey" in str(e).lower():
                            logger.warning(f"Host {hostname} only supports publickey authentication, skipping password auth")
                            ssh_setup_failures[component_type].add(hostname)
                            return False
                        if attempt < ssh_retries - 1:
                            time.sleep(2)
                    except paramiko.SSHException as e:
                        if "No existing session" in str(e):
                            break
                    except Exception as e:
                        logger.error(f"Unexpected error during password auth for {hostname} with {username}: {e}")
                        if attempt < ssh_retries - 1:
                            time.sleep(2)
                    finally:
                        client.close()
                        client = SSHClient()
                        client.set_missing_host_key_policy(AutoAddPolicy())
        if successful_users:
            for username in successful_users:
                for attempt in range(ssh_retries):
                    try:
                        password = get_credential(cursor, component_type, hostname, username) or get_credential(cursor, component_type, 'default', username)
                        client.connect(
                            hostname,
                            username=username,
                            password=password,
                            timeout=timeout + 10,
                            banner_timeout=30
                        )
                        commands = [
                            "mkdir -p ~/.ssh",
                            "chmod 700 ~/.ssh",
                            f"echo '{pubkeys.get('ssh-rsa', '')}' >> ~/.ssh/authorized_keys",
                            f"echo '{pubkeys.get('ecdsa-sha2-nistp256', '')}' >> ~/.ssh/authorized_keys",
                            f"echo '{pubkeys.get('ssh-ed25519', '')}' >> ~/.ssh/authorized_keys",
                            "chmod 600 ~/.ssh/authorized_keys"
                        ]
                        for cmd in commands:
                            stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
                            error = stderr.read().decode().strip()
                            if error:
                                logger.error(f"Failed to execute '{cmd}' on {hostname} for {username}: {error}")
                        break
                    except Exception as e:
                        logger.error(f"Failed to install SSH keys for {username} on {hostname}: {e}")
                        if attempt < ssh_retries - 1:
                            time.sleep(2)
                    finally:
                        client.close()
                        client = SSHClient()
                        client.set_missing_host_key_policy(AutoAddPolicy())
                for attempt in range(ssh_retries):
                    try:
                        for key, key_type in ssh_keys:
                            client.connect(
                                hostname,
                                username=username,
                                pkey=key,
                                timeout=timeout + 10,
                                banner_timeout=30
                            )
                            break
                        else:
                            ssh_setup_failures[component_type].add(hostname)
                            return False
                        break
                    except Exception as e:
                        logger.error(f"Key-based verification failed for {hostname}: {e}")
                        if attempt < ssh_retries - 1:
                            time.sleep(2)
                    finally:
                        client.close()
        else:
            ssh_setup_failures[component_type].add(hostname)
            return False
        return True
    except Exception as e:
        logger.error(f"Error setting up SSH for {hostname}: {e}")
        ssh_setup_failures[component_type].add(hostname)
        return False
    finally:
        cursor.close()
def get_credential_silent(cursor, component_type, component_name, username, log_file=None):
    """Retrieve and decrypt credentials from maamd.access_credentials, logging to file."""
    if log_file is None:
        log_file = os.path.join(config.OUTPUT_DIR, 'collect_agent_data.log')
    def log(message, log_file=log_file):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    try:
        cursor.execute(
            """
            SELECT ENCRYPTED_PASSWORD
            FROM maamd.access_credentials
            WHERE component_type = :1
            AND component_name = :2
            AND username = :3
            """,
            (component_type, component_name, username)
        )
        row = cursor.fetchone()
        if row and row[0]:
            lob_data = row[0].read()
            decrypted = decrypt_data(lob_data)
            if decrypted:
                log(f"Retrieved and decrypted password for {component_type}:{component_name}:{username}")
                return decrypted
            else:
                log(f"Failed to decrypt password for {component_type}:{component_name}:{username}")
                return None
        else:
            log(f"No password found for {component_type}:{component_name}:{username}")
            return None
    except oracledb.Error as e:
        log(f"Error retrieving credential for {component_type}:{component_name}:{username}: {type(e).__name__}: {str(e)}")
        return None
def set_switch_alert_v2c(ssh, alert_id, destination_ip, port, community_string, status, switch_type):
    """Configure SNMP v2c alert for a switch."""
    try:
        if switch_type.lower() == 'infiniband':
            cmd = f"set snmp trap {alert_id} destination={destination_ip} port={port} community={community_string} version=2c"
            execute_ssh_command(ssh, cmd)
            execute_ssh_command(ssh, f"set snmp trap {alert_id} enable={status.lower()}")
        else: # Cisco or other
            cmd = f"snmp-server host {destination_ip} traps version 2c {community_string} udp-port {port}"
            execute_ssh_command(ssh, cmd)
            execute_ssh_command(ssh, f"snmp-server enable traps")
        logger.info(f"Configured SNMP v2c alert {alert_id} for switch type {switch_type} with destination {destination_ip}:{port}")
    except Exception as e:
        logger.error(f"Failed to configure SNMP v2c alert {alert_id} for switch type {switch_type}: {str(e)}")
        raise
def set_switch_alert_v3(ssh, alert_id, destination_ip, port, username, status, switch_type, old_destination_ip=None, old_version=None, old_port=None, old_username=None):
    """Configure SNMP v3 alert for a switch."""
    try:
        if switch_type.lower() == 'infiniband':
            cmd = f"set snmp trap {alert_id} destination={destination_ip} port={port} user={username} version=3"
            execute_ssh_command(ssh, cmd)
            execute_ssh_command(ssh, f"set snmp trap {alert_id} enable={status.lower()}")
        else: # Cisco or other
            if old_destination_ip and old_version:
                execute_ssh_command(ssh, f"no snmp-server host {old_destination_ip} version {old_version} {old_username if old_version == '3' else ''} udp-port {old_port}")
            cmd = f"snmp-server host {destination_ip} traps version 3 auth {username} udp-port {port}"
            execute_ssh_command(ssh, cmd)
            execute_ssh_command(ssh, f"snmp-server enable traps")
        logger.info(f"Configured SNMP v3 alert {alert_id} for switch type {switch_type} with destination {destination_ip}:{port}")
    except Exception as e:
        logger.error(f"Failed to configure SNMP v3 alert {alert_id} for switch type {switch_type}: {str(e)}")
        raise
def reset_switch_alert_to_default(ssh_user=None, switch_ip=None, alert_id=None, switch_type=None, destination_ip=None, version=None, community_string=None, username=None, security_level=None, port=None, confirm_delete=True, key_file="/home/maatest/.ssh/id_rsa", ssh=None):
    """Reset SNMP alert to default for a switch."""
    if not ssh:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh.connect(switch_ip, username=ssh_user, key_filename=key_file, timeout=SSH_TIMEOUT)
        except (SSHException, TimeoutError) as e:
            logger.error(f"Failed to connect to switch {switch_ip}: {str(e)}")
            return False
    try:
        if switch_type.lower() == 'infiniband':
            cmd = f"set snmp trap {alert_id} disable"
            execute_ssh_command(ssh, cmd)
            cmd = f"set snmp trap {alert_id} destination=0.0.0.0 port=0 community=public version=2c"
            execute_ssh_command(ssh, cmd)
        else: # Cisco or other
            if destination_ip and version:
                cmd = f"no snmp-server host {destination_ip} version {version} {username if version == '3' else community_string} udp-port {port}"
                execute_ssh_command(ssh, cmd)
        logger.info(f"Reset SNMP alert {alert_id} to default on switch {switch_ip} (type: {switch_type})")
        return True
    except Exception as e:
        logger.error(f"Failed to reset switch alert {alert_id} on {switch_ip}: {str(e)}")
        return False
def detect_switch_os(ssh):
    """Detect the operating system of a switch."""
    try:
        stdin, stdout, stderr = ssh.exec_command("show version", timeout=30)
        output = stdout.read().decode().strip()
        if 'IOS' in output.upper():
            return 'IOS'
        elif 'NX-OS' in output.upper():
            return 'NXOS'
        elif 'Infiniband' in output.lower():
            return 'INFINIBAND'
        else:
            return 'UNKNOWN'
    except Exception as e:
        logger.error(f"Failed to detect switch OS: {str(e)}")
        return 'UNKNOWN'
def execute_paramiko_command(ssh_client, command, timeout=30):
    """Execute a command via Paramiko SSH and return output, error, and exit status."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()
        return output, error, exit_status
    except (SSHException, TimeoutError) as e:
        logger.error(f"Paramiko command execution failed: {str(e)}")
        return '', str(e), 1
def is_hypervisor(system, conn):
    """Check if a system is a hypervisor."""
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT IS_HYPERVISOR FROM MAAMD.HYPERVISORS WHERE HOSTNAME = :1",
            {'hostname': system}
        )
        result = cursor.fetchone()
        if result:
            return result[0] == 'Y'
        cursor.execute(
            "SELECT COUNT(*) FROM MAAMD.GUESTS WHERE HYPERVISOR = :1",
            {'hypervisor': system}
        )
        count = cursor.fetchone()[0]
        return count > 0
    except oracledb.Error as e:
        logger.error(f"Error checking hypervisor status for {system}: {e}")
        return False
    finally:
        cursor.close()
def get_guests(system, conn):
    """Retrieve guest VMs from a hypervisor."""
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT HOSTNAME FROM MAAMD.GUESTS WHERE HYPERVISOR = :1",
            {'hypervisor': system}
        )
        guests = [row[0] for row in cursor.fetchall()]
        return guests
    except oracledb.Error as e:
        logger.error(f"Error fetching guests for {system}: {e}")
        return []
    finally:
        cursor.close()
def process_system(row, hypervisor_map=None, conn=None):
    """Process a CSV row into allocation and guest data."""
    component = row.get('COMPONENT', '').strip()
    if not component:
        logger.warning(f"Skipping row with empty component: {row}")
        return None, []
    try:
        system_hosts = expand_host_range(component, component)
        if not system_hosts:
            logger.warning(f"No valid hosts derived for component {component}")
            return None, []
        system_name = system_hosts[0] # Use the first resolved host
        allocations_json = row.get('ALLOCATIONS', row.get('MY_ALLOCATION', ''))
        if not allocations_json:
            logger.warning(f"No allocation data for {component}")
            return None, []
        cleaned_json = clean_for_json(fix_json_start(allocations_json))
        allocation_data = json.loads(cleaned_json)
        current = allocation_data.get('current', [{}])[0]
        allocation = (
            system_name,
            current.get('description', 'Unknown'),
            current.get('start_date', ''),
            current.get('end_date', ''),
            current.get('allocator', {}).get('username', 'Unknown'),
            None,
            datetime.now(),
            derive_rack_name(system_name),
            derive_ilom_name(system_name),
            None,
            current.get('allocation_type', {}).get('label', 'Unknown'),
            ', '.join(user.get('username', '') for user in current.get('allocatees', {}).get('users', []))[:500],
            None,
            None,
            current.get('notes', None)
        )
        guests = []
        is_vm = hypervisor_map.get(component, False) if hypervisor_map else False
        if is_vm or 'vm' in system_name.lower() or 'client' in system_name.lower():
            hypervisor = derive_hypervisor_name(system_name)
            if hypervisor and is_fqdn_resolvable(hypervisor, conn):
                guests.append((system_name, hypervisor))
        return allocation, guests
    except Exception as e:
        logger.error(f"Error processing system {component}: {e}")
        return None, []
def derive_rack_name(hostname):
    hostname_lower = hostname.lower()
    # Remove domain if present
    if '.us.oracle.com' in hostname_lower:
        hostname = hostname.split('.us.oracle.com')[0]
    # Remove ILOM suffix if present
    if hostname_lower.endswith('-c') or hostname_lower.endswith('-ilom'):
        hostname = hostname.rsplit('-', 1)[0]
    # Split on '.' to get base
    parts = hostname.split('.')
    base = parts[0]
    # Remove 'celadmXX' or 'admXX' – check 'celadm' first since it contains 'adm'
    if 'celadm' in base:
        base = base.split('celadm')[0]
    elif 'adm' in base:
        base = base.split('adm')[0]
    return base
def derive_ilom_name(system_name, hypervisor_name=None):
    """Derive ILOM name for a system."""
    if 'adm' in system_name.lower() or 'celadm' in system_name.lower():
        return system_name.replace('.us.oracle.com', '-c.us.oracle.com').replace('.usdv1.oraclecorp.com', '-c.usdv1.oraclecorp.com')
    return None
def derive_hypervisor_name(guest_name):
    """Derive hypervisor name for a guest."""
    if 'vm' in guest_name.lower() or 'client' in guest_name.lower():
        base = guest_name.rsplit('vm', 1)[0].rstrip('-_') if 'vm' in guest_name.lower() else guest_name.rsplit('client', 1)[0].rstrip('-_')
        return base + '.us.oracle.com'
    return None
def is_roce_switch(switch_hostname):
    """Check if a switch is RoCE-based."""
    return 'roce' in switch_hostname.lower()
def is_infiniband_switch(switch_hostname):
    """Check if a switch is InfiniBand-based."""
    return 'ib' in switch_hostname.lower()
def get_serial_number(ilom_name, conn):
    """Retrieve serial number for an ILOM host."""
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT SERIAL_NUMBER FROM MAAMD.SYSTEM_ALLOCATIONS WHERE ILOM_NAME = :1",
            {'ilom_name': ilom_name}
        )
        result = cursor.fetchone()
        return result[0] if result else None
    except oracledb.Error as e:
        logger.error(f"Error fetching serial number for {ilom_name}: {e}")
        return None
    finally:
        cursor.close()
def configure_passwordless_ssh(switch_hostname, is_infiniband=False, conn=None, ssh_cache={}):
    """Configure passwordless SSH for a switch (simplified version)."""
    return configure_passwordless_ssh_with_creds(switch_hostname, is_infiniband, conn, [], [], {'SWITCH': []}, SSH_TIMEOUT)
def setup_ssh_keys(system, ilom_name, is_storage=False, is_guest=False, conn=None):
    """Set up SSH keys for a system."""
    ssh_keys = [(RSAKey.from_private_key_file('/home/maatest/.ssh/id_rsa'), 'ssh-rsa')]
    ssh_setup_failures = {'PHYSICAL_HOST': set(), 'ILOM': set(), 'GUEST': set()}
    return setup_host_ssh(
        system,
        conn,
        ssh_keys,
        ssh_setup_failures,
        SSH_RETRIES,
        3,
        is_ilom=bool(ilom_name),
        is_storage=is_storage,
        is_guest=is_guest,
        timeout=SSH_TIMEOUT
    )
def process_switch(switch_hostname, pool):
    conn = get_db_pool_connection(pool)
    cursor = None
    try:
        cursor = conn.cursor()
        try:
            ip_address = socket.gethostbyname(switch_hostname)
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for switch {switch_hostname}: {e}")
            return None
        rack_name = derive_rack_name(switch_hostname) if 'derive_rack_name' in globals() else switch_hostname # Fallback if not defined
        is_ib = is_infiniband_switch(switch_hostname)
        user = 'root' if is_ib else 'admin'
        switch_data = {
            'hostname': switch_hostname,
            'ip_address': ip_address,
            'make': 'Oracle' if is_ib else 'Cisco',
            'model': 'Unknown',
            'version': 'Unknown',
            'rack_name': rack_name,
            'fw_version': 'None',
            'serial_number': 'Unknown'
        }
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connected = False
        try_password_first = not is_ib
        for attempt in range(4):
            try:
                if (attempt == 0 and not try_password_first) or (attempt == 1 and try_password_first):
                    logger.debug(f"Attempting SSH key auth for {switch_hostname} as {user}")
                    pkey = paramiko.RSAKey.from_private_key_file('/home/maatest/.ssh/id_rsa')
                    client.connect(switch_hostname, username=user, pkey=pkey, timeout=SSH_TIMEOUT)
                    logger.info(f"Connected to {switch_hostname} with SSH key")
                    ssh_connected = True
                    break
                else:
                    component_name = 'default' if (attempt % 2 == 1 if try_password_first else attempt % 2 == 0) else switch_hostname
                    logger.debug(f"Attempting password auth for {switch_hostname} as {user} using {component_name}")
                    password = get_credential(cursor, 'SWITCH', component_name, user)
                    if not password:
                        logger.debug(f"No {component_name} password found for {switch_hostname} ({user})")
                        password = 'We1come$' if user == 'root' else 'admin'
                        logger.debug(f"Using hardcoded fallback for {switch_hostname} ({user})")
                    if password:
                        client.connect(switch_hostname, username=user, password=password, timeout=SSH_TIMEOUT,
                                       look_for_keys=False, allow_agent=False)
                        logger.info(f"Connected to {switch_hostname} with {component_name} password")
                        ssh_connected = True
                        break
            except paramiko.AuthenticationException as e:
                logger.warning(f"Authentication failed for {switch_hostname}: {e}")
            except paramiko.SSHException as e:
                logger.warning(f"SSH exception for {switch_hostname}: {e}")
                if "No existing session" in str(e):
                    time.sleep(3)
            except Exception as e:
                logger.error(f"Unexpected auth error for {switch_hostname}: {e}")
            finally:
                if not ssh_connected:
                    try:
                        client.close()
                    except:
                        pass
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if not ssh_connected:
            logger.error(f"Failed to connect to {switch_hostname} after all attempts")
            return switch_data
        try:
            if is_ib:
                cmd = "spsh -c 'version'"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
                output = stdout.read().decode().strip()
                errors = stderr.read().decode().strip()
                logger.debug(f"IB switch {switch_hostname} - Raw output from '{cmd}': {output}")
                if errors:
                    logger.warning(f"IB switch {switch_hostname} - Errors from '{cmd}': {errors}")
                version_match = re.search(r'SP\s+firmware\s+(\d+\.\d+\.\d+(?:-\d+)?)', output, re.IGNORECASE)
                if version_match:
                    switch_data['version'] = version_match.group(1)
                cmd = "spsh 'ls /SYS'"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
                output = stdout.read().decode().strip()
                errors = stderr.read().decode().strip()
                logger.debug(f"IB switch {switch_hostname} - Raw output from '{cmd}': {output}")
                if errors:
                    logger.warning(f"IB switch {switch_hostname} - Errors from '{cmd}': {errors}")
                if output:
                    model_match = re.search(r'product_name\s*=\s*(.+?)(?:\s*$|\n)', output, re.IGNORECASE)
                    serial_match = re.search(r'product_serial_number\s*=\s*(\S+)', output, re.IGNORECASE)
                    fw_match = re.search(r'Version\s+(\d+\.\d+\.\d+)', output, re.IGNORECASE)
                    switch_data['model'] = model_match.group(1).strip() if model_match else 'Unknown'
                    switch_data['serial_number'] = serial_match.group(1) if serial_match else 'Unknown'
                    switch_data['fw_version'] = fw_match.group(1) if fw_match else 'None'
            else:
                cmd = "show version"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
                output = stdout.read().decode().strip()
                errors = stderr.read().decode().strip()
                logger.debug(f"Cisco switch {switch_hostname} - Raw output from '{cmd}': {output}")
                if errors:
                    logger.warning(f"Cisco switch {switch_hostname} - Errors from '{cmd}': {errors}")
                model_match = re.search(r'cisco\s+Nexus.*?(C\d+[A-Z\-0-9]*)', output, re.IGNORECASE) or \
                              re.search(r'Hardware\s+cisco\s+(\S+)', output, re.IGNORECASE)
                serial_match = re.search(r'Processor\s+Board\s+ID\s+(\S+)', output, re.IGNORECASE) or \
                                 re.search(r'Serial\s+Number\s*:\s*(\S+)', output, re.IGNORECASE)
                version_match = re.search(r'NXOS:\s+version\s+(\d+\.\d+\(\d+\))', output, re.IGNORECASE) or \
                                  re.search(r'(?:IOS\s+Software.*Version|Software\s+version|Version)\s*[:\s]+([\d\.\(\)a-zA-Z]+)', output, re.IGNORECASE)
                fw_match = re.search(r'BIOS:\s+version\s+(\S+)', output, re.IGNORECASE)
                switch_data['model'] = model_match.group(1) if model_match else 'Unknown'
                switch_data['serial_number'] = serial_match.group(1) if serial_match else 'Unknown'
                switch_data['version'] = version_match.group(1) if version_match else 'Unknown'
                switch_data['fw_version'] = fw_match.group(1) if fw_match else 'None'
                if switch_data['serial_number'] == 'Unknown':
                    cmd = "show inventory"
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
                    output = stdout.read().decode().strip()
                    errors = stderr.read().decode().strip()
                    serial_match = re.search(r'SN:\s*(\S+)', output, re.IGNORECASE)
                    switch_data['serial_number'] = serial_match.group(1) if serial_match else 'Unknown'
                if is_roce_switch(switch_hostname):
                    switch_data['model'] = '9336C'
        except Exception as e:
            logger.error(f"Failed to collect switch data for {switch_hostname}: {e}", exc_info=True)
        finally:
            client.close()
        logger.info(f"Processed switch {switch_hostname}: {switch_data}")
        return switch_data
    except oracledb.Error as e:
        logger.error(f"Database error processing switch {switch_hostname}: {e}", exc_info=True)
        return None
    finally:
        if cursor:
            cursor.close()
        release_db_connection(conn, pool)
def populate_switch_info(conn):
    """Populate switch information in the database."""
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SYSTEM_NAME FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME LIKE '%sw%'")
        switches = [(row[0], None) for row in cursor.fetchall()]
        for switch in switches:
            process_switch(switch[0], conn)
    except oracledb.Error as e:
        logger.error(f"Error populating switch info: {e}")
    finally:
        cursor.close()
def insert_into_db(allocations, guests_data, conn):
    """Insert allocation and guest data into the database."""
    cursor = conn.cursor()
    try:
        for alloc in allocations:
            cursor.execute(
                """
                INSERT INTO MAAMD.SYSTEM_ALLOCATIONS (
                    SYSTEM_NAME, CURRENT_ALLOCATION, START_DATE, END_DATE, ALLOCATOR,
                    LAST_UPDATED, RACK_NAME, ILOM_NAME, ALLOCATION_TYPE, OWNER_GROUP, NOTES
                ) VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11)
                ON DUPLICATE KEY UPDATE
                    CURRENT_ALLOCATION = :2, START_DATE = :3, END_DATE = :4, ALLOCATOR = :5,
                    LAST_UPDATED = :6, RACK_NAME = :7, ILOM_NAME = :8, ALLOCATION_TYPE = :9,
                    OWNER_GROUP = :10, NOTES = :11
                """,
                alloc[:11]
            )
        for guest in guests_data:
            cursor.execute(
                """
                INSERT INTO MAAMD.GUESTS (HOSTNAME, HYPERVISOR, LAST_UPDATED)
                VALUES (:1, :2, SYSDATE)
                ON DUPLICATE KEY UPDATE HYPERVISOR = :2, LAST_UPDATED = SYSDATE
                """,
                guest
            )
        conn.commit()
        logger.info(f"Inserted {len(allocations)} allocations and {len(guests_data)} guests into database")
    except oracledb.Error as e:
        logger.error(f"Error inserting data into database: {e}")
        conn.rollback()
    finally:
        cursor.close()
def populate_exadata_racks(allocations, conn):
    """Populate exadata rack data in the database."""
    cursor = conn.cursor()
    try:
        for alloc in allocations:
            rack_name = alloc[7] # RACK_NAME
            if rack_name and rack_name != 'unknown':
                cursor.execute(
                    """
                    INSERT INTO MAAMD.EXADATA_RACKS (RACK_NAME, STORAGENETWORK_TYPE)
                    VALUES (:1, 'UNKNOWN')
                    ON DUPLICATE KEY UPDATE STORAGENETWORK_TYPE = 'UNKNOWN'
                    """,
                    (rack_name,)
                )
        conn.commit()
        logger.info(f"Populated exadata racks from {len(allocations)} allocations")
    except oracledb.Error as e:
        logger.error(f"Error populating exadata racks: {e}")
        conn.rollback()
    finally:
        cursor.close()
def download_csv():
    """Download CSV data from a predefined URL."""
    url = "exaboard.oraclecorp.com/api/dview/3403/data/csv/"
    csv_file = "/tmp/allocation_data.csv"
    try:
        result = subprocess.run(['wget', '-O', csv_file, url], capture_output=True, text=True, check=True)
        logger.info(f"Downloaded CSV to {csv_file}")
        return csv_file
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to download CSV: {e.stderr}")
        raise RuntimeError(f"Failed to download CSV: {e.stderr}")
def is_resolvable_fqdn(fqdn, cache=None):
    """Check if an FQDN is resolvable, with optional caching."""
    if cache is None:
        cache = {}
    if fqdn in cache:
        return cache[fqdn]
    result = is_fqdn_resolvable(fqdn)
    cache[fqdn] = result
    return result
def is_host_reachable(hostname, ip=None):
    """Check if a host is reachable via TCP connect to port 22.
    Supports BOTH calling styles:
      - is_host_reachable(hostname)
      - is_host_reachable(hostname, ip)
    More reliable than ping in firewalled Exadata environments.
    Added *args safety for shared library compatibility."""
    if not hostname:
        return False
    try:
        target = ip or hostname
        socket.create_connection((target, 22), timeout=5)
        logger.debug(f"Host {hostname} is reachable (TCP/22)")
        return True
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
        logger.debug(f"Host {hostname} not reachable: {type(e).__name__}")
        return False
def resolve_system_name(original_name):
    """Resolve a system name to a valid FQDN."""
    try:
        return socket.getfqdn(original_name)
    except socket.gaierror:
        logger.warning(f"Could not resolve system name: {original_name}")
        return original_name
def force_exit():
    """Force script exit."""
    logger.info("Forcing script exit")
    os._exit(1)
def generate_ssh_summary_report():
    """Generate an SSH setup summary report."""
    logger.info("Generating SSH setup summary report")
    return {"status": "SSH setup completed"}
def run_scheduled_scripts(script_list):
    """Run a list of scheduled scripts."""
    for script in script_list:
        try:
            result = subprocess.run([script], capture_output=True, text=True, check=True)
            logger.info(f"Successfully ran script {script}: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running script {script}: {e.stderr}")
def check_hosts_reachability(hosts, max_workers=50, timeout=300, fh=None):
    """Check reachability of hosts in parallel with timeout and DNS retries."""
    reachable = {}
    logger.info(f"Starting reachability check for {len(hosts)} hosts")
    # Safe flush: only if fh exists
    if fh is not None:
        fh.flush()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host_reachability_single_with_retry, host, fh=fh): host for host in hosts}
        try:
            for future in as_completed(futures, timeout=timeout):
                host, is_reachable = future.result()
                reachable[host] = is_reachable
                logger.debug(f"Reachability for {host}: {'reachable' if is_reachable else 'unreachable'}")
                if fh is not None:
                    fh.flush()
        except TimeoutError:
            logger.error(f"Reachability check timed out after {timeout} seconds")
            if fh is not None:
                fh.flush()
            for future in futures:
                if not future.done():
                    future.cancel()
    unreachable_hosts = [host for host, is_reach in reachable.items() if not is_reach]
    if unreachable_hosts:
        logger.warning(f"Unreachable hosts: {unreachable_hosts[:10]}{'...' if len(unreachable_hosts) > 10 else ''}")
    reachable_count = sum(1 for v in reachable.values() if v)
    logger.info(f"Reachability check complete: {reachable_count}/{len(reachable)} hosts reachable")
    if fh is not None:
        fh.flush()
    return reachable
def check_hosts_reachability_single(hosts, max_workers=50, timeout=300, fh=None):
    """Check reachability of hosts in parallel with timeout and DNS retries."""
    reachable = {}
    logger.info(f"Starting reachability check for {len(hosts)} hosts")
    # Safe flush: only if fh exists
    if fh is not None:
        fh.flush()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host_reachability_single_with_retry, host, fh=fh): host for host in hosts}
        try:
            for future in as_completed(futures, timeout=timeout):
                host, is_reachable = future.result()
                reachable[host] = is_reachable
                logger.debug(f"Reachability for {host}: {'reachable' if is_reachable else 'unreachable'}")
                if fh is not None:
                    fh.flush()
        except TimeoutError:
            logger.error(f"Reachability check timed out after {timeout} seconds")
            if fh is not None:
                fh.flush()
            for future in futures:
                if not future.done():
                    future.cancel()
    unreachable_hosts = [host for host, is_reach in reachable.items() if not is_reach]
    if unreachable_hosts:
        logger.warning(f"Unreachable hosts: {unreachable_hosts[:10]}{'...' if len(unreachable_hosts) > 10 else ''}")
    reachable_count = sum(1 for v in reachable.values() if v)
    logger.info(f"Reachability check complete: {reachable_count}/{len(reachable)} hosts reachable")
    if fh is not None:
        fh.flush()
    return reachable
def check_host_reachability_single_with_retry(host, retries=3, fh=None, port=22, timeout=5):
    """
    Check if a single host is reachable via TCP connect (default SSH port 22).
    Retries on failure.
    """
    for attempt in range(1, retries + 1):
        logger.debug(f"Attempt {attempt}/{retries} for {host} on port {port}")
        try:
            socket.create_connection((host, port), timeout=timeout)
            logger.debug(f"{host}:{port} is reachable")
            if fh is not None:
                fh.flush()
            return host, True
        except socket.timeout:
            logger.debug(f"{host}:{port} timeout")
        except ConnectionRefusedError:
            logger.debug(f"{host}:{port} connection refused")
        except socket.gaierror:
            logger.debug(f"{host} DNS resolution failed")
        except Exception as e:
            logger.debug(f"{host}:{port} error: {type(e).__name__}: {str(e)}")
        if fh is not None:
            fh.flush()
        time.sleep(1) # backoff
    logger.warning(f"{host} failed reachability after {retries} attempts")
    return host, False
# =============================================================================
# MAA AGENT LOG PARSER HELPERS (added 2026-03-29)
# =============================================================================
def get_db_connection_standalone():
    """Standalone DB connection for jobs / direct runs"""
    import os
    dsn = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
    password = os.environ.get('DB_PASSWORD')
    if not password:
        raise ValueError("DB_PASSWORD environment variable is not set")
    try:
        conn = oracledb.connect(user="maamd", password=password, dsn=dsn)
        logger.info("Standalone DB connection successful (maamd user)")
        return conn
    except Exception as e:
        logger.error(f"Standalone DB connection failed: {e}")
        raise
def get_em_agent_targets(conn):
    """DB servers + Guests ONLY - storage servers completely excluded"""
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT SYSTEM_NAME
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE SYSTEM_NAME IS NOT NULL
              AND LOWER(SYSTEM_NAME) NOT LIKE '%celadm%'
              AND LOWER(SYSTEM_NAME) NOT LIKE '%cell%'
              AND LOWER(SYSTEM_NAME) NOT LIKE '%storage%'
            UNION
            SELECT HOSTNAME FROM MAAMD.GUESTS
            ORDER BY 1
        """)
        targets = [r[0] for r in cursor.fetchall()]
        logger.info(f"EM agent targets: {len(targets)} (storage servers excluded)")
        return targets
    finally:
        cursor.close()
def cleanup_agent(hostname):
    """Remove from host + EM"""
    logger.info(f"Cleaning up bad agent on {hostname}")
    # 1. Remove from EM
    emcli_cmd = f"{config.EMCLI_PATH} delete_target -name=\"oracle_emd:{hostname}:{AGENT_PORT}\" -type=oracle_emd -delete_monitored_targets -force"
    subprocess.run(emcli_cmd, shell=True, capture_output=True)
    # 2. Remove from host
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username='oracle', timeout=15, key_filename=SSH_KEY)
        ssh.exec_command(f"rm -rf {AGENT_HOME}")
        ssh.close()
    except:
        pass
def deploy_em_agent(hostname):
    """Full push deploy via emcli submit_add_host"""
    emcli = config.EMCLI_PATH
    cmd = f'''
    {emcli} submit_add_host \
      -host_names="{hostname}" \
      -platform=226 \
      -credential_name=AGENT_HOST_CRED \
      -installation_base_directory="{AGENT_HOME}" \
      -port={AGENT_PORT} \
      -privilege_delegation_setting="sudo" \
      -privilege_credential=VM_ROOT_CRED \
      -wait_for_completion
    '''
    logger.info(f"Deploying agent to {hostname}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=900)
        if result.returncode == 0:
            logger.info(f"✓ Deployed successfully to {hostname}")
            # Run root.sh as root
            root_cmd = f"sudo {AGENT_HOME}/root.sh"
            # (executed via VM_ROOT_CRED privilege)
            return True
        else:
            logger.error(f"Deployment failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Exception: {e}")
        return False
def robust_ssh_connect(hostname, timeout=10):
    """Load your existing id_rsa + disable legacy DSA"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    paramiko.Transport._preferred_pubkeys = ('ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa')
    pkey = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
    ssh.connect(hostname, username='oracle', pkey=pkey, timeout=timeout,
                allow_agent=False, look_for_keys=False, banner_timeout=20)
    return ssh
def get_current_agent_home(hostname):
    logger.debug(f"get_current_agent_home started for {hostname}")
    if not is_host_reachable(hostname):
        logger.debug(f"{hostname} unreachable - returning None")
        return None
    try:
        ssh = robust_ssh_connect(hostname, timeout=8)
        logger.debug(f"{hostname} SSH connected")
        cmd = r'find /u01/app/oracle/em/agent_vm04 -path "*/agent_inst/*" -prune -o -name emctl -type f -executable -print 2>/dev/null | sort -V | tail -1 | xargs dirname 2>/dev/null || echo "NOT_FOUND"'
        logger.debug(f"{hostname} executing: {cmd}")
        _, stdout, stderr = ssh.exec_command(cmd)
        result = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        logger.debug(f"{hostname} result: {result}")
        if err:
            logger.debug(f"{hostname} stderr: {err}")
        ssh.close()
        logger.debug(f"{hostname} returning: {result if result != 'NOT_FOUND' else None}")
        return result if result != 'NOT_FOUND' else None
    except Exception as e:
        logger.debug(f"{hostname} error: {str(e)}")
        return None
# Constants
AGENT_BASE_DIR = "/u01/app/oracle/em/agent_vm04"
AGENT_PORT = 2410
EMCLI_PATH = config.EMCLI_PATH
SSH_KEY_PATH = config.SSH_KEY_PATH
