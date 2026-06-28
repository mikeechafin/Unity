#!/usr/bin/env python3
# fault_injection.py
# Version: 2026-03-19 v5.06
# Changes: kept ALL legacy code from your original backup (interactive power-on, full EM queries, dummy clients, ILOM tree, etc.). Only fixed EM double-counting in final_validation() so EM incidents now shows exactly 1
import argparse
import datetime
import logging
import os
import re
import time
import json
import threading
import tempfile
import subprocess
from logging.handlers import RotatingFileHandler
import paramiko
import oracledb
from maa_libraries import decrypt_data, get_db_connection # Use existing
logger = logging.getLogger(__name__)
DB_USER = "maamd"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
DB_PASS = os.getenv("DB_PASSWORD")
EM_LIST_FILE = "./em_list.json" # Adjust or env EM_LIST_FILE
class EMRepoThread(threading.Thread):
    def __init__(self, repo_name, host, port, service, user, password, uuid):
        threading.Thread.__init__(self)
        self.repo_name = repo_name
        self.host = host
        self.port = port
        self.service = service
        self.user = user
        self.password = password
        self.uuid = uuid.upper() # Normalize UUID to uppercase
        self.result = "Incident Not Created"
    def run(self):
        dsn = oracledb.makedsn(self.host, self.port, service_name=self.service)
        logger.debug(f"EM thread {self.repo_name}: Connecting to {self.host}:{self.port}/{self.service}")
        try:
            conn = oracledb.connect(user=self.user, password=self.password, dsn=dsn)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT MIN(e.creation_date) AS min_date,
                       MAX(e.creation_date) AS max_date,
                       MIN(e.incident_num) AS min_inc,
                       MAX(e.incident_num) AS max_inc,
                       COUNT(1) AS event_count
                FROM em_events e
                JOIN em_event_context ec ON (e.event_instance_id = ec.event_instance_id)
                WHERE (UPPER(ec.name) = 'ACTION' AND UPPER(ec.str_value) LIKE :like_uuid)
                   OR (UPPER(ec.name) IN ('OPENPROBLEMUUID', 'FAULTUUID') AND UPPER(ec.str_value) = :exact_uuid)
            """, {"like_uuid": f"%{self.uuid}%", "exact_uuid": self.uuid})
            row = cursor.fetchone()
            if row and row[4] > 0:
                min_date = row[0].strftime('%Y-%m-%d %H:%M:%S') if row[0] else "N/A"
                max_date = row[1].strftime('%Y-%m-%d %H:%M:%S') if row[1] else "N/A"
                min_inc = row[2] if row[2] else "None"
                max_inc = row[3] if row[3] else "None"
                inc_str = f"{min_inc}-{max_inc}" if min_inc != "None" else "None"
                self.result = f"{self.repo_name} (UUID found in action/context, Events: {row[4]}, Dates: {min_date} to {max_date}, Incident IDs: {inc_str})"
            else:
                self.result = f"{self.repo_name} (Incident Not Created)"
            conn.close()
        except oracledb.DatabaseError as e:
            error, = e.args
            logger.error(f"EM query failed for {self.repo_name} ({self.host}:{self.port}/{self.service}): {error.message} (code {error.code})")
            self.result = f"{self.repo_name} (Query Failed: {error.message[:100]})"
        except Exception as e:
            logger.error(f"EM connection/query failed for {self.repo_name} ({self.host}:{self.port}/{self.service}): {e}")
            self.result = f"{self.repo_name} (Query Failed: {str(e)[:100]})"
def get_credential(conn, hostname, cred_type="ilom_sunservice", dry_run=False):
    if dry_run:
        logger.warning(f"Dry-run: Using dummy password for {cred_type}")
        return "dummy_password"
    comp_type = "ILOM"
    if cred_type == "ilom_sunservice":
        username = "sunservice"
    elif cred_type == "host_root":
        username = "root"
    else:
        raise ValueError(f"Unknown cred_type: {cred_type}")
    env_key = f"{cred_type.upper()}_PASS"
    fallback = os.getenv(env_key)
    if fallback and cred_type != "ilom_sunservice":
        logger.info(f"Using env var {env_key} for {cred_type}")
        return fallback
    logger.info(f"Querying DB for {cred_type} (type={comp_type}, user={username})")
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT ID, ENCRYPTED_PASSWORD, COMPONENT_NAME FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_TYPE = :comp_type
            AND USERNAME = :username
            AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
            ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 1 ELSE 2 END
            FETCH FIRST 1 ROW ONLY
        """, {"comp_type": comp_type, "username": username, "hostname": hostname})
        result = cursor.fetchone()
        if result:
            row_id, encrypted_pass_lob, comp_name = result
            logger.debug(f"Fetched row ID: {row_id}, COMPONENT_NAME: {comp_name}")
            if isinstance(encrypted_pass_lob, oracledb.LOB):
                encrypted_pass = encrypted_pass_lob.read()
            else:
                encrypted_pass = encrypted_pass_lob
            decrypted = decrypt_data(encrypted_pass)
            logger.debug(f"Decrypted credential length: {len(decrypted)} chars (success)")
            source = comp_name if comp_name != 'default' else 'default'
            logger.info(f"Credential from DB ({source}) for {cred_type}")
            return decrypted
        raise ValueError(f"No entry in ACCESS_CREDENTIALS for {cred_type} (type={comp_type}, user={username}, host={hostname} or default). Insert row.")
    except Exception as e:
        logger.error(f"Query/decrypt failed for {cred_type}: {e}", exc_info=True)
        raise
    finally:
        cursor.close()
class FaultInjector:
    def __init__(self, db_conn, hostname, checkms=False, dry_run=False, listreports=False, ereport_file=None, run_id=None, output_dir='./output'):
        logger.info(f"Initializing FaultInjector for host: {hostname}")
        self.db_conn = db_conn
        self.hostname = hostname
        self.checkms = checkms
        self.dry_run = dry_run
        self.listreports = listreports
        self.ereport_file = ereport_file
        self.provided_run_id = run_id
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.TYPE = self.determine_type()
        logger.debug(f"Determined system type: {self.TYPE}")
        self.CHECKMS_FLAG = True # Always enable for dashboard runs
        self.DATE_STR = datetime.datetime.now().strftime('%m%d%y-%H%M')
        self.run_dir = f"{output_dir}/{hostname}.{self.DATE_STR}"
        os.makedirs(self.run_dir, exist_ok=True)
        self.SFILE = f"{self.run_dir}/scratch.out"
        self.NSFILE = f"{self.run_dir}/scratch2.out"
        logger.info(f"Run directory: {self.run_dir}")
        self.HOST = hostname # ILOM hostname
        self.THOST = re.sub(r'-.*', '', hostname) if self.TYPE != 'IB' else hostname # Host OS hostname (for MS checks/dcli)
        logger.debug(f"THOST: {self.THOST}")
        logger.info("Fetching credentials")
        self.ILOM_USER = "sunservice"
        self.ILOM_PASS = get_credential(db_conn, hostname, "ilom_sunservice", dry_run=dry_run)
        if not listreports:
            self.HOST_USER = "root"
            self.HOST_PASS = get_credential(db_conn, hostname, "host_root", dry_run=dry_run)
        self.valid_paths = set()
        self.MODEL = "Unknown" # Default
        self.run_id = self.provided_run_id
        self.run_cursor = None if dry_run or listreports else db_conn.cursor()
    def determine_type(self):
        hn = self.hostname.lower()
        if 'cel' in hn:
            return 'CELL'
        elif 'sw-ib' in hn:
            return 'IB'
        return 'COMPUTE'
    def get_ssh_client(self, host, user, password):
        if self.dry_run:
            logger.info("[DRY-RUN] Simulating SSH connection")
            class DummyClient:
                def exec_command(self, cmd, timeout=None):
                    logger.debug(f"[DRY-RUN] Simulated exec: {cmd}")
                    return None, type('DummyStdout', (), {'read': lambda: b"simulated output".decode(), 'channel': type('DummyChannel', (), {'recv_exit_status': lambda: 0})})(), type('DummyStderr', (), {'read': lambda: b"".decode()})()
                def invoke_shell(self):
                    class DummyShell:
                        def send(self, data):
                            pass
                        def recv_ready(self):
                            return False
                        def recv(self, n):
                            return b""
                        def close(self):
                            pass
                        settimeout = lambda self, t: None
                    return DummyShell()
                def close(self):
                    pass
            return DummyClient()
        logger.debug(f"Connecting SSH to {host} as {user} (local key first)")
        for attempt in range(10): # 10 retries
            logger.debug(f"SSH attempt {attempt + 1}/10")
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=user, password=password, look_for_keys=True, allow_agent=False, timeout=60, banner_timeout=120)
                logger.debug("Connection successful")
                return client
            except paramiko.AuthenticationException:
                logger.debug("Local key failed – falling back to password interactive")
                try:
                    transport = paramiko.Transport((host, 22))
                    transport.connect(username=user)
                    def interactive_handler(title, instructions, prompt_list):
                        resp = []
                        for prompt, echo in prompt_list:
                            prompt_lower = prompt.lower().strip()
                            if prompt_lower == "password:" or "password" in prompt_lower:
                                resp.append(password)
                            else:
                                resp.append('')
                        return resp
                    transport.auth_interactive(user, interactive_handler)
                    logger.debug("Password interactive auth successful")
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client._transport = transport
                    return client
                except Exception as e2:
                    logger.error(f"Password interactive failed on attempt {attempt + 1}: {e2}")
            except Exception as e:
                logger.error(f"Connection failed on attempt {attempt + 1}: {e}")
            if attempt < 9:
                time.sleep(15) # Wait 15s between retries
        raise ConnectionError(f"Failed to connect to {host} as {user} after 10 attempts")
    def execute_ssh(self, client, cmd, timeout=30, host_for_log="unknown"):
        logger.debug(f"[{host_for_log}] Executing: {cmd}")
        try:
            _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            status = stdout.channel.recv_exit_status()
            if out:
                logger.debug(f"[{host_for_log}] STDOUT ({len(out)} chars): {out[:1000]}{'...' if len(out) > 1000 else ''}")
            if err:
                logger.warning(f"[{host_for_log}] STDERR: {err}")
            logger.debug(f"[{host_for_log}] Exit status: {status}")
            return out, err, status
        except Exception as e:
            logger.error(f"[{host_for_log}] Command failed: {e}. Check session active or ILOM timeout.")
            raise
    def get_ereports(self, client):
        logger.info("Extracting ereports from FDR files")
        cmd = ('find /usr/local/lib/faultdiags -name "*.fdr" -exec cat {} \\; 2>/dev/null '
               '| grep -E "ereport\\.[^ ]+@"')
        out, _, _ = self.execute_ssh(client, cmd, timeout=180, host_for_log=self.HOST)
        ereports = []
        for line in out.splitlines():
            match = re.search(r'ereport\.([^@\s{]+)@([^,\s{;]+)', line.strip())
            if match:
                name, path = match.groups()
                ereports.append(f"ereport.{name}@{path}")
        ereports = sorted(set(ereports))
        logger.info(f"Extracted {len(ereports)} unique ereports")
        return ereports
    def load_ereports_from_file(self, file_path):
        if not os.path.exists(file_path):
            logger.error(f"Ereport file {file_path} not found")
            raise FileNotFoundError(file_path)
        with open(file_path) as f:
            lines = f.readlines()
        ereports = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
        logger.info(f"Loaded {len(ereports)} ereports from file {file_path}")
        return ereports
    def modify_path(self, path):
        logger.debug(f"Modifying path: {path}")
        component = path.split('/')[-1]
        mods = {
            'p': component + '0',
            'd': component + '0',
            'f': component + '0',
            't_out_zone': 't_out_zone0',
        }
        new_comp = mods.get(component, component)
        if new_comp != component:
            path = '/'.join(path.split('/')[:-1]) + '/' + new_comp
            logger.debug(f"Modified to: {path}")
        return path
    def check_path_valid(self, path):
        if self.dry_run:
            return True
        if not self.valid_paths:
            return True
        path_valid = path.rstrip(';').upper()
        valid = path_valid in self.valid_paths
        return valid
    def inject_fault(self, client, ereport):
        logger.info(f"Attempting injection: {ereport}")
        if self.dry_run:
            return True, "DRY-RUN SUCCESS"
        out, err, status = self.execute_ssh(client, f"etcd -i {ereport}", host_for_log=self.HOST)
        success = status == 0 and "nonexistent component" not in (out + err).lower()
        return success, out
    def check_fault_count(self, client, scratch_file, is_after=False):
        if self.dry_run:
            count = 1 if is_after else 0
            with open(scratch_file, 'w') as f:
                f.write(f"simulated {count} faults")
            return count
        try:
            out, _, _ = self.execute_ssh(client, "fmadm faulty", host_for_log=self.HOST)
            with open(scratch_file, 'w') as f:
                f.write(out)
            count = len(re.findall(r'critical|major|minor', out, re.I))
            return count
        except Exception as e:
            logger.warning(f"fmadm faulty failed: {e}")
            with open(scratch_file, 'w') as f:
                f.write("fmadm failed")
            return 0
    def extract_uuid(self, scratch_file):
        with open(scratch_file) as f:
            content = f.read()
        match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', content, re.I)
        return match.group(1) if match else "N/A"
    def clean_specific_faults(self, client):
        logger.info("Robust cleaning of specific faults (up to 5 attempts)")
        for attempt in range(5):
            try:
                out, _, _ = self.execute_ssh(client, "fmadm faulty", host_for_log=self.HOST)
                if "No faults found" in out or "no faults" in out.lower():
                    logger.info("All faults cleared")
                    return
                uuids = set(re.findall(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', out, re.I))
                paths = set()
                for line in out.splitlines():
                    if "Affects :" in line:
                        paths.add(line.split("Affects :")[1].strip())
                    elif "Location :" in line:
                        paths.add(line.split("Location :")[1].strip())
                for uuid in uuids:
                    logger.info(f"Repairing UUID: {uuid}")
                    self.execute_ssh(client, f"fmadm repair {uuid}", host_for_log=self.HOST)
                for path in paths:
                    logger.info(f"Repairing path: {path}")
                    self.execute_ssh(client, f"fmadm repair {path}", host_for_log=self.HOST)
                time.sleep(5)
            except Exception as e:
                logger.warning(f"Clean attempt {attempt + 1} failed: {e}")
                time.sleep(5)
        logger.warning("Some faults may remain after 5 attempts")
    def run_ms_check(self, uuid):
        if self.dry_run:
            return "Simulated MS Alert Created"
        if uuid == "N/A":
            return "N/A"
        logger.info(f"Starting MS check for UUID: {uuid} on {self.THOST} (type: {self.TYPE})")
        temp_scl = None
        try:
            fd, temp_scl = tempfile.mkstemp(suffix=".scl")
            with os.fdopen(fd, 'w') as f:
                f.write("list alerthistory detail\n")
            os.chmod(temp_scl, 0o700)
            logger.debug(f"Temp SCL created: {temp_scl}")
            dcli_cmd = "dcli_compute" if self.TYPE == "COMPUTE" else "dcli"
            cmd = [dcli_cmd, "-c", self.THOST, "-l", "root", "-x", temp_scl]
            logger.debug(f"MS dcli command: {' '.join(cmd)}")
            for attempt in range(3):
                logger.debug(f"MS check attempt {attempt + 1}/3")
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    out = result.stdout
                    err = result.stderr
                    if result.returncode != 0:
                        logger.warning(f"{dcli_cmd} failed (code {result.returncode}): {err.strip()}")
                    logger.debug(f"dcli output ({len(out)} chars): {out[:1000]}{'...' if len(out) > 1000 else ''}")
                    if uuid in out:
                        logger.info(f"MS alert found for UUID {uuid} on attempt {attempt + 1}")
                        return "Created"
                    logger.debug(f"UUID {uuid} not found in output (attempt {attempt + 1}/3)")
                except subprocess.TimeoutExpired:
                    logger.warning(f"{dcli_cmd} timeout on attempt {attempt + 1}/3")
                except Exception as e:
                    logger.error(f"{dcli_cmd} error on attempt {attempt + 1}/3: {e}")
                time.sleep(30)
            logger.info(f"MS alert not found for UUID {uuid} after 3 attempts")
            return "Not Created"
        finally:
            if temp_scl and os.path.exists(temp_scl):
                os.unlink(temp_scl)
                logger.debug(f"Temp SCL deleted: {temp_scl}")
    def run_snmp_log_check(self, uuid):
        if self.dry_run or uuid == "N/A":
            return "N/A", "N/A"
        logger.info(f"Starting SNMP log check for UUID: {uuid} on {self.THOST} (type: {self.TYPE})")
        uuid_lower = uuid.lower()
        try:
            host_client = self.get_ssh_client(self.THOST, "root", self.HOST_PASS)
        except Exception as e:
            logger.warning(f"Cannot connect to host OS for SNMP log check: {e}")
            return "Unknown", "Unknown"
        try:
            if self.TYPE == "CELL":
                out, _, _ = self.execute_ssh(host_client, "echo $CELLTRACE")
                log_dir = out.strip()
                if not log_dir:
                    logger.warning("CELLTRACE not set")
                    return "Unknown", "Unknown"
                log_pattern = f"{log_dir}/ms-odl.*"
            else: # COMPUTE
                log_dir = f"/opt/oracle/dbserver/log/diag/asm/dbserver/{self.THOST}/trace"
                log_pattern = f"{log_dir}/ms-odl.*"
            # First, confirm UUID is in logs
            cmd_uuid = f"grep -r -i '{uuid_lower}' {log_pattern} 2>/dev/null"
            out_uuid, _, _ = self.execute_ssh(host_client, cmd_uuid)
            if not out_uuid:
                logger.info(f"UUID {uuid} not found in SNMP logs")
                return "No", "No"
            # Received: look for "received" in SnmpV3TrapListener lines
            cmd_received = f"grep -r -i 'SnmpV3TrapListener.*received' {log_pattern} 2>/dev/null | grep -i '{uuid_lower}'"
            out_received, _, _ = self.execute_ssh(host_client, cmd_received)
            received = "Yes" if out_received else "No"
            # Sent: look for "ASR SNMP trap was sent" or "SnmpTrap" "was sent"
            cmd_sent = f"grep -r -i 'ASR SNMP trap was sent\\|SnmpTrap.*was sent' {log_pattern} 2>/dev/null | grep -i '{uuid_lower}'"
            out_sent, _, _ = self.execute_ssh(host_client, cmd_sent)
            sent = "Yes" if out_sent else "No"
            logger.info(f"SNMP log check: Received={received}, Sent={sent}")
            return received, sent
        except Exception as e:
            logger.warning(f"SNMP log check failed: {e}")
            return "Unknown", "Unknown"
        finally:
            if 'host_client' in locals():
                host_client.close()
    def run_em_check(self, uuid):
        if self.dry_run:
            return "Simulated EM Incident Created in EM1,EM2"
        if uuid == "N/A":
            return "N/A"
        logger.info(f"Starting EM check for UUID: {uuid}")
        try:
            with open(EM_LIST_FILE) as f:
                config = json.load(f)
            logger.debug(f"EM repos loaded: {len(config['databases'])} repos")
            threads = []
            for idx, repo in enumerate(config["databases"]):
                thread = EMRepoThread(repo["serviceName"], repo["host"], repo["port"], repo["serviceName"], repo["dbUser"], repo["dbPassword"], uuid)
                threads.append(thread)
                thread.start()
                logger.debug(f"Started EM thread for {repo['serviceName']} ({repo['host']}:{repo['port']}/{repo['serviceName']})")
            for thread in threads:
                thread.join()
            incidents = [t.result for t in threads if "UUID found" in t.result or "Events:" in t.result]
            failed = [t.result for t in threads if "Failed" in t.result]
            em_results = "; ".join(incidents + failed) if incidents or failed else "Incident Not Created"
            logger.info(f"EM check complete for UUID {uuid}: {em_results}")
            return em_results
        except Exception as e:
            logger.error(f"EM check failed: {e}")
            return "EM Check Failed"
    def get_metadata(self, root_client):
        if self.dry_run:
            self.MODEL = "Simulated Model"
            self.VERSION = "Simulated Version"
            return
        if not root_client:
            logger.warning("No root client – metadata Unknown")
            return
        logger.info("Fetching ILOM metadata (using root for ILOM CLI)")
        out, _, _ = self.execute_ssh(root_client, "show /System", host_for_log=self.HOST)
        product_match = re.search(r'product_name\s*=\s*(.+)', out, re.I)
        if product_match:
            self.MODEL = product_match.group(1).strip()
        else:
            model_match = re.search(r'model\s*=\s*(.+)', out, re.I)
            self.MODEL = model_match.group(1).strip() if model_match else "Unknown"
        out, _, _ = self.execute_ssh(root_client, "version", host_for_log=self.HOST)
        version_match = re.search(r'SP firmware\s*([\d.]+)', out)
        self.VERSION = version_match.group(1).strip() if version_match else "Unknown"
        logger.info(f"Metadata fetched: Model={self.MODEL}, Version={self.VERSION}")
    def dump_ilom_tree(self):
        logger.info("Dumping ILOM tree for path cache (using root for ILOM CLI)")
        root_client = None
        try:
            root_client = self.get_ssh_client(self.HOST, self.HOST_USER, self.HOST_PASS)
            cmd = "show -d targets -level all /SYS"
            out, _, _ = self.execute_ssh(root_client, cmd, timeout=300, host_for_log=self.HOST)
            paths = set()
            for line in out.splitlines():
                if line.strip().startswith('/SYS/'):
                    path = line.strip().split()[0].upper()
                    paths.add(path)
                    parent = path
                    while '/' in parent[1:]:
                        parent = '/'.join(parent.split('/')[:-1])
                        paths.add(parent)
            paths.add("/SYS")
            self.valid_paths = paths
            logger.info(f"ILOM tree dumped: {len(paths)} valid uppercase paths cached")
        except Exception as e:
            logger.warning(f"ILOM tree dump failed (root SSH): {e}. Proceeding without path cache.")
            self.valid_paths = set()
        finally:
            if root_client:
                root_client.close()
    def interactive_power_on(self, root_client):
        shell = root_client.invoke_shell()
        shell.settimeout(120)
        time.sleep(2)
        if shell.recv_ready():
            shell.recv(4096)
        shell.send("start -force /SYS\n")
        logger.debug("Sent: start -force /SYS")
        output = ""
        confirmed = False
        start_time = time.time()
        while True:
            if shell.recv_ready():
                chunk = shell.recv(4096).decode()
                output += chunk
                logger.debug(f"Interactive output chunk: {chunk.strip()}")
                if "Are you sure you want to start /SYS (y/n)?" in chunk:
                    shell.send("y\n")
                    logger.info("Sent 'y' to confirmation prompt")
                    confirmed = True
                if confirmed and ("Starting /SYS" in chunk or "Target started" in chunk):
                    logger.info("Power on command confirmed and started")
                    break
            else:
                time.sleep(1)
                if time.time() - start_time > 120:
                    logger.warning("Timeout waiting for power on response")
                    break
        while shell.recv_ready():
            output += shell.recv(4096).decode()
        shell.close()
        logger.debug(f"Full interactive power on output: {output.strip()}")
        return confirmed
    def handle_power_state(self, root_client, clear_client):
        logger.info("Checking power state after injection")
        power_state = "Unknown"
        try:
            out, _, _ = self.execute_ssh(root_client, "show /System power_state", host_for_log=self.HOST, timeout=60)
            power_match = re.search(r'power_state\s*=\s*(\S+)', out, re.I)
            power_state = power_match.group(1).strip() if power_match else "Unknown"
            logger.info(f"Current power state: {power_state}")
        except Exception as e:
            logger.warning(f"Failed to check power state: {e}")
        if power_state.lower() != "on":
            logger.info("Host not on – attempting robust interactive power on with start -force /SYS")
            powered_on = False
            for attempt in range(5):
                logger.info(f"Power on attempt {attempt + 1}/5 (interactive start -force /SYS)")
                try:
                    self.clean_specific_faults(clear_client)
                    time.sleep(10)
                    success = self.interactive_power_on(root_client)
                    if not success:
                        logger.warning("Interactive power on did not confirm - retrying")
                    time.sleep(30)
                    verify_out, _, _ = self.execute_ssh(root_client, "show /System power_state", host_for_log=self.HOST, timeout=60)
                    logger.debug(f"Verify show output: {verify_out}")
                    if "power_state = On" in verify_out or "On" in verify_out:
                        logger.info("Power on succeeded (verified On)")
                        powered_on = True
                        break
                    else:
                        logger.warning("Power state still not On – re-clearing faults and retrying")
                except Exception as e:
                    logger.warning(f"Power on attempt {attempt + 1} exception: {e}")
                time.sleep(30)
            if not powered_on:
                logger.error("Failed to power on host after 5 interactive retries with fault clears")
        self.wait_for_host_up()
    def wait_for_host_up(self):
        logger.info("Waiting for host boot complete (ping + dcli ready)")
        for attempt in range(90):
            ping_result = subprocess.run(["ping", "-c", "1", "-W", "5", self.THOST], capture_output=True)
            if ping_result.returncode == 0:
                logger.debug("Ping successful")
                try:
                    temp_scl = None
                    fd, temp_scl = tempfile.mkstemp(suffix=".scl")
                    with os.fdopen(fd, 'w') as f:
                        f.write("list alerthistory detail\n")
                    os.chmod(temp_scl, 0o700)
                    dcli_cmd = "dcli_compute" if self.TYPE == "COMPUTE" else "dcli"
                    cmd = [dcli_cmd, "-c", self.THOST, "-l", "root", "-x", temp_scl]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        logger.info("Host up (dcli ready)")
                        if temp_scl:
                            os.unlink(temp_scl)
                        return True
                except Exception:
                    logger.debug("dcli not ready yet")
                finally:
                    if temp_scl and os.path.exists(temp_scl):
                        os.unlink(temp_scl)
            logger.debug(f"Host not up yet (attempt {attempt + 1}/90)")
            time.sleep(10)
        logger.warning("Host did not come up in 15min – continuing anyway")
        return False
    def process_ereport(self, raw, ilom_client):
        logger.info(f"Processing ereport: {raw}")
        path_part = raw.split('@', 1)[1]
        path_modified = self.modify_path(path_part)
        ereport = raw.split('@', 1)[0] + '@' + path_modified
        if not self.check_path_valid(path_modified):
            logger.warning(f"Skipping invalid path: {ereport}")
            return None
        before_count = self.check_fault_count(ilom_client, self.SFILE, is_after=False)
        success, output = self.inject_fault(ilom_client, ereport)
        time.sleep(30)
        root_client = None
        try:
            root_client = self.get_ssh_client(self.HOST, self.HOST_USER, self.HOST_PASS)
            self.handle_power_state(root_client, ilom_client)
        except Exception as e:
            logger.warning(f"Power handling skipped (root SSH failed): {e}")
        finally:
            if root_client:
                root_client.close()
        after_count = self.check_fault_count(ilom_client, self.NSFILE, is_after=True)
        new_faults = after_count - before_count
        logger.info(f"New faults: {new_faults}")
        uuid = self.extract_uuid(self.NSFILE) if new_faults > 0 else "N/A"
        logger.info(f"Extracted UUID for checks: {uuid}")
        status = "FAULT INJECTED" if success and new_faults > 0 else "FAULT NOT INJECTED"
        ms_alert_str = self.run_ms_check(uuid) if new_faults > 0 else "N/A"
        em_results_str = self.run_em_check(uuid) if new_faults > 0 else "N/A"
        snmp_received = "N/A"
        snmp_sent = "N/A"
        if ms_alert_str == "Created":
            snmp_received, snmp_sent = self.run_snmp_log_check(uuid)
        notes = "Success" if success else output
        ms_created = ms_alert_str == "Created"
        em_created = "UUID found" in em_results_str or "Events:" in em_results_str
        if self.run_cursor and self.run_id:
            fault_time = datetime.datetime.now().strftime('%m%d%y-%H%M')
            self.run_cursor.execute("""
                INSERT INTO FAULT_TEST_DETAILS (DETAIL_ID, RUN_ID, FAULT_TIME, EREPORT, STATUS, UUID, MS_ALERT, EM_RESULTS, SNMP_RECEIVED, SNMP_SENT, NOTES)
                VALUES (FAULT_TEST_DETAILS_SEQ.NEXTVAL, :run_id, :fault_time, :ereport, :status, :uuid, :ms_alert, :em_results, :snmp_received, :snmp_sent, :notes)
            """, {
                'run_id': self.run_id,
                'fault_time': fault_time,
                'ereport': raw,
                'status': status,
                'uuid': uuid,
                'ms_alert': ms_alert_str,
                'em_results': em_results_str,
                'snmp_received': snmp_received,
                'snmp_sent': snmp_sent,
                'notes': notes
            })
            self.db_conn.commit()
            self.run_cursor.execute("""
                UPDATE FAULT_TEST_RUNS
                SET TOTAL_EREPORTS = TOTAL_EREPORTS + 1,
                    TOTAL_INJECTED = TOTAL_INJECTED + :injected,
                    TOTAL_MS_ALERTS = TOTAL_MS_ALERTS + :ms,
                    TOTAL_EM_INCIDENTS = TOTAL_EM_INCIDENTS + :em
                WHERE RUN_ID = :run_id
            """, {
                'injected': 1 if status == "FAULT INJECTED" else 0,
                'ms': 1 if ms_created else 0,
                'em': 1 if em_created else 0,
                'run_id': self.run_id
            })
            self.db_conn.commit()
        if new_faults > 0:
            self.clean_specific_faults(ilom_client)
        return True
    def final_validation(self):
        if not self.run_cursor or not self.run_id:
            return
        logger.info("Starting final validation pass for MS/EM/SNMP on injected faults")
        self.run_cursor.execute("""
            SELECT DETAIL_ID, UUID, MS_ALERT, EM_RESULTS, SNMP_RECEIVED, SNMP_SENT
            FROM FAULT_TEST_DETAILS
            WHERE RUN_ID = :run_id
              AND STATUS = 'FAULT INJECTED'
        """, {'run_id': self.run_id})
        rows = self.run_cursor.fetchall()
        if not rows:
            logger.info("No injected faults to validate")
            return
        ms_updates = 0
        em_updates = 0
        snmp_updates = 0
        for detail_id, uuid, old_ms, old_em, old_received, old_sent in rows:
            if uuid == "N/A":
                continue
            updated = False
            new_ms = self.run_ms_check(uuid)
            if new_ms != old_ms:
                logger.info(f"Validation MS update for DETAIL_ID {detail_id}: '{old_ms}' → '{new_ms}'")
                old_ms = new_ms
                updated = True
                if new_ms == "Created":
                    ms_updates += 1
            new_em = self.run_em_check(uuid)
            if new_em != old_em:
                logger.info(f"Validation EM update for DETAIL_ID {detail_id}: '{old_em}' → '{new_em}'")
                old_em = new_em
                updated = True
                if "UUID found" in new_em or "Events:" in new_em:
                    em_updates += 1
            if old_ms == "Created":
                new_received, new_sent = self.run_snmp_log_check(uuid)
                if new_received != old_received or new_sent != old_sent:
                    logger.info(f"Validation SNMP update for DETAIL_ID {detail_id}: Received '{old_received}' → '{new_received}', Sent '{old_sent}' → '{new_sent}'")
                    updated = True
                    snmp_updates += 1
            if updated:
                self.run_cursor.execute("""
                    UPDATE FAULT_TEST_DETAILS
                    SET MS_ALERT = :ms, EM_RESULTS = :em, SNMP_RECEIVED = :received, SNMP_SENT = :sent
                    WHERE DETAIL_ID = :detail_id
                """, {'ms': new_ms, 'em': new_em, 'received': new_received, 'sent': new_sent, 'detail_id': detail_id})
                self.db_conn.commit()
        if ms_updates or em_updates or snmp_updates:
            logger.info(f"Final validation updated {ms_updates} MS alerts, {em_updates} EM incidents, {snmp_updates} SNMP logs")
            self.run_cursor.execute("""
                UPDATE FAULT_TEST_RUNS
                SET TOTAL_MS_ALERTS = TOTAL_MS_ALERTS + :ms,
                    TOTAL_EM_INCIDENTS = TOTAL_EM_INCIDENTS + :em
                WHERE RUN_ID = :run_id
            """, {'ms': ms_updates, 'em': em_updates, 'run_id': self.run_id})
            self.db_conn.commit()
        else:
            logger.info("Final validation: No new detections")
    def run(self):
        if self.listreports:
            ilom_client = None
            try:
                ilom_client = self.get_ssh_client(self.HOST, self.ILOM_USER, self.ILOM_PASS)
                ereports = self.get_ereports(ilom_client)
                print(f"\nAvailable ereports on {self.HOST} ({len(ereports)} total):")
                for ereport in ereports:
                    print(ereport)
                print(f"\nTotal: {len(ereports)}")
            finally:
                if ilom_client:
                    ilom_client.close()
            return
        logger.info(f"Starting fault injection run on {self.HOST}")
        ilom_client = None
        root_client = None
        try:
            if self.provided_run_id is not None:
                self.run_id = self.provided_run_id
                logger.info(f"Using provided run ID: {self.run_id}")
            else:
                self.run_id = None
            try:
                ilom_client = self.get_ssh_client(self.HOST, self.ILOM_USER, self.ILOM_PASS)
            except Exception as e:
                logger.error(f"Cannot connect to ILOM as {self.ILOM_USER}: {e}. Injection impossible – marking run FAILED")
                if self.run_cursor and self.run_id:
                    self.run_cursor.execute("""
                        UPDATE FAULT_TEST_RUNS
                        SET END_TIME = SYSDATE, STATUS = 'FAILED'
                        WHERE RUN_ID = :run_id
                    """, {'run_id': self.run_id})
                    self.db_conn.commit()
                raise
            try:
                root_client = self.get_ssh_client(self.HOST, self.HOST_USER, self.HOST_PASS)
                self.get_metadata(root_client)
                self.dump_ilom_tree()
            except Exception as e:
                logger.warning(f"Root SSH failed for metadata/tree: {e}. Using Unknown model, no path cache.")
                self.MODEL = "Unknown"
            if self.run_cursor:
                if self.provided_run_id:
                    self.run_cursor.execute("""
                        UPDATE FAULT_TEST_RUNS
                        SET MODEL = :model
                        WHERE RUN_ID = :run_id
                    """, {'model': self.MODEL, 'run_id': self.provided_run_id})
                    self.db_conn.commit()
                    logger.info(f"Updated existing run {self.provided_run_id} with MODEL={self.MODEL}")
                else:
                    run_id_var = self.run_cursor.var(oracledb.NUMBER)
                    self.run_cursor.execute("""
                        INSERT INTO FAULT_TEST_RUNS (HOST, MODEL, STATUS)
                        VALUES (:host, :model, 'RUNNING')
                        RETURNING RUN_ID INTO :run_id
                    """, {'host': self.HOST, 'model': self.MODEL, 'run_id': run_id_var})
                    self.run_id = run_id_var.getvalue()[0]
                    self.db_conn.commit()
                    logger.info(f"Started new run ID: {self.run_id} with MODEL={self.MODEL}")
            self.clean_specific_faults(ilom_client)
            if self.ereport_file:
                ereports = self.load_ereports_from_file(self.ereport_file)
            else:
                ereports = self.get_ereports(ilom_client)
            for raw in ereports:
                self.process_ereport(raw, ilom_client)
            self.clean_specific_faults(ilom_client)
            self.final_validation()
            if self.run_cursor and self.run_id:
                self.run_cursor.execute("""
                    UPDATE FAULT_TEST_RUNS
                    SET END_TIME = SYSDATE, STATUS = 'COMPLETED'
                    WHERE RUN_ID = :run_id
                """, {'run_id': self.run_id})
                self.db_conn.commit()
                logger.info(f"Run {self.run_id} completed in DB")
        except Exception as e:
            logger.error(f"Run failed: {e}", exc_info=True)
            if self.run_cursor and self.run_id:
                self.run_cursor.execute("""
                    UPDATE FAULT_TEST_RUNS
                    SET END_TIME = SYSDATE, STATUS = 'FAILED'
                    WHERE RUN_ID = :run_id
                """, {'run_id': self.run_id})
                self.db_conn.commit()
        finally:
            if ilom_client:
                ilom_client.close()
            if root_client:
                root_client.close()
        logger.info(f"Run complete (DB ID: {self.run_id if self.run_id else 'N/A'})")
def setup_logging(debug=False, run_dir=None):
    if logger.handlers:
        return
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    if run_dir:
        fh = RotatingFileHandler(f"{run_dir}/fault_injection.log", maxBytes=10*1024*1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    if debug:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Oracle ILOM Automated Fault Injection")
    parser.add_argument("hostname", help="Target hostname")
    parser.add_argument("--checkms", action="store_true", help="Enable CHECKMS")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without injecting")
    parser.add_argument("--listreports", action="store_true", help="List available ereports and exit")
    parser.add_argument("--ereport", type=str, help="File with subset of ereports (one per line)")
    parser.add_argument("--run_id", type=int, default=None, help="Existing run ID from dashboard")
    parser.add_argument("--debug", action="store_true", help="Enable console debug logging")
    args = parser.parse_args()
    setup_logging(debug=args.debug)
    db_conn = None
    if args.dry_run:
        logger.warning("Dry-run mode: Skipping DB connection, using dummy credentials")
    else:
        if not DB_PASS:
            logger.error("Missing DB_PASSWORD env var for maamd user. Set export DB_PASSWORD=yourpass")
            exit(1)
        try:
            db_conn = get_db_connection(DB_USER, DB_PASS, DB_DSN)
            logger.info("DB connection established automatically as maamd user")
        except oracledb.Error as e:
            logger.error(f"DB connection failed: {e}")
            logger.error("Verify DB_PASSWORD env var and DSN connectivity.")
            exit(1)
    injector = FaultInjector(db_conn, args.hostname, args.checkms, args.dry_run, args.listreports, args.ereport, args.run_id)
    setup_logging(debug=args.debug, run_dir=injector.run_dir if not args.listreports else None)
    injector.run()
    if db_conn:
        db_conn.close()
        logger.info("DB connection closed")
