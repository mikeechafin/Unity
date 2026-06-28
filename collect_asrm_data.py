#!/usr/bin/env python3

import paramiko
import logging
import queue
import re
import os
import oracledb
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import QueueHandler, QueueListener

SSH_KEY = "/home/maatest/.ssh/id_rsa"
MCHAFIN_PASSWORD = "$RFV3edc"
ROOT_PASSWORD="welcome2"
DB_USER = "maamd"
DB_PASSWORD = "welcome2"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
import config

OUTPUT_FILE = os.path.join(config.OUTPUT_DIR, 'collect_asrm_data.log')
MAX_WORKERS = 5
SSH_TIMEOUT = 15
SSH_RETRIES = 2

logger = logging.getLogger('collect_asrm_data')

logger.setLevel(logging.DEBUG)
log_queue = queue.Queue(-1)
queue_handler = QueueHandler(log_queue)
fh = logging.FileHandler(OUTPUT_FILE)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
fh.setFormatter(formatter)
logger.addHandler(queue_handler)
logger.propagate = False



def setup_ssh_key(client, hostname, username):
    client.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    pub_key_path = SSH_KEY + ".pub"
    if not os.path.isfile(pub_key_path):
        return False
    with open(pub_key_path, "r") as f:
        pub_key = f.read().strip()
    cmd = f"echo '{pub_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    stdin, stdout, stderr = client.exec_command(cmd)
    return stdout.channel.recv_exit_status() == 0

def get_ssh_client(username, hostname):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    password = MCHAFIN_PASSWORD if username == "mchafin" else ROOT_PASSWORD

    for attempt in range(SSH_RETRIES):
        try:
            if os.path.isfile(SSH_KEY):
                pkey = paramiko.RSAKey.from_private_key_file(SSH_KEY)
                client.connect(hostname, username=username, pkey=pkey, allow_agent=False, look_for_keys=False, timeout=SSH_TIMEOUT)
                client.get_transport().set_keepalive(60)
                return client
            else:
                raise FileNotFoundError
        except Exception as e:
            if attempt == SSH_RETRIES - 1:
                try:
                    fallback_user = "root" if username != "root" else username
                    client.connect(hostname, username=fallback_user, password=ROOT_PASSWORD, allow_agent=False, look_for_keys=False, timeout=SSH_TIMEOUT)
                    client.get_transport().set_keepalive(60)
                    if username == "mchafin" and fallback_user == "root":
                        setup_ssh_key(client, hostname, username)
                    return client
                except Exception:
                    return None
            time.sleep(5)
    return None

def get_asr_home(client, hostname):
    stdin, stdout, stderr = client.exec_command("ps -ef | grep -i asr | grep -v grep")
    ps_output = stdout.read().decode().strip()
    if not ps_output:
        return None
    match = re.search(r'-Dlog4j\.configurationFile=(/opt/asrmanager)/configuration/log4j2\.xml', ps_output)
    if match:
        asr_home = match.group(1)
        stdin, stdout, stderr = client.exec_command(f"test -f {asr_home}/bin/asr && echo 'exists'")
        if stdout.read().decode().strip() == "exists":
            return asr_home
    return None

def parse_asr_output(output, hostname):
    assets = []
    lines = output.splitlines()
    current_parent_serial = None

    for line in lines:
        line = line.strip()
        if not line or "IP_ADDRESS" in line or "--------" in line or "Please use My Oracle Support" in line or "To view the latest" in line:
            continue
        
        if ".SYSTEM." in line:
            match = re.search(r'\.SYSTEM\.\s+(\S+)', line)
            if match:
                current_parent_serial = match.group(1)
            continue

        fields = re.split(r'\s+', line.strip())
        if len(fields) < 10:
            continue

        ip_address = fields[0]
        host_name = fields[1]
        serial_number = fields[2]
        parent_serial = current_parent_serial if fields[3] == "............." else fields[3]
        asr = fields[4]
        asr_status = fields[5]
        protocol = fields[6]
        source = fields[7]

        if fields[8] == "NA":
            last_heartbeat = None
            product_name = " ".join(fields[9:])
        else:
            time_pattern = r'^\d{2}:\d{2}:\d{2}(\.\d+)?$'
            if len(fields) > 10 and re.match(time_pattern, fields[9]):
                last_heartbeat = " ".join(fields[8:10])
                product_name = " ".join(fields[10:])
            else:
                last_heartbeat = fields[8]
                product_name = " ".join(fields[9:])

        assets.append({
            "IP_ADDRESS": ip_address,
            "HOST_NAME": host_name,
            "SERIAL_NUMER": serial_number,
            "PARENT_SERIAL": parent_serial,
            "ASR": asr,
            "ASR_STATUS": asr_status,
            "PROTOCOL": protocol,
            "SOURCE": source,
            "LAST_HEARTBEAT": last_heartbeat,
            "PRODUCT_NAME": product_name,
            "ASRM_HOSTNAME": hostname
        })

    return assets

def parse_asr_status(output):
    status_match = re.search(r'ASR Manager \(pid \d+\) is (\w+)', output)
    return status_match.group(1).lower() if status_match else "unknown"

def parse_reg_status(output):
    return output.strip()

def parse_version(output):
    version_match = re.search(r'ASR Manager version[:\s]*(.+)', output, re.IGNORECASE)
    return version_match.group(1).strip().split('\n')[0] if version_match else "unknown"

def parse_mos_backend(output):
    backend_match = re.search(r'Connecting to endpoint @ (https://[^ \n]+)', output)
    return backend_match.group(1) if backend_match else "unknown"

def collect_asr_data(hostname, asr_user):
    client = get_ssh_client(asr_user, hostname)
    if not client:
        return []

    try:
        asr_home = get_asr_home(client, hostname)
        if not asr_home:
            client.close()
            return []

        asr_command = f"{asr_home}/bin/asr list_asset"
        if asr_user == "mchafin":
            command = f"echo '{MCHAFIN_PASSWORD}' | sudo -S {asr_command}"
            stdin, stdout, stderr = client.exec_command(command)
            stdin.write(f"{MCHAFIN_PASSWORD}\n")
            stdin.flush()
        else:
            stdin, stdout, stderr = client.exec_command(asr_command)

        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        if exit_status != 0:
            client.close()
            return []

        assets = parse_asr_output(output, hostname)

        commands = {
            "status": f"{asr_home}/bin/asr status",
            "reg_status": f"{asr_home}/bin/asr show_reg_status",
            "version": f"{asr_home}/bin/asr show_version",
            "test_connection": f"{asr_home}/bin/asr test_connection"
        }

        asr_info = {}
        for cmd_name, cmd in commands.items():
            if asr_user == "mchafin":
                cmd = f"echo '{MCHAFIN_PASSWORD}' | sudo -S {cmd}"
            stdin, stdout, stderr = client.exec_command(cmd)
            if asr_user == "mchafin":
                stdin.write(f"{MCHAFIN_PASSWORD}\n")
                stdin.flush()
            
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            if exit_status != 0:
                asr_info[cmd_name] = "unknown"
            else:
                if cmd_name == "status":
                    asr_info[cmd_name] = parse_asr_status(output)
                elif cmd_name == "reg_status":
                    asr_info[cmd_name] = parse_reg_status(output)
                elif cmd_name == "version":
                    asr_info[cmd_name] = parse_version(output)
                elif cmd_name == "test_connection":
                    asr_info[cmd_name] = parse_mos_backend(output)

        asr_manager_data = {
            "hostname": hostname,
            "asr_user": asr_user,
            "status": asr_info["status"],
            "reg_status": asr_info["reg_status"],
            "version": asr_info["version"],
            "mos_backend": asr_info["test_connection"],
            "assets": assets
        }

        client.close()
        return [asr_manager_data]

    except Exception:
        return []
    finally:
        if client:
            client.close()

def get_asr_managers():
    try:
        with oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT hostname, asr_user FROM maamd.asrm WHERE hostname IS NOT NULL AND asr_user IS NOT NULL")
            return cursor.fetchall()
    except oracledb.Error:
        return []

def save_asr_data(asr_data_list):
    if not asr_data_list:
        return
    
    with oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN) as conn:
        cursor = conn.cursor()
        
        asrm_data = [
            (
                data["hostname"],
                data["mos_backend"],
                data["asr_user"],
                data["version"],
                data["reg_status"],
                data["status"]
            ) for data in asr_data_list
        ]
        cursor.executemany("""
            BEGIN
                INSERT INTO maamd.asrm (
                    hostname, mos_backend, asr_user, version, reg_status, status
                ) VALUES (:1, :2, :3, :4, :5, :6);
            EXCEPTION
                WHEN DUP_VAL_ON_INDEX THEN
                    UPDATE maamd.asrm
                    SET mos_backend = :2,
                        version = :4,
                        reg_status = :5,
                        status = :6
                    WHERE hostname = :1;
            END;
        """, asrm_data)

        asset_data = []
        for data in asr_data_list:
            for asset in data["assets"]:
                asset_data.append((
                    asset["IP_ADDRESS"],
                    asset["HOST_NAME"],
                    asset["SERIAL_NUMER"],
                    asset["PARENT_SERIAL"],
                    asset["ASR"],
                    asset["ASR_STATUS"],
                    asset["PROTOCOL"],
                    asset["SOURCE"],
                    asset["LAST_HEARTBEAT"],
                    asset["PRODUCT_NAME"],
                    asset["ASRM_HOSTNAME"]
                ))

        if asset_data:
            cursor.executemany("""
                BEGIN
                    INSERT INTO maamd.asrm_assets (
                        ip_address, host_name, serial_numer, parent_serial, asr, asr_status,
                        protocol, source, last_heartbeat, product_name, asrm_hostname
                    ) VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11);
                EXCEPTION
                    WHEN DUP_VAL_ON_INDEX THEN
                        UPDATE maamd.asrm_assets
                        SET ip_address = :1,
                            host_name = :2,
                            parent_serial = :4,
                            asr = :5,
                            asr_status = :6,
                            protocol = :7,
                            source = :8,
                            last_heartbeat = :9,
                            product_name = :10
                        WHERE serial_numer = :3
                        AND asrm_hostname = :11;
                END;
            """, asset_data)

        conn.commit()

def main():
    asr_managers = get_asr_managers()
    if not asr_managers:
        exit(1)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_host = {executor.submit(collect_asr_data, hostname, asr_user): hostname for hostname, asr_user in asr_managers}
        all_asr_data = []
        for future in as_completed(future_to_host):
            result = future.result()
            if result:
                all_asr_data.extend(result)
        
        if all_asr_data:
            save_asr_data(all_asr_data)

if __name__ == "__main__":
    main()
