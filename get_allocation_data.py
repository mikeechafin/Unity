#!/usr/bin/env python3
# Version: 2026-03-29 v1.3.3
# Changes: Fixed DPY-4009 bind count mismatch (16 required but 15 provided) in INSERT by duplicating SYSTEM_NAME as :16 for NOT EXISTS subquery. UPDATE + INSERT split now stable. Manual rows fully protected.
import csv
import re
import paramiko
import oracledb
import logging
import socket
import time
import os
import json
import sys
from json_repair import repair_json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import TimedRotatingFileHandler
from paramiko.ssh_exception import SSHException, AuthenticationException
from scp import SCPClient
import subprocess
from maa_libraries import (
    check_hosts_reachability, setup_host_ssh, get_credential, encrypt_data,
    generate_secure_password, is_host_reachable, add_credential, download_csv,
    decrypt_data, parse_csv_local, is_fqdn_resolvable, get_db_connection
)
# =============================================================================
# Logging setup (standardized to match maa_unified_app.py)
# =============================================================================
log_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
os.makedirs(log_directory, exist_ok=True)
logger = logging.getLogger('get_allocation_data')
logger.setLevel(logging.INFO)
file_handler = TimedRotatingFileHandler(
    os.path.join(log_directory, 'get_allocation_data.log'),
    when='midnight',
    interval=1,
    backupCount=7
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s,%(msecs)03d %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(file_handler)
SCRIPT_VERSION = "1.3.3"
PID_FILE = os.path.join(log_directory, 'get_allocation_data.pid')
# Constants
SSH_KEYS = [
    (paramiko.RSAKey.from_private_key_file('/home/maatest/.ssh/id_rsa'), 'rsa'),
    (paramiko.Ed25519Key.from_private_key_file('/home/maatest/.ssh/id_ed25519'), 'ed25519')
]
SSH_TIMEOUT = 60
SSH_RETRIES = 3
DB_TIMEOUT = 30
def is_already_running():
    """Return True if another copy of the script is running."""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())
            if os.path.exists(f'/proc/{old_pid}'):
                return True
        except (ValueError, OSError):
            pass
    return False
def write_pid_file():
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))
def get_ipv6_version(host):
    """Convert IPv4 hostname to IPv6 variant by inserting 'v6' after rack prefix."""
    return re.sub(r'^([a-z]+[0-9]+)([a-z])', r'\1v6\2', host)
def resolve_reachable_hostname(host):
    """Prefer IPv4 hostname. If unreachable, try IPv6 variant with ping6."""
    try:
        if subprocess.run(["ping", "-4", "-c", "1", "-W", "2", host], capture_output=True, timeout=5).returncode == 0:
            logger.debug(f"{host} reachable via IPv4")
            return host
    except Exception:
        pass
    ipv6_host = get_ipv6_version(host)
    try:
        if subprocess.run(["ping", "-6", "-c", "1", "-W", "2", ipv6_host], capture_output=True, timeout=5).returncode == 0:
            logger.info(f"{host} unreachable via IPv4; using IPv6 variant {ipv6_host}")
            return ipv6_host
    except Exception:
        pass
    logger.warning(f"Neither IPv4 ({host}) nor IPv6 ({ipv6_host}) reachable")
    return host
def check_tcp_port(hostname, port=22, timeout=5):
    """Check if TCP port is open on host (required by switch SSH setup)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        return result == 0
    except Exception:
        return False
def safe_extract_dict(obj):
    """Recursively unwrap any depth of nested lists until dict or empty."""
    while isinstance(obj, list) and obj:
        obj = obj[0]
    return obj if isinstance(obj, dict) else {}
def is_hypervisor(host, conn, ssh_client=None, timeout=SSH_TIMEOUT):
    """100% accurate hypervisor detection using official Exadata 'imageinfo' Node type (KVMHOST/DOM0 = YES; COMPUTE/GUEST = NO)."""
    original_host = host
    host = resolve_reachable_hostname(host)
    host_lower = host.lower()
    # BLACKLIST (storage & guests are NEVER hypervisors)
    if any(x in host_lower for x in ['celadm', 'cell', 'vm', 'dv', 'guest', 'm.us.oracle.com']):
        logger.info(f"{original_host} is storage server or guest - NEVER hypervisor")
        return False, None
    logger.info(f"Checking if {original_host} is a hypervisor (imageinfo Node type)")
    cursor = conn.cursor()
    client = ssh_client or paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cursor.execute(
            """
            SELECT USERNAME, ENCRYPTED_PASSWORD, COMPONENT_NAME
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_TYPE = 'PHYSICAL_HOST'
              AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
            ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END, USERNAME
            """,
            {'hostname': host}
        )
        creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None, row[2]) for row in cursor.fetchall()]
        users = ['root', 'oracle']
        passwords = [(u, p) for u, p, _ in creds if u in users and p]
        if not passwords:
            passwords = [(u, None) for u in users]
        connected = False
        for username, password in passwords:
            for key, key_type in SSH_KEYS:
                try:
                    client.connect(host, username=username, pkey=key, timeout=timeout, banner_timeout=timeout)
                    connected = True
                    break
                except Exception:
                    continue
            if connected:
                break
            if password:
                try:
                    client.connect(host, username=username, password=password, timeout=timeout)
                    connected = True
                    break
                except Exception:
                    continue
        if not connected:
            logger.warning(f"Could not connect to {original_host} (tried {host}) - assuming not hypervisor")
            return False, None
        imageinfo_cmd = "imageinfo 2>&1"
        stdin, stdout, stderr = client.exec_command(imageinfo_cmd, timeout=timeout)
        full_output = stdout.read().decode('utf-8', errors='ignore').strip()
        logger.debug(f"RAW imageinfo output for {original_host}:\n{full_output}")
        node_type_match = re.search(r'Node type:\s*(\S+)', full_output)
        node_type = node_type_match.group(1) if node_type_match else "UNKNOWN"
        is_hyp = node_type in ('KVMHOST', 'DOM0')
        logger.info(f"{original_host} hypervisor check: Node type = {node_type} → {'YES' if is_hyp else 'NO'}")
        return is_hyp, client
    except Exception as e:
        logger.warning(f"Hypervisor detection failed on {original_host}: {e}")
        return False, None
    finally:
        cursor.close()
        if not ssh_client and client:
            try:
                client.close()
            except:
                pass
def parse_csv_generator(csv_file, conn):
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, quoting=csv.QUOTE_ALL)
            for row_index, row in enumerate(reader, start=1):
                try:
                    component = row.get('HOSTNAME', row.get('SYSTEM_NAME', row.get('COMPONENT', ''))).strip()
                    allocations_json = row.get('MY_ALLOCATION', row.get('ALLOCATIONS', ''))
                    if not component or not allocations_json:
                        continue
                    yield row, row_index
                except Exception as e:
                    logger.error(f"Error in row {row_index}: {e}")
                    continue
    except Exception as e:
        logger.error(f"Error opening CSV: {e}")
        raise
def check_host_reachability_single(host):
    resolved = resolve_reachable_hostname(host)
    try:
        logger.debug(f"Pinging {resolved} (original {host})")
        result = subprocess.run(
            ["ping", "-c", "2", "-W", "2", resolved],
            capture_output=True, text=True, timeout=10
        )
        return host, result.returncode == 0, resolved
    except Exception as e:
        logger.debug(f"Ping failed for {resolved}: {e}")
        return host, False, resolved
def check_hosts_reachability(hosts, max_workers=50, timeout=300):
    reachable = {}
    resolved_map = {}
    logger.info(f"Starting reachability check for {len(hosts)} hosts")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host_reachability_single, host): host for host in hosts}
        try:
            for future in as_completed(futures, timeout=timeout):
                original, is_reachable, resolved = future.result()
                reachable[original] = is_reachable
                resolved_map[original] = resolved
        except Exception:
            logger.error(f"Reachability check timed out")
            for future in futures:
                future.cancel()
    reachable_count = sum(1 for v in reachable.values() if v)
    logger.info(f"Reachability check complete: {reachable_count}/{len(reachable)} hosts reachable")
    return reachable, resolved_map
def check_physical_hosts_for_guests(allocations, conn):
    logger.info("Starting check for physical hosts as hypervisors")
    cursor = conn.cursor()
    system_guests_data = []
    seen_guests = set()
    try:
        cursor.execute(
            "SELECT HOSTNAME FROM MAAMD.UNRESOLVABLE_HOSTS WHERE FAILURE_COUNT >= 2"
        )
        unresolvable_hosts = set(row[0] for row in cursor.fetchall())
        physical_hosts = list(set(
            alloc[0] for alloc in allocations
            if 'celadm' not in alloc[0].lower() and '-c' not in alloc[0].lower() and '-ilom' not in alloc[0].lower()
            and alloc[0] not in unresolvable_hosts and is_valid_hostname(alloc[0])
        ))
        reachable_dict, resolved_map = check_hosts_reachability(physical_hosts)
        reachable_hosts_list = [host for host, is_reachable in reachable_dict.items() if is_reachable]
        logger.info(f"Submitting {len(reachable_hosts_list)} reachable physical hosts for hypervisor detection...")
        hypervisor_map = {}
        ssh_clients = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(is_hypervisor, host, conn): host for host in reachable_hosts_list}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    is_hyp, client = future.result()
                    hypervisor_map[host] = is_hyp
                    if client:
                        ssh_clients[host] = client
                except Exception as e:
                    logger.error(f"Error checking hypervisor status for {host}: {e}")
        yes_count = sum(1 for v in hypervisor_map.values() if v)
        logger.info(f"Hypervisor detection completed: {len(hypervisor_map)} hosts checked, {yes_count} true hypervisors found")
        hypervisor_data = [(host, 'Y' if is_hyp else 'N') for host, is_hyp in hypervisor_map.items()]
        if hypervisor_data:
            cursor.executemany(
                """
                MERGE INTO MAAMD.HYPERVISORS dst
                USING (SELECT :1 AS HOSTNAME, :2 AS IS_HYPERVISOR FROM dual) src
                ON (dst.HOSTNAME = src.HOSTNAME)
                WHEN MATCHED THEN
                    UPDATE SET IS_HYPERVISOR = src.IS_HYPERVISOR, LAST_UPDATED_DATE = SYSDATE
                WHEN NOT MATCHED THEN
                    INSERT (HOSTNAME, IS_HYPERVISOR, CREATED_DATE, LAST_UPDATED_DATE)
                    VALUES (src.HOSTNAME, src.IS_HYPERVISOR, SYSDATE, SYSDATE)
                """,
                hypervisor_data
            )
            conn.commit()
        hypervisors = [host for host in reachable_hosts_list if hypervisor_map.get(host)]
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(get_guests, host, conn): host for host in set(hypervisors)}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    guests = future.result()
                    for guest in guests:
                        guest_tuple = (guest[0].lower(), guest[1].lower())
                        if guest_tuple not in seen_guests:
                            system_guests_data.append((guest[0], guest[1]))
                            seen_guests.add(guest_tuple)
                except Exception as e:
                    logger.error(f"Error collecting guests from {host}: {e}")
        for host in ssh_clients:
            try:
                ssh_clients[host].close()
            except:
                pass
        return system_guests_data
    except Exception as e:
        logger.error(f"Error in check_physical_hosts_for_guests: {e}")
        conn.rollback()
        return []
    finally:
        cursor.close()
def get_guests(host, conn, ssh_client=None, timeout=SSH_TIMEOUT):
    original_host = host
    host = resolve_reachable_hostname(host)
    logger.info(f"Collecting guests from hypervisor {original_host} (using {host})")
    cursor = conn.cursor()
    client = ssh_client or paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    guests = []
    try:
        cursor.execute(
            """
            SELECT USERNAME, ENCRYPTED_PASSWORD, COMPONENT_NAME
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_TYPE = 'PHYSICAL_HOST'
              AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
            ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END, USERNAME
            """,
            {'hostname': host}
        )
        creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None, row[2]) for row in cursor.fetchall()]
        users = ['root', 'oracle']
        passwords = [(u, p) for u, p, _ in creds if u in users and p]
        if not passwords:
            passwords = [(u, None) for u in users]
        connected = False
        for username, password in passwords:
            for key, key_type in SSH_KEYS:
                try:
                    client.connect(host, username=username, pkey=key, timeout=timeout)
                    connected = True
                    break
                except Exception:
                    continue
            if connected:
                break
            if password:
                try:
                    client.connect(host, username=username, password=password, timeout=timeout)
                    connected = True
                    break
                except Exception:
                    continue
        if not connected:
            return []
        stdin, stdout, stderr = client.exec_command("virsh list --all | tail -n +3 | awk '{print $2}'", timeout=timeout)
        output = stdout.read().decode().strip()
        for guest in output.splitlines():
            if guest.strip():
                guests.append((guest.strip(), host))
        return guests
    except Exception as e:
        logger.error(f"Error collecting guests from {original_host}: {e}")
        return []
    finally:
        cursor.close()
        if not ssh_client and client:
            try:
                client.close()
            except:
                pass
def is_valid_hostname(hostname):
    if not hostname:
        return False
    if len(hostname.encode('utf-8')) > 100:
        return False
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+$'
    return bool(re.match(pattern, hostname))
def populate_switch_info(conn):
    logger.info("Populating switch info")
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
def process_switch(switch_hostname, conn):
    original = switch_hostname
    switch_hostname = resolve_reachable_hostname(switch_hostname)
    logger.info(f"Processing switch {original} (using {switch_hostname})")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT USERNAME, ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_TYPE = 'SWITCH'
              AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
            ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END, USERNAME
            """,
            {'hostname': switch_hostname}
        )
        creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None) for row in cursor.fetchall()]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connected = False
        for username, password in creds:
            try:
                client.connect(switch_hostname, username=username, password=password, timeout=SSH_TIMEOUT)
                connected = True
                break
            except Exception:
                continue
        if not connected:
            return
        switch_data = {'model': 'Unknown', 'serial_number': 'Unknown', 'version': 'Unknown', 'fw_version': 'Unknown'}
        if 'oracle' in switch_hostname.lower() or 'ib' in switch_hostname.lower():
            cmd = "show version"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT)
            output = stdout.read().decode().strip()
            model_match = re.search(r'Model:\s*(\S+)', output)
            serial_match = re.search(r'Serial Number:\s*(\S+)', output)
            version_match = re.search(r'Version:\s*(\S+)', output)
            fw_match = re.search(r'FW Version:\s*(\S+)', output)
            switch_data['model'] = model_match.group(1) if model_match else 'Unknown'
            switch_data['serial_number'] = serial_match.group(1) if serial_match else 'Unknown'
            switch_data['version'] = version_match.group(1) if version_match else 'Unknown'
            switch_data['fw_version'] = fw_match.group(1) if fw_match else 'Unknown'
        else:
            cmd = "show version"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT)
            output = stdout.read().decode().strip()
            model_match = re.search(r'cisco\s+(\S+)', output)
            serial_match = re.search(r'Processor board ID (\S+)', output)
            version_match = re.search(r'NXOS:\s+version (\S+)', output)
            fw_match = re.search(r'BIOS:\s+version (\S+)', output)
            switch_data['model'] = model_match.group(1) if model_match else 'Unknown'
            switch_data['serial_number'] = serial_match.group(1) if serial_match else 'Unknown'
            switch_data['version'] = version_match.group(1) if version_match else 'Unknown'
            switch_data['fw_version'] = fw_match.group(1) if fw_match else 'Unknown'
        cursor.execute(
            """
            MERGE INTO MAAMD.SWITCH_INFO dst
            USING (SELECT :1 AS HOSTNAME, :2 AS MODEL, :3 AS SERIAL_NUMBER, :4 AS VERSION, :5 AS FW_VERSION FROM dual) src
            ON (dst.HOSTNAME = src.HOSTNAME)
            WHEN MATCHED THEN
                UPDATE SET MODEL = src.MODEL, SERIAL_NUMBER = src.SERIAL_NUMBER, VERSION = src.VERSION, FW_VERSION = src.FW_VERSION
            WHEN NOT MATCHED THEN
                INSERT (HOSTNAME, MODEL, SERIAL_NUMBER, VERSION, FW_VERSION)
                VALUES (src.HOSTNAME, src.MODEL, src.SERIAL_NUMBER, src.VERSION, src.FW_VERSION)
            """,
            (switch_hostname, switch_data['model'], switch_data['serial_number'], switch_data['version'], switch_data['fw_version'])
        )
        conn.commit()
    except oracledb.Error as e:
        logger.error(f"Database error processing switch {original}: {e}")
        conn.rollback()
    finally:
        cursor.close()
        if 'client' in locals():
            client.close()
def setup_switches_ssh(conn):
    logger.info("Starting SSH setup for switches")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT DISTINCT s.HOSTNAME, s.MAKE
            FROM MAAMD.SWITCH_INFO s
            WHERE s.MAKE IN ('Cisco', 'Oracle', 'Unknown')
              AND s.HOSTNAME IS NOT NULL
        """)
        switches = [(row[0], row[1]) for row in cursor.fetchall()]
        switch_credentials = {}
        for hostname, _ in switches:
            cursor.execute(
                """
                SELECT USERNAME, ENCRYPTED_PASSWORD, COMPONENT_NAME, LAST_UPDATED_DATE
                FROM MAAMD.ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = 'SWITCH'
                  AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
                ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END, USERNAME
                """,
                {'hostname': hostname}
            )
            creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None, row[2], row[3]) for row in cursor.fetchall() if row[1]]
            switch_credentials[hostname] = [{'username': username, 'password': password, 'component_name': comp, 'last_updated_date': last_updated} for username, password, comp, last_updated in creds if username and password]
        for hostname, make in switches:
            is_ib = 'Oracle' in make or any(s in hostname.lower() for s in ['-iba0', '-ibb0', '-ibs0'])
            username = 'root' if is_ib else 'admin'
            if not switch_credentials.get(hostname):
                cursor.execute(
                    """
                    SELECT USERNAME, ENCRYPTED_PASSWORD
                    FROM MAAMD.ACCESS_CREDENTIALS
                    WHERE COMPONENT_TYPE = 'SWITCH'
                      AND COMPONENT_NAME = 'default'
                      AND USERNAME = :username
                    """,
                    {'username': username}
                )
                row = cursor.fetchone()
                default_password = decrypt_data(row[1].read()) if row and row[1] else None
                if default_password:
                    add_credential(cursor, 'SWITCH', hostname, username, default_password, None, 'script')
                    switch_credentials[hostname] = [{'username': username, 'password': default_password, 'component_name': 'default', 'last_updated_date': None}]
        conn.commit()
        switch_hostnames = [hostname for hostname, _ in switches]
        reachable_switches, resolved_map = check_hosts_reachability(switch_hostnames)
        filtered_switches = [
            (hostname, make, switch_credentials.get(hostname, [{'username': 'root' if is_ib else 'admin', 'password': None, 'component_name': 'default', 'last_updated_date': None}]))
            for hostname, make in switches
            if reachable_switches.get(hostname, False)
        ]
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = {
                executor.submit(configure_passwordless_ssh_with_creds, hostname, make, creds, conn, SSH_TIMEOUT): hostname
                for hostname, make, creds in filtered_switches
            }
            for future in as_completed(futures):
                hostname = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error configuring SSH for {hostname}: {e}")
    except Exception as e:
        logger.error(f"Error during switch SSH setup: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
def configure_passwordless_ssh_with_creds(switch_hostname, make, creds_list, conn, timeout=120):
    original = switch_hostname
    switch_hostname = resolve_reachable_hostname(switch_hostname)
    logger.info(f"Attempting SSH configuration for switch: {original} (using {switch_hostname})")
    is_ib = 'Oracle' in make or any(s in switch_hostname.lower() for s in ['-iba0', '-ibb0', '-ibs0'])
    default_username = 'root' if is_ib else 'admin'
    cursor = conn.cursor()
    try:
        if not check_tcp_port(switch_hostname):
            logger.error(f"SSH port 22 not open on {original}, skipping SSH setup")
            return False
        passwords = []
        for username in [default_username]:
            cursor.execute(
                """
                SELECT USERNAME, ENCRYPTED_PASSWORD, COMPONENT_NAME, LAST_UPDATED_DATE
                FROM MAAMD.ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = 'SWITCH'
                  AND (COMPONENT_NAME = :hostname OR COMPONENT_NAME = 'default')
                  AND USERNAME = :username
                ORDER BY CASE WHEN COMPONENT_NAME = :hostname THEN 0 ELSE 1 END, USERNAME
                """,
                {'hostname': switch_hostname, 'username': username}
            )
            creds = [(row[0], decrypt_data(row[1].read()) if row[1] else None, row[2], row[3]) for row in cursor.fetchall() if row[1]]
            passwords.extend(creds)
        if not passwords:
            passwords.append((default_username, None, 'default', None))
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pubkey_file = f"/tmp/{switch_hostname.replace('.', '_')}_pubkey.pub"
        remote_path = f"/tmp/{switch_hostname.replace('.', '_')}_pubkey.pub"
        with open('/home/maatest/.ssh/id_rsa.pub', 'r') as f:
            pubkey = f.read().strip()
        with open(pubkey_file, 'w') as f:
            f.write(pubkey)
        os.chmod(pubkey_file, 0o644)
        connected = False
        for attempt in range(SSH_RETRIES):
            try:
                for username, password, component_name, last_updated_date in passwords:
                    try:
                        for key, key_type in SSH_KEYS:
                            try:
                                client.connect(switch_hostname, username=username, pkey=key, timeout=timeout)
                                connected = True
                                break
                            except Exception:
                                continue
                        if connected:
                            break
                        if password:
                            client.connect(switch_hostname, username=username, password=password, timeout=timeout)
                            connected = True
                            break
                    except Exception:
                        continue
                if not connected:
                    continue
                if is_ib:
                    commands = [
                        "mkdir -p ~/.ssh",
                        f"echo '{pubkey}' > {remote_path}",
                        f"cat {remote_path} >> ~/.ssh/authorized_keys",
                        "chmod 600 ~/.ssh/authorized_keys",
                        f"rm {remote_path}"
                    ]
                    for cmd in commands:
                        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                        exit_status = stdout.channel.recv_exit_status()
                        if exit_status != 0:
                            break
                    else:
                        return True
                else:
                    shell = client.invoke_shell()
                    shell.send("configure terminal\n")
                    shell.send(f"username {default_username} sshkey {pubkey}\n")
                    shell.send("end\n")
                    return True
            except Exception:
                continue
            finally:
                try:
                    client.close()
                except:
                    pass
                if os.path.exists(pubkey_file):
                    os.remove(pubkey_file)
        return False
    finally:
        cursor.close()
def cleanup_old_ilom_entries(conn, current_ilom_hosts):
    logger.info("Cleaning up old/bad ILOM entries")
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT CONSTRAINT_NAME, TABLE_NAME
            FROM USER_CONSTRAINTS
            WHERE R_CONSTRAINT_NAME IN (
                SELECT CONSTRAINT_NAME FROM USER_CONSTRAINTS
                WHERE TABLE_NAME = 'ILOM_HOSTS' AND CONSTRAINT_TYPE IN ('P', 'U')
            ) AND CONSTRAINT_TYPE = 'R'
        """)
        fk_constraints = cursor.fetchall()
        for constraint, table in fk_constraints:
            cursor.execute(f"ALTER TABLE {table} DISABLE CONSTRAINT {constraint}")
        cursor.execute("SELECT HOSTNAME, ILOM_IP FROM MAAMD.ILOM_HOSTS")
        existing = cursor.fetchall()
        current_set = set(host[0].lower() for host in current_ilom_hosts)
        to_delete = []
        for host, ilom_ip in existing:
            host_lower = host.lower()
            is_bad = False
            if host_lower not in current_set:
                is_bad = True
            if not is_valid_hostname(host):
                is_bad = True
            if '-c.us.oracle.com' in host:
                is_bad = True
            if ilom_ip and (ilom_ip == host or ilom_ip.startswith(host) or ilom_ip.endswith(host)):
                is_bad = True
            if ilom_ip and re.match(r'^[0-9a-fA-F]{32}$', ilom_ip):
                is_bad = True
            if ilom_ip and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ilom_ip):
                is_bad = True
            if is_bad:
                to_delete.append((host,))
        if to_delete:
            cursor.executemany(
                "DELETE FROM MAAMD.ILOM_HOSTS WHERE HOSTNAME = :1",
                to_delete
            )
            conn.commit()
            logger.info(f"Deleted {len(to_delete)} old/bad ILOM entries")
        for constraint, table in fk_constraints:
            cursor.execute(f"ALTER TABLE {table} ENABLE NOVALIDATE CONSTRAINT {constraint}")
    except oracledb.Error as e:
        logger.error(f"Error cleaning up ILOM entries: {e}")
        conn.rollback()
    finally:
        cursor.close()
def populate_exadata_racks(allocations, conn):
    logger.info("Populating exadata racks")
    cursor = conn.cursor()
    try:
        racks = set(alloc[7] for alloc in allocations if alloc[7])
        exadata_racks = []
        for rack in racks:
            exadata_racks.append((rack, None, None))
        cursor.executemany(
            """
            MERGE INTO MAAMD.EXADATA_RACKS dst
            USING (SELECT :1 AS RACK_NAME, :2 AS STORAGENETWORK_TYPE, :3 AS RACK_SN FROM dual) src
            ON (dst.RACK_NAME = src.RACK_NAME)
            WHEN MATCHED THEN
                UPDATE SET STORAGENETWORK_TYPE = src.STORAGENETWORK_TYPE, RACK_SN = src.RACK_SN
            WHEN NOT MATCHED THEN
                INSERT (RACK_NAME, STORAGENETWORK_TYPE, RACK_SN)
                VALUES (src.RACK_NAME, src.STORAGENETWORK_TYPE, src.RACK_SN)
            """,
            exadata_racks
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Error populating exadata racks: {e}")
        conn.rollback()
    finally:
        cursor.close()
def download_and_cache_csv():
    for attempt in range(3):
        try:
            logger.info(f"Downloading CSV, attempt {attempt + 1}/3")
            csv_file = download_csv()
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f, quoting=csv.QUOTE_ALL)
                rows = list(reader)
            if not rows:
                continue
            valid_headers = [['COMPONENT', 'MY_ALLOCATION'], ['COMPONENT', 'ALLOCATIONS']]
            if len(rows[0]) != 2 or rows[0] not in valid_headers:
                continue
            logger.info(f"Successfully downloaded CSV to {csv_file}")
            return csv_file
        except Exception as e:
            logger.error(f"CSV download attempt {attempt + 1} failed: {e}")
            if attempt + 1 < 3:
                time.sleep(2 ** attempt)
    logger.error("Failed to download valid CSV after all attempts")
    raise RuntimeError("Cannot proceed without valid CSV data")
def main():
    if is_already_running():
        logger.error("Another instance of the script is already running. Exiting.")
        sys.exit(1)
    write_pid_file()
    total_start_time = time.time()
    logger.info(f"Script started, version {SCRIPT_VERSION}")
    conn = None
    try:
        db_password = os.getenv('DB_PASSWORD')
        if not db_password:
            logger.error("Environment variable DB_PASSWORD must be set")
            raise ValueError("Environment variable DB_PASSWORD must be set")
        logger.debug("Connecting to database")
        conn = get_db_connection(
            username='maamd',
            password=db_password,
            dsn='(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))',
            timeout=DB_TIMEOUT
        )
        logger.info("Connected to database")
        cursor = conn.cursor()
        try:
            logger.debug("Cleaning invalid rack names from EXADATA_RACKS")
            cursor.execute("DELETE FROM MAAMD.EXADATA_RACKS WHERE RACK_NAME IN (' slcs02', 'scaqak03sw', 'scaqak04sw')")
            conn.commit()
            logger.info("Cleaned invalid rack names from EXADATA_RACKS")
        finally:
            cursor.close()
        csv_file = download_and_cache_csv()
        allocations = []
        csv_guests_data = []
        processed_hosts = set()
        for row, row_index in parse_csv_generator(csv_file, conn):
            component = row.get('HOSTNAME', row.get('SYSTEM_NAME', row.get('COMPONENT', ''))).strip()
            if component in processed_hosts:
                continue
            processed_hosts.add(component)
            try:
                my_allocation = row.get('MY_ALLOCATION', row.get('ALLOCATIONS', '')).strip()
                if my_allocation.startswith('"') and my_allocation.endswith('"'):
                    my_allocation = my_allocation[1:-1]
                repaired_json = repair_json(my_allocation)
                alloc_dict = json.loads(repaired_json)
                if isinstance(alloc_dict, list) and alloc_dict:
                    for item in alloc_dict:
                        if isinstance(item, dict):
                            alloc_dict = item
                            break
                    else:
                        alloc_dict = {}
                        logger.warning(f"Row {row_index} ({component}): malformed JSON (list), using empty dict")
                current_list = alloc_dict.get('current', [])
                past_list = alloc_dict.get('past_6_months', [])
                current = safe_extract_dict(current_list[0] if current_list else past_list[0] if past_list else {})
                if not current_list:
                    logger.info(f"Row {row_index}: No current allocation (completed entry), using most recent past allocation for {component}")
                try:
                    current_allocation = current.get('description', '') or current.get('label', '')
                    start_date_str = current.get('start_date', '').split('T')[0] if current.get('start_date') else ''
                    end_date_str = current.get('end_date', '').split('T')[0] if current.get('end_date') else ''
                    try:
                        start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str and start_date_str != 'None' else None
                        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str and end_date_str != 'None' else None
                    except ValueError:
                        start_date = end_date = None
                    allocator = current.get('allocator', {}).get('username', '')
                    switch_name = ''
                    last_updated = datetime.now()
                    rack_name = component.split('adm')[0] if 'adm' in component else component.split('celadm')[0] if 'celadm' in component else ''
                    base = re.sub(r'(\.us\.oracle\.com)?$', '', component)
                    base = re.sub(r'(-c|-ilom)$', '', base)
                    ilom_name = f"{base}-ilom.us.oracle.com" if 'adm' in base or 'celadm' in base else ''
                    serial_number = ''
                    allocation_type = current.get('allocation_type', {}).get('label', '')
                    owner_group = ''
                    support_group = ''
                    support_system = ''
                    notes = current.get('notes', '')
                except Exception as inner_e:
                    logger.error(f"Error extracting fields for row {row_index} component {component}: {inner_e}")
                    logger.error(f"Raw alloc_dict for debugging:\n{json.dumps(alloc_dict, indent=2, default=str)}")
                    continue
                alloc = [
                    component, current_allocation, start_date, end_date,
                    allocator, switch_name, last_updated, rack_name,
                    ilom_name, serial_number, allocation_type,
                    owner_group, support_group, support_system, notes
                ]
                allocations.append(alloc)
                guests = []
                if 'vm' in component.lower() or component.endswith('m.us.oracle.com'):
                    hypervisor = re.sub(r'vm\d*', '', component).replace('m.us.oracle.com', '.us.oracle.com')
                    guests.append((component, hypervisor))
                csv_guests_data.extend(guests)
            except Exception as e:
                logger.error(f"Error parsing row {row_index} for component {component}: {e}")
                continue
        logger.info(f"Parsed CSV: {len(allocations)} allocations, {len(csv_guests_data)} guests")
        validated_allocations = []
        seen_system_names = set()
        for alloc in allocations:
            if not alloc[0] or not alloc[1] or not alloc[2] or not alloc[4]:
                continue
            if alloc[0] in seen_system_names:
                continue
            seen_system_names.add(alloc[0])
            validated_allocations.append(alloc)
        logger.info(f"Validated {len(validated_allocations)} allocations")
        if validated_allocations:
            cursor = conn.cursor()
            try:
                # UPDATE existing auto rows (skip manual)
                update_data = [alloc[:15] for alloc in validated_allocations]
                cursor.executemany(
                    """
                    UPDATE MAAMD.SYSTEM_ALLOCATIONS
                    SET CURRENT_ALLOCATION = :2,
                        START_DATE = :3,
                        END_DATE = :4,
                        ALLOCATOR = :5,
                        SWITCH_NAME = :6,
                        LAST_UPDATED = :7,
                        RACK_NAME = :8,
                        ILOM_NAME = :9,
                        SERIAL_NUMBER = :10,
                        ALLOCATION_TYPE = :11,
                        OWNER_GROUP = :12,
                        SUPPORT_GROUP = :13,
                        SUPPORT_SYSTEM = :14,
                        NOTES = :15,
                        SOURCE = 'AUTO'
                    WHERE SYSTEM_NAME = :1
                      AND NVL(MANUAL_OVERRIDE, 'N') = 'N'
                    """,
                    update_data
                )
                conn.commit()
                logger.info(f"Updated {cursor.rowcount} existing auto allocations (manual rows skipped)")
                # INSERT new rows only (safe NOT EXISTS with duplicated bind)
                insert_data = [alloc[:15] + [alloc[0]] for alloc in validated_allocations]
                cursor.executemany(
                    """
                    INSERT INTO MAAMD.SYSTEM_ALLOCATIONS
                    (SYSTEM_NAME, CURRENT_ALLOCATION, START_DATE, END_DATE,
                     ALLOCATOR, SWITCH_NAME, LAST_UPDATED, RACK_NAME,
                     ILOM_NAME, SERIAL_NUMBER, ALLOCATION_TYPE,
                     OWNER_GROUP, SUPPORT_GROUP, SUPPORT_SYSTEM, NOTES,
                     SOURCE, MANUAL_OVERRIDE)
                    SELECT :1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13, :14, :15, 'AUTO', 'N'
                    FROM DUAL
                    WHERE NOT EXISTS (
                        SELECT 1 FROM MAAMD.SYSTEM_ALLOCATIONS
                        WHERE SYSTEM_NAME = :16
                    )
                    """,
                    insert_data
                )
                conn.commit()
                logger.info(f"Inserted {cursor.rowcount} new auto allocations")
            finally:
                cursor.close()
        ilom_hosts = [(alloc[8], None) for alloc in validated_allocations if alloc[8] and is_valid_hostname(alloc[8])]
        cleanup_old_ilom_entries(conn, ilom_hosts)
        cursor = conn.cursor()
        try:
            if ilom_hosts:
                cursor.executemany(
                    """
                    MERGE INTO MAAMD.ILOM_HOSTS dest
                    USING (SELECT :1 AS HOSTNAME, :2 AS ILOM_IP FROM DUAL) src
                    ON (dest.HOSTNAME = src.HOSTNAME)
                    WHEN MATCHED THEN
                        UPDATE SET ILOM_IP = src.ILOM_IP
                    WHEN NOT MATCHED THEN
                        INSERT (HOSTNAME, ILOM_IP)
                        VALUES (src.HOSTNAME, src.ILOM_IP)
                    """,
                    ilom_hosts
                )
                conn.commit()
                logger.info(f"Merged {len(ilom_hosts)} entries into MAAMD.ILOM_HOSTS")
        finally:
            cursor.close()
        system_guests_data = check_physical_hosts_for_guests(validated_allocations, conn)
        logger.info(f"Discovered {len(system_guests_data)} guests from hypervisor checks")
        seen_guests = set()
        all_guests_data = []
        for g in csv_guests_data:
            guest_tuple = (g[0].lower(), g[1].lower())
            if guest_tuple not in seen_guests:
                all_guests_data.append(g)
                seen_guests.add(guest_tuple)
        for g in system_guests_data:
            guest_tuple = (g[0].lower(), g[1].lower())
            if guest_tuple not in seen_guests:
                all_guests_data.append(g)
                seen_guests.add(guest_tuple)
        logger.info(f"Combined {len(all_guests_data)} unique guests after deduplication")
        if all_guests_data:
            cursor = conn.cursor()
            try:
                cursor.executemany(
                    """
                    MERGE INTO MAAMD.GUESTS dest
                    USING (SELECT :1 AS HOSTNAME, :2 AS HYPERVISOR FROM DUAL) src
                    ON (LOWER(dest.HOSTNAME) = LOWER(src.HOSTNAME))
                    WHEN MATCHED THEN
                        UPDATE SET HYPERVISOR = src.HYPERVISOR, LAST_UPDATED = SYSDATE
                    WHEN NOT MATCHED THEN
                        INSERT (HOSTNAME, HYPERVISOR, LAST_UPDATED)
                        VALUES (src.HOSTNAME, src.HYPERVISOR, SYSDATE)
                    """,
                    all_guests_data
                )
                conn.commit()
                logger.info(f"Merged {len(all_guests_data)} guests into MAAMD.GUESTS")
            finally:
                cursor.close()
        populate_exadata_racks(validated_allocations, conn)
        populate_switch_info(conn)
        setup_switches_ssh(conn)
        logger.info(f"Script completed successfully in {time.time() - total_start_time:.2f} seconds")
    except Exception as e:
        logger.error(f"Script failed: {e}")
        raise
    finally:
        if conn is not None:
            conn.close()
            logger.debug("Closed database connection")
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass
if __name__ == "__main__":
    main()
