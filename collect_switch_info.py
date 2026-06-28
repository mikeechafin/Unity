#!/usr/bin/env python3
# Version: 2026-04-09 v2.1
# Changes: ALL transient auth, reachability, "No password found" and credential messages downgraded to DEBUG (eliminates massive stderr that was causing ORA-12899 in JOB_HISTORY). Only the final summary report stays at INFO. Script now exits cleanly (code 0) on partial success.

import os
import atexit
import logging
import oracledb
import paramiko
import re
import time
import fcntl
from collections import defaultdict
from maa_libraries import check_hosts_reachability, process_switch, force_exit, is_infiniband_switch, get_credential
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import sys

logger = logging.getLogger('collect_switch_info')
logger.setLevel(logging.DEBUG)

import config

LOG_PATH = os.path.join(config.OUTPUT_DIR, 'collect_switch_info.log')
BACKUP_PATH = LOG_PATH + '.bak'

# Proper log rotation (matches unified scripts)
if os.path.exists(LOG_PATH):
    try:
        if os.path.exists(BACKUP_PATH):
            os.remove(BACKUP_PATH)
        os.rename(LOG_PATH, BACKUP_PATH)
        logger.info(f"Previous log backed up to {BACKUP_PATH}")
    except Exception as e:
        logger.warning(f"Log rotation failed: {e}")

fh = logging.FileHandler(LOG_PATH)
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
logger.propagate = False

DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
DB_USER = os.environ.get('DB_USER', 'maamd')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'welcome2')
SWITCH_WORKERS = 8
DB_TIMEOUT = 300
PROCESS_TIMEOUT = 90
SSH_TIMEOUT = 60
SSH_KEY = "/home/maatest/.ssh/id_rsa"
LOCK_FILE = "/tmp/collect_switch_info.lock"

def signal_handler(signum, frame):
    logger.info("Received SIGINT, forcing exit...")
    os._exit(1)

def fetch_snmp_subscriptions(switch_hostname, pool, failure_report):
    is_ib = is_infiniband_switch(switch_hostname)
    user = 'root' if is_ib else 'admin'
    switch_type = 'INFINIBAND' if is_ib else 'CISCO'
    snmp_subscriptions = []

    conn = None
    cursor = None
    client = None
    try:
        conn = pool.acquire()
        cursor = conn.cursor()
        ssh_connected = False

        credential_order = ['default', switch_hostname]
        for attempt in range(3):
            for cred_name in credential_order:
                try:
                    password = get_credential(cursor, 'SWITCH', cred_name, user)
                    if not password:
                        password = 'admin' if user == 'admin' else 'We1come$'
                        logger.debug(f"No password found for SWITCH:{switch_hostname}:{user}")
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(switch_hostname, username=user, password=password,
                                   timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False)
                    ssh_connected = True
                    break
                except Exception as e:
                    logger.debug(f"Authentication failed for {switch_hostname}: {e}")
                    try:
                        client.close()
                    except:
                        pass
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    time.sleep(1)
            if ssh_connected:
                break

        if not ssh_connected and is_ib:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                key = paramiko.RSAKey.from_private_key_file(SSH_KEY)
                client.connect(switch_hostname, username=user, pkey=key, timeout=SSH_TIMEOUT)
                ssh_connected = True
            except Exception as e:
                logger.debug(f"SSH key fallback failed for {switch_hostname}: {e}")

        if not ssh_connected:
            failure_report['Authentication Failed'].append(switch_hostname)
            return snmp_subscriptions

        try:
            if is_ib:
                cmd = "spsh -c 'show -level all /SP/alertmgmt/rules'"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=180)
                rules_output = stdout.read().decode('utf-8', errors='ignore')
                current_rule = None
                rule_data = {}
                for line in rules_output.splitlines():
                    line = line.strip()
                    if line.startswith('/SP/alertmgmt/rules/'):
                        if current_rule and 'snmp_version' in rule_data:
                            subscription = (current_rule, rule_data.get('snmp_version', '2c').lower(),
                                            rule_data.get('destination', '0.0.0.0'), rule_data.get('community_or_username'),
                                            None, rule_data.get('level', 'disable').lower(),
                                            int(rule_data.get('destination_port', 0)), switch_hostname, None, switch_type)
                            snmp_subscriptions.append(subscription)
                        current_rule = int(line.split('/')[-1])
                        rule_data = {}
                        continue
                    if current_rule and '=' in line:
                        key, value = [x.strip() for x in line.split('=', 1)]
                        rule_data[key.lower()] = value
                if current_rule and 'snmp_version' in rule_data:
                    subscription = (current_rule, rule_data.get('snmp_version', '2c').lower(),
                                    rule_data.get('destination', '0.0.0.0'), rule_data.get('community_or_username'),
                                    None, rule_data.get('level', 'disable').lower(),
                                    int(rule_data.get('destination_port', 0)), switch_hostname, None, switch_type)
                    snmp_subscriptions.append(subscription)
            else:
                cmd = "show snmp host"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
                output = stdout.read().decode('utf-8', errors='ignore')
                if "%SNMP agent not enabled" in output:
                    failure_report['SNMP Agent Disabled'].append(switch_hostname)
                    logger.info(f"SNMP agent not enabled on Cisco {switch_hostname}")
                    return snmp_subscriptions
                if not output.strip():
                    stdin, stdout, stderr = client.exec_command("show snmp", timeout=120)
                    output = stdout.read().decode('utf-8', errors='ignore')
                alert_id = 1
                pattern = re.compile(r'^(?P<host>\S+)\s+(?P<port>\d+)(?:/udp)?\s*(?P<version>v2c|v3)\s+(?P<level>\S+)\s+(?P<type>\S+)\s+(?P<secname>\S+)(?:\s+\S+)?$')
                for line in output.splitlines():
                    line = line.strip()
                    if not line or line.startswith("---") or line.startswith("Host"):
                        continue
                    match = pattern.match(line)
                    if match:
                        dest_ip = match.group('host')
                        port = int(match.group('port'))
                        version = match.group('version').lower()
                        community_or_username = match.group('secname')
                        status = 'enable' if dest_ip != '0.0.0.0' else 'disable'
                        subscription = (alert_id, version, dest_ip,
                                        community_or_username if version == 'v2c' else None,
                                        community_or_username if version == 'v3' else None,
                                        status, port, switch_hostname, None, switch_type)
                        snmp_subscriptions.append(subscription)
                        alert_id += 1
            logger.debug(f"Collected {len(snmp_subscriptions)} SNMP subscriptions for {switch_hostname}")
            if len(snmp_subscriptions) == 0:
                failure_report['Zero SNMP Subscriptions'].append(switch_hostname)
            return snmp_subscriptions
        finally:
            client.close()
    except Exception as e:
        failure_report['Other Error'].append(switch_hostname)
        logger.error(f"Failed to fetch SNMP from {switch_hostname}: {e}", exc_info=True)
        return []
    finally:
        if cursor:
            cursor.close()
        if conn:
            pool.release(conn)

def collect_switch_info(pool):
    start_time = time.time()
    failure_report = defaultdict(list)

    with pool.acquire() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT hostname FROM switch_info")
            switch_hosts = [row[0] for row in cursor.fetchall()]
            logger.info(f"Retrieved {len(switch_hosts)} switch hostnames from switch_info table.")
        finally:
            cursor.close()

    logger.info("Checking host reachability...")
    reachable_hosts_dict = check_hosts_reachability(switch_hosts)
    unreachable = [h for h, r in reachable_hosts_dict.items() if not r]
    if unreachable:
        failure_report['Unreachable'].extend(unreachable)
        logger.debug(f"Unreachable hosts ({len(unreachable)}): {unreachable}")
    reachable_hosts = [h for h, r in reachable_hosts_dict.items() if r]
    logger.info(f"Found {len(reachable_hosts)} reachable hosts out of {len(switch_hosts)}")

    switch_info_list = []
    snmp_subscriptions_list = []
    with ThreadPoolExecutor(max_workers=SWITCH_WORKERS) as executor:
        future_to_host = {executor.submit(process_switch, host, pool): host for host in reachable_hosts}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                switch_data = future.result(timeout=PROCESS_TIMEOUT)
                if switch_data:
                    switch_info_list.append(switch_data)
                    snmp_subscriptions = fetch_snmp_subscriptions(host, pool, failure_report)
                    snmp_subscriptions_list.extend(snmp_subscriptions)
            except Exception as e:
                failure_report['Other Error'].append(host)
                logger.error(f"Failed to process {host}: {e}", exc_info=True)

    elapsed = time.time() - start_time

    # Database merge
    with pool.acquire() as conn:
        cursor = conn.cursor()
        try:
            merge_switch_info_sql = """
                MERGE INTO switch_info dst
                USING (
                    SELECT :hostname AS hostname,
                           :ip_address AS ip_address,
                           :make AS make,
                           :model AS model,
                           :version AS version,
                           :rack_name AS rack_name,
                           :fw_version AS fw_version,
                           :serial_number AS serial_number
                    FROM dual
                ) src
                ON (dst.hostname = src.hostname)
                WHEN MATCHED THEN
                    UPDATE SET dst.ip_address = COALESCE(src.ip_address, dst.ip_address),
                               dst.make = COALESCE(src.make, dst.make),
                               dst.model = COALESCE(src.model, dst.model),
                               dst.version = COALESCE(src.version, dst.version),
                               dst.rack_name = COALESCE(src.rack_name, dst.rack_name),
                               dst.fw_version = COALESCE(src.fw_version, dst.fw_version),
                               dst.serial_number = COALESCE(src.serial_number, dst.serial_number)
                WHEN NOT MATCHED THEN
                    INSERT (hostname, ip_address, make, model, version, rack_name, fw_version, serial_number)
                    VALUES (src.hostname, src.ip_address, src.make, src.model, src.version, src.rack_name,
                            src.fw_version, src.serial_number)
            """
            cursor.executemany(merge_switch_info_sql, switch_info_list)

            if snmp_subscriptions_list:
                merge_snmp_sql = """
                    MERGE INTO MAAMD.SWITCH_SNMP_SUBSCRIPTIONS dest
                    USING (
                        SELECT :1 AS ALERT_ID, :2 AS VERSION, :3 AS DESTINATION_IP,
                               :4 AS COMMUNITY_STRING, :5 AS USERNAME, :6 AS STATUS,
                               :7 AS PORT, :8 AS SWITCH_HOSTNAME, :9 AS SECURITY_LEVEL,
                               :10 AS SWITCH_TYPE
                        FROM DUAL
                    ) src
                    ON (dest.SWITCH_HOSTNAME = src.SWITCH_HOSTNAME AND dest.ALERT_ID = src.ALERT_ID)
                    WHEN MATCHED THEN
                        UPDATE SET dest.VERSION = src.VERSION,
                                   dest.DESTINATION_IP = src.DESTINATION_IP,
                                   dest.COMMUNITY_STRING = src.COMMUNITY_STRING,
                                   dest.USERNAME = src.USERNAME,
                                   dest.STATUS = src.STATUS,
                                   dest.PORT = src.PORT,
                                   dest.SECURITY_LEVEL = src.SECURITY_LEVEL,
                                   dest.SWITCH_TYPE = src.SWITCH_TYPE
                    WHEN NOT MATCHED THEN
                        INSERT (ALERT_ID, VERSION, DESTINATION_IP, COMMUNITY_STRING, USERNAME,
                                STATUS, PORT, SWITCH_HOSTNAME, SECURITY_LEVEL, SWITCH_TYPE)
                        VALUES (src.ALERT_ID, src.VERSION, src.DESTINATION_IP, src.COMMUNITY_STRING,
                                src.USERNAME, src.STATUS, src.PORT, src.SWITCH_HOSTNAME,
                                src.SECURITY_LEVEL, src.SWITCH_TYPE)
                """
                cursor.executemany(merge_snmp_sql, snmp_subscriptions_list)
            conn.commit()
            logger.info("Database merge completed successfully.")
        except Exception as e:
            logger.error(f"Database error: {e}", exc_info=True)
            conn.rollback()
        finally:
            cursor.close()

    # === FINAL FAILURE & SUCCESS SUMMARY REPORT (guaranteed at end) ===
    logger.info("=" * 80)
    logger.info("FINAL FAILURE & SUCCESS SUMMARY REPORT")
    logger.info("=" * 80)
    zero_count = len(failure_report.get('Zero SNMP Subscriptions', []))
    unreachable_count = len(failure_report.get('Unreachable', []))
    other_errors = len(failure_report.get('Other Error', [])) + len(failure_report.get('Authentication Failed', []))
    data_hosts = len(reachable_hosts) - zero_count - other_errors
    success_rate = (len(reachable_hosts) / len(switch_hosts) * 100) if switch_hosts else 0
    logger.info(f"SUCCESS RATE: {success_rate:.1f}% reachable | {data_hosts} switches with SNMP data")
    logger.info(f"ZERO SNMP SUBSCRIPTIONS (normal for many RoCE): {zero_count}")
    logger.info(f"UNREACHABLE: {unreachable_count}")
    for category, hosts in failure_report.items():
        if hosts and category not in ['Zero SNMP Subscriptions', 'Unreachable']:
            logger.info(f"{category} ({len(hosts)} hosts):")
            for h in sorted(set(hosts)):
                logger.info(f"   - {h}")
    if not any(failure_report.values()):
        logger.info("No failures - perfect run!")
    logger.info("=" * 80)

    logger.info(f"Switch info collection completed: {len(switch_info_list)} switches processed, "
                f"{len(snmp_subscriptions_list)} SNMP subscriptions collected in {elapsed:.1f} seconds.")

def main():
    logger.info("Switch info collection script started")
    atexit.register(force_exit)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logger.error("Another instance is already running. Exiting.")
        sys.exit(1)

    pool = oracledb.create_pool(
        user=DB_USER,
        password=DB_PASSWORD,
        dsn=DSN,
        min=1,
        max=SWITCH_WORKERS,
        increment=1,
        timeout=DB_TIMEOUT
    )
    try:
        collect_switch_info(pool)
    finally:
        pool.close()
        try:
            os.unlink(LOCK_FILE)
        except:
            pass
        logger.info("Switch info collection script completed")

if __name__ == "__main__":
    main()
