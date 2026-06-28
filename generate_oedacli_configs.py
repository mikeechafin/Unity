#!/usr/bin/env python3
# Filename: generate_oedacli_configs.py
# Version: 2026-04-23 v1.36
# Changes: Fixed ORA-01461 by properly binding CLOB columns using setinputsizes()

import os
import sys
import json
import argparse
import logging
import subprocess
import threading
import re
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import oracledb
import paramiko
from cryptography.fernet import Fernet

print("=== OEDACLI CONFIG GENERATOR v1.36 STARTED ===")

DISCOVERY_SCRIPT = "/home/maatest/mchafin/MAA_APPS_NEW/discover_dbmachine_standalone.py"
OEDACLI_BINARY = "/home/maatest/mchafin/MAA_APPS_NEW/OEDA/oedacli"
OUTPUT_DIR = "/tmp/oedacli_configs"
MAX_WORKERS = 12
DEFAULT_TIMEOUT = 600
SSH_TEST_TIMEOUT = 6
DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
DB_USER = os.environ.get('DB_USER', 'maamd')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'welcome2')

key_file = '/home/maatest/mchafin/MAA_APPS_NEW/encryption_key.txt'
if os.path.exists(key_file):
    with open(key_file, 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(ENCRYPTION_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

processed_canonical_hosts = set()
lock = threading.Lock()
successful_clusters = []
skipped_clusters = []

def setup_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_db_pool():
    try:
        return oracledb.create_pool(user=DB_USER, password=DB_PASSWORD, dsn=DSN, min=1, max=5, increment=1)
    except Exception as e:
        logger.error(f"DB pool creation failed: {e}")
        return None

def get_database_servers_from_db():
    pool = get_db_pool()
    if not pool:
        return []
    conn = None
    try:
        conn = pool.acquire()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT SYSTEM_NAME
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE LOWER(SYSTEM_NAME) LIKE '%adm%'
              AND LOWER(SYSTEM_NAME) NOT LIKE '%celadm%'
            ORDER BY SYSTEM_NAME
        """)
        hosts = [row[0] for row in cursor.fetchall()]
        cursor.close()
        pool.release(conn)
        pool.close()
        logger.info(f"Found {len(hosts)} database servers from SYSTEM_ALLOCATIONS")
        return hosts
    except Exception as e:
        logger.error(f"DB query failed: {e}")
        if conn:
            pool.release(conn)
        if pool:
            pool.close()
        return []

def decrypt_data(encrypted_data):
    if not encrypted_data:
        return None
    try:
        if isinstance(encrypted_data, bytes):
            return cipher_suite.decrypt(encrypted_data).decode()
        return None
    except Exception:
        return None

def get_password_for_user(host, username):
    pool = get_db_pool()
    if not pool:
        return None, None
    conn = None
    try:
        conn = pool.acquire()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE UPPER(COMPONENT_NAME) = UPPER(:h)
              AND UPPER(USERNAME) = UPPER(:u)
            FETCH FIRST 1 ROW ONLY
        """, h=host, u=username)
        row = cursor.fetchone()
        if row and row[0]:
            return decrypt_data(row[0].read() if hasattr(row[0], 'read') else row[0]), "specific"

        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_NAME = 'default'
              AND UPPER(USERNAME) = UPPER(:u)
            FETCH FIRST 1 ROW ONLY
        """, u=username)
        row = cursor.fetchone()
        if row and row[0]:
            return decrypt_data(row[0].read() if hasattr(row[0], 'read') else row[0]), "default"
        return None, None
    finally:
        if cursor:
            cursor.close()
        if conn:
            pool.release(conn)
        if pool:
            pool.close()

def run_discovery_with_password(host, password, username="root", timeout=DEFAULT_TIMEOUT, debug=False):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password, timeout=12,
                       allow_agent=False, look_for_keys=False)
        cmd = f"cd /home/maatest/mchafin/MAA_APPS_NEW && python3 -u {DISCOVERY_SCRIPT} {host} --json"
        if debug:
            cmd += " --debug"
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        output = stdout.read().decode() + stderr.read().decode()
        client.close()
        return output, True
    except paramiko.AuthenticationException:
        logger.debug(f"[{host}] Password auth failed for user {username}")
        return "", False
    except Exception as e:
        logger.debug(f"[{host}] Password-based discovery failed ({username}): {e}")
        return "", False

def extract_cluster_key_and_members(raw_output, seed_host, debug=False):
    members = []
    try:
        json_match = re.search(r'\[\s*\{.*\}\s*\]', raw_output, re.DOTALL)
        if json_match:
            members = json.loads(json_match.group(0))
    except:
        pass

    if not members:
        try:
            start = raw_output.rfind('[')
            if start != -1:
                json_str = raw_output[start:].strip()
                if json_str.endswith(']'):
                    members = json.loads(json_str)
        except:
            pass

    if not members:
        if debug:
            logger.debug(f"[{seed_host}] No valid members found in discovery output")
        return [], [], seed_host

    clean_members = []
    cluster_key = []
    for m in members:
        h = m.get("management_hostname", "")
        t = m.get("type", "")
        if t in ("Database Server", "Storage Server"):
            clean_members.append(m)
            cluster_key.append(h)
        elif debug and t == "Guest":
            logger.debug(f"[{seed_host}] → DISCARD (Guest): {h}")

    cluster_key = sorted(set(cluster_key))
    db_servers = sorted([h for h in cluster_key if 'cel' not in h.lower()])
    canonical_host = db_servers[0] if db_servers else (cluster_key[0] if cluster_key else seed_host)

    if debug:
        logger.debug(f"[{seed_host}] Final cluster_key: {cluster_key}")
        logger.debug(f"[{seed_host}] Canonical host chosen: {canonical_host}")

    return cluster_key, clean_members, canonical_host

def run_discovery(host, timeout=DEFAULT_TIMEOUT, debug=False):
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "-o", "BatchMode=yes", f"root@{host}", "echo OK"],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode == 0 and "OK" in result.stdout:
            cmd = ["python3", "-u", DISCOVERY_SCRIPT, host, "--json"]
            if debug:
                cmd.append("--debug")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                    cwd=os.path.dirname(DISCOVERY_SCRIPT))
            return result.stdout + (result.stderr or ""), result.returncode == 0
    except:
        pass

    for username in ["root", "oracle"]:
        password, source = get_password_for_user(host, username)
        if password:
            source_label = "SPECIFIC" if source == "specific" else "DEFAULT"
            logger.info(f"[{host}] Using {source_label} {username} password from DB")
            output, success = run_discovery_with_password(host, password, username, timeout, debug)
            if success:
                return output, True
            else:
                logger.debug(f"[{host}] {username} password failed (source: {source})")
        else:
            logger.debug(f"[{host}] No {username} password found in DB")

    logger.warning(f"[{host}] No working authentication method found")
    return "", False

def generate_proper_oeda_xml(cluster_name, members):
    work_dir = os.path.join(OUTPUT_DIR, f"discover_{cluster_name}_{datetime.now().strftime('%H%M%S')}")
    os.makedirs(work_dir, exist_ok=True)
    hostnames = ",".join([m['management_hostname'] for m in members])
    location = os.path.join(work_dir, "discovered")

    cmd_file = os.path.join(work_dir, "commands.txt")
    with open(cmd_file, "w") as f:
        f.write(f"DISCOVER ES HOSTNAMES='{hostnames}' LOCATION={location}\n")
        f.write("EXIT\n")

    cmd = [OEDACLI_BINARY, "-f", cmd_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                                cwd=os.path.dirname(OEDACLI_BINARY))
        xml_files = []
        for root, dirs, files in os.walk(work_dir):
            for f in files:
                if f.endswith(".xml"):
                    xml_files.append(os.path.join(root, f))
        if xml_files:
            with open(xml_files[0], 'r', encoding='utf-8') as f:
                return f.read()
        else:
            logger.error(f"No XML file generated for {cluster_name}")
            return None
    except subprocess.TimeoutExpired:
        logger.error(f"XML generation timed out for {cluster_name}")
        return None
    except Exception as e:
        logger.error(f"XML generation exception for {cluster_name}: {e}")
        return None
    finally:
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)

def save_config(seed_host, cluster_key, members, canonical_host, raw_output, debug=False):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"es_{seed_host}_{timestamp}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)
    config = {
        "cluster_key": cluster_key,
        "members": members,
        "generated_at": datetime.now().isoformat(),
        "source": "generate_oedacli_configs.py v1.36"
    }
    with open(filepath, "w") as f:
        json.dump(config, f, indent=2)
    if debug:
        with open(os.path.join(OUTPUT_DIR, f"debug_raw_{seed_host}.txt"), "w") as f:
            f.write(raw_output)
    logger.info(f"✅ Saved config: {filepath}")
    return filepath, config

def meets_minimum_size(members):
    db_count = sum(1 for m in members if m.get("type") == "Database Server")
    cell_count = sum(1 for m in members if m.get("type") == "Storage Server")
    return db_count >= 2 and cell_count >= 3

def store_in_db(canonical_host, cluster_key, members, debug=False):
    if not meets_minimum_size(members):
        db_count = sum(1 for m in members if m.get("type") == "Database Server")
        cell_count = sum(1 for m in members if m.get("type") == "Storage Server")
        skipped_clusters.append({
            "canonical_host": canonical_host,
            "host_count": len(cluster_key),
            "db_count": db_count,
            "cell_count": cell_count,
            "reason": "Too small (needs ≥2 DB + ≥3 cells)"
        })
        logger.info(f"⏭️ Skipped {canonical_host} — does not meet minimum size")
        return False

    with lock:
        if canonical_host in processed_canonical_hosts:
            return False

        pool = get_db_pool()
        if not pool:
            return False

        try:
            proper_xml = generate_proper_oeda_xml(canonical_host, members)
            if not proper_xml:
                logger.error(f"Failed to generate proper XML for {canonical_host}")
                return False

            clean_json = {
                "cluster_key": cluster_key,
                "members": members,
                "generated_at": datetime.now().isoformat(),
                "source": "generate_oedacli_configs.py v1.36"
            }

            conn = pool.acquire()
            cursor = conn.cursor()

            # === FIXED: Proper CLOB binding to avoid ORA-01461 ===
            cursor.setinputsizes(
                xml_content=oracledb.CLOB,
                proper_xml=oracledb.CLOB
            )

            cursor.execute("""
                MERGE INTO MAAMD.OEDACLI_CONFIGS t
                USING (
                    SELECT :canonical_host AS SYSTEM_ALLOCATION_ID,
                           :config_name    AS CONFIG_NAME,
                           :xml_content    AS XML_CONTENT,
                           :proper_xml     AS PROPER_OEDA_XML,
                           :created_by     AS CREATED_BY
                    FROM dual
                ) s
                ON (t.SYSTEM_ALLOCATION_ID = s.SYSTEM_ALLOCATION_ID)
                WHEN MATCHED THEN
                    UPDATE SET 
                        t.CONFIG_NAME     = s.CONFIG_NAME,
                        t.XML_CONTENT     = s.XML_CONTENT,
                        t.PROPER_OEDA_XML = s.PROPER_OEDA_XML,
                        t.VERSION         = t.VERSION + 1
                WHEN NOT MATCHED THEN
                    INSERT (SYSTEM_ALLOCATION_ID, CONFIG_NAME, XML_CONTENT, PROPER_OEDA_XML, CREATED_BY, VERSION)
                    VALUES (s.SYSTEM_ALLOCATION_ID, s.CONFIG_NAME, s.XML_CONTENT, s.PROPER_OEDA_XML, s.CREATED_BY, 1)
            """, {
                'canonical_host': canonical_host,
                'config_name': f"es_{canonical_host}",
                'xml_content': json.dumps(clean_json, indent=2),
                'proper_xml': proper_xml,
                'created_by': 'generate_oedacli_configs'
            })

            conn.commit()
            cursor.close()
            pool.release(conn)
            pool.close()

            processed_canonical_hosts.add(canonical_host)

            db_count = sum(1 for m in members if m.get("type") == "Database Server")
            cell_count = sum(1 for m in members if m.get("type") == "Storage Server")
            successful_clusters.append({
                "canonical_host": canonical_host,
                "host_count": len(cluster_key),
                "db_count": db_count,
                "cell_count": cell_count
            })
            logger.info(f"✅ Stored in DB: {canonical_host} — UNIQUE cluster + proper XML (version incremented if existed)")
            return True

        except Exception as e:
            logger.error(f"DB upsert failed for {canonical_host}: {e}")
            if pool:
                pool.close()
            return False

def process_host(host, timeout, debug, store_db):
    raw_output, success = run_discovery(host, timeout, debug)
    if not success or not raw_output:
        logger.warning(f"❌ Discovery failed for {host}")
        return None

    cluster_key, members, canonical_host = extract_cluster_key_and_members(raw_output, host, debug)
    if not cluster_key:
        return None

    with lock:
        if canonical_host in processed_canonical_hosts:
            return None

    filepath, config = save_config(host, cluster_key, members, canonical_host, raw_output, debug)
    if store_db:
        store_in_db(canonical_host, cluster_key, members, debug)
    return {"host": host, "canonical_host": canonical_host, "filepath": filepath}

def print_final_report():
    print("\n" + "="*80)
    print(" OEDACLI CONFIG GENERATION REPORT (v1.36)")
    print("="*80)
    print(f"\n✅ SUCCESSFUL CLUSTERS ({len(successful_clusters)})")
    print("-" * 80)
    if successful_clusters:
        for i, c in enumerate(successful_clusters, 1):
            print(f"{i:2}. {c['canonical_host']:<35} | {c['db_count']} DB + {c['cell_count']} Cells | {c['host_count']} total hosts")
    else:
        print(" None")

    print(f"\n❌ UNSUCCESSFUL / SKIPPED CLUSTERS ({len(skipped_clusters)})")
    print("-" * 80)
    if skipped_clusters:
        for i, c in enumerate(skipped_clusters, 1):
            print(f"{i:2}. {c['canonical_host']:<35} | {c['host_count']} hosts ({c['db_count']} DB + {c['cell_count']} Cells) → {c['reason']}")
    else:
        print(" None")

    print("\n" + "="*80)
    print(f"Final Summary: {len(successful_clusters)} valid clusters stored | {len(skipped_clusters)} skipped")
    print("="*80 + "\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--max-workers", type=int, default=MAX_WORKERS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--store-db", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    setup_output_dir()
    hosts = args.host or (get_database_servers_from_db() if args.all else [])
    if not hosts:
        logger.error("No hosts provided.")
        sys.exit(1)

    logger.info(f"Starting bulk discovery for {len(hosts)} hosts...")
    results = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {executor.submit(process_host, h, args.timeout, args.debug, args.store_db): h for h in hosts}
        for future in tqdm(as_completed(futures), total=len(hosts), desc="Discovering clusters"):
            if future.result():
                results.append(future.result())

    logger.info(f"\n🎉 Done! Hosts processed: {len(results)} | Unique valid clusters stored: {len(processed_canonical_hosts)}")
    print_final_report()

if __name__ == "__main__":
    main()
