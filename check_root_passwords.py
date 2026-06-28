#!/usr/bin/env python3
# check_root_passwords.py
# Version: 2026-04-23 v1.0
# Purpose: Generate a clean report of which hosts have working vs broken root passwords

import os
import sys
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import oracledb
from cryptography.fernet import Fernet

# ====================== CONFIG ======================
DB_USER = "maamd"
DB_DSN = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
SSH_TIMEOUT = 12
MAX_WORKERS = 15

if not DB_PASSWORD:
    print("ERROR: DB_PASSWORD environment variable not set")
    sys.exit(1)

# Encryption key
import config

key_file = config.ENCRYPTION_KEY_FILE
with open(key_file, 'rb') as f:
    ENCRYPTION_KEY = f.read()
cipher_suite = Fernet(ENCRYPTION_KEY)

def decrypt_credential(enc_blob):
    try:
        if enc_blob:
            return cipher_suite.decrypt(enc_blob.read() if hasattr(enc_blob, 'read') else enc_blob).decode()
        return None
    except:
        return None

def get_db_connection():
    return oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN)

def get_root_password(host):
    """Returns (password, source) where source is 'specific' or 'default'"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 1. Try specific credential first
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE UPPER(COMPONENT_NAME) = UPPER(:host)
              AND UPPER(USERNAME) = 'ROOT'
            FETCH FIRST 1 ROW ONLY
        """, host=host)
        row = cursor.fetchone()
        if row and row[0]:
            pwd = decrypt_credential(row[0])
            if pwd:
                return pwd, "specific"

        # 2. Fall back to default
        cursor.execute("""
            SELECT ENCRYPTED_PASSWORD
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE COMPONENT_NAME = 'default'
              AND UPPER(USERNAME) = 'ROOT'
            FETCH FIRST 1 ROW ONLY
        """)
        row = cursor.fetchone()
        if row and row[0]:
            pwd = decrypt_credential(row[0])
            if pwd:
                return pwd, "default"
        return None, None
    finally:
        cursor.close()
        conn.close()

def test_host(host):
    password, source = get_root_password(host)
    if not password:
        return {
            'host': host,
            'result': 'NO_PASSWORD',
            'source': None,
            'error': 'No root password found in database'
        }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            username="root",
            password=password,
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False
        )
        return {
            'host': host,
            'result': 'SUCCESS',
            'source': source,
            'error': None
        }
    except paramiko.AuthenticationException:
        return {
            'host': host,
            'result': 'AUTH_FAILED',
            'source': source,
            'error': 'Authentication failed (wrong password)'
        }
    except Exception as e:
        return {
            'host': host,
            'result': 'CONNECTION_ERROR',
            'source': source,
            'error': str(e)
        }
    finally:
        try:
            client.close()
        except:
            pass

def main():
    print(f"\n{'='*80}")
    print("ROOT PASSWORD VALIDATION REPORT")
    print(f"Generated: {datetime.now()}")
    print(f"{'='*80}\n")

    # Get all hosts from SYSTEM_ALLOCATIONS
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT SYSTEM_NAME FROM MAAMD.SYSTEM_ALLOCATIONS ORDER BY SYSTEM_NAME")
    hosts = [row[0] for row in cursor]
    cursor.close()
    conn.close()

    print(f"Testing {len(hosts)} hosts...\n")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_host = {executor.submit(test_host, host): host for host in hosts}
        for future in as_completed(future_to_host):
            results.append(future.result())

    # Sort results
    results.sort(key=lambda x: x['host'])

    # Print summary
    success = [r for r in results if r['result'] == 'SUCCESS']
    auth_failed = [r for r in results if r['result'] == 'AUTH_FAILED']
    no_password = [r for r in results if r['result'] == 'NO_PASSWORD']
    connection_error = [r for r in results if r['result'] == 'CONNECTION_ERROR']

    print(f"{'HOST':<45} {'RESULT':<15} {'SOURCE':<12} {'ERROR'}")
    print("-" * 100)

    for r in results:
        source_str = r['source'] or '-'
        error_str = r['error'] or ''
        print(f"{r['host']:<45} {r['result']:<15} {source_str:<12} {error_str}")

    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total hosts tested     : {len(results)}")
    print(f"✓ Working passwords    : {len(success)}")
    print(f"✗ Wrong password       : {len(auth_failed)}")
    print(f"✗ No password in DB    : {len(no_password)}")
    print(f"✗ Connection error     : {len(connection_error)}")
    print("="*80 + "\n")

    if auth_failed:
        print("HOSTS WITH WRONG ROOT PASSWORD (need fixing in DB):")
        for r in auth_failed:
            print(f"  - {r['host']}")

if __name__ == "__main__":
    main()
