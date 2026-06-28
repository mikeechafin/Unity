#!/usr/bin/env python3
"""
RTI Configuration Refresh Job
- Fetches current metric configuration from all Exadata hosts
- Saves to MAAMD.RTI_METRIC_SETTINGS table
- Can be run manually or scheduled as a job
- Usage: python3 refresh_rti_configs.py [--host HOSTNAME] [--all]

This ensures the database always has the latest configuration from live hosts,
which can be used to restore settings if a storage server is rebuilt.
"""

import sys
import os
import json
from datetime import datetime, timezone
from maa_libraries import logger, get_db_connection_standalone, get_credential_silent
import paramiko

def get_rti_servers():
    """Get all storage and compute servers from SYSTEM_ALLOCATIONS"""
    servers = []
    try:
        conn = get_db_connection_standalone()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT UPPER(SYSTEM_NAME) as HOSTNAME 
            FROM MAAMD.SYSTEM_ALLOCATIONS 
            WHERE UPPER(SYSTEM_NAME) LIKE '%CEL%' OR UPPER(SYSTEM_NAME) LIKE '%DB%' 
               OR UPPER(SYSTEM_NAME) LIKE '%ADM%'
            ORDER BY HOSTNAME
        """)
        for row in cursor.fetchall():
            host = row[0]
            typ = 'STORAGE' if 'CEL' in host else 'COMPUTE'
            servers.append({'hostname': host, 'type': typ})
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to get servers: {e}")
    return servers

def robust_ssh_connect(hostname, username='root', timeout=20):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, key_filename="/home/maatest/.ssh/id_rsa", timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
        return ssh, "keyfile"
    except:
        pass
    password = None
    try:
        conn = get_db_connection_standalone()
        cursor = conn.cursor()
        password = get_credential_silent(cursor, 'default', hostname, username) or get_credential_silent(cursor, 'default', 'default', username)
        cursor.close()
        conn.close()
    except:
        pass
    if password:
        try:
            ssh.connect(hostname, username=username, password=password, timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
            return ssh, "password"
        except:
            pass
    raise Exception(f"SSH failed for {hostname}")

def run_cellcli_or_dcli(host, cmd, is_storage=True):
    """Execute command via dcli/dcli_compute"""
    try:
        if is_storage:
            full_cmd = f"dcli -c {host} -l root 'cellcli -e \"{cmd}\"' 2>&1"
        else:
            full_cmd = f"dcli_compute -c {host} -l root 'dbmcli -e \"{cmd}\"' 2>&1"
        
        ssh, _ = robust_ssh_connect('localhost', 'maatest')
        stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=60)
        out = stdout.read().decode('utf-8', errors='ignore').strip()
        ssh.close()
        
        if out.startswith(host + ':'):
            out = out.split(':', 1)[1].strip()
        
        return out, "", 0
    except Exception as e:
        return "", str(e), 1

def fetch_host_config(host, is_storage):
    """Fetch current metric configuration from a host"""
    try:
        cmd = "list metricdefinition attributes name,finegrained,streaming"
        out, err, rc = run_cellcli_or_dcli(host, cmd, is_storage)
        
        if rc != 0 or 'Permission' in out or 'disconnect' in out.lower():
            return None, f"Failed to fetch: {err or out[:100]}"
        
        metrics = {}
        for line in out.splitlines():
            line = line.strip()
            if not line or ':' in line:
                if ':' in line:
                    line = line.split(':', 1)[1].strip()
            parts = line.split()
            if len(parts) >= 3:
                name = parts[0]
                metrics[name] = {
                    'finegrained': parts[1].lower() == 'enabled',
                    'streaming': parts[2].lower() == 'enabled'
                }
        
        return metrics, None
    except Exception as e:
        return None, str(e)

def save_to_database(host, metrics, host_type):
    """Save metrics to RTI_METRIC_SETTINGS table"""
    try:
        conn = get_db_connection_standalone()
        cursor = conn.cursor()
        
        # Delete old entries for this host
        cursor.execute("DELETE FROM MAAMD.RTI_METRIC_SETTINGS WHERE HOSTNAME = :hostname", {'hostname': host})
        
        # Insert all metrics
        for metric_name, settings in metrics.items():
            cursor.execute("""
                INSERT INTO MAAMD.RTI_METRIC_SETTINGS 
                (HOSTNAME, METRIC_NAME, FINEGRAINED, STREAMING, LAST_UPDATED)
                VALUES (:hostname, :metric, :fine, :stream, CURRENT_TIMESTAMP)
            """, {
                'hostname': host,
                'metric': metric_name,
                'fine': 'enabled' if settings['finegrained'] else 'disabled',
                'stream': 'enabled' if settings['streaming'] else 'disabled'
            })
        
        conn.commit()
        cursor.close()
        conn.close()
        return True, len(metrics)
    except Exception as e:
        return False, str(e)

def refresh_host(host, host_type):
    """Refresh configuration for a single host"""
    print(f"\n{'='*60}")
    print(f"Refreshing: {host} ({host_type})")
    print(f"{'='*60}")
    
    is_storage = host_type == 'STORAGE'
    
    # Fetch current config from host
    print(f"[1/3] Fetching current config from {host}...")
    metrics, error = fetch_host_config(host, is_storage)
    
    if error:
        print(f"✗ Failed: {error}")
        return False
    
    print(f"✓ Fetched {len(metrics)} metrics")
    
    # Save to database
    print(f"[2/3] Saving to database...")
    success, result = save_to_database(host, metrics, host_type)
    
    if not success:
        print(f"✗ Database save failed: {result}")
        return False
    
    print(f"✓ Saved {result} metrics to RTI_METRIC_SETTINGS")
    
    # Also update global settings
    print(f"[3/3] Updating global settings...")
    try:
        conn = get_db_connection_standalone()
        cursor = conn.cursor()
        cursor.execute("""
            MERGE INTO MAAMD.RTI_SERVER_CONFIG t
            USING (SELECT :hostname AS HOSTNAME FROM DUAL) s
            ON (t.HOSTNAME = s.HOSTNAME)
            WHEN MATCHED THEN UPDATE SET
                TYPE = :type,
                LAST_UPDATED = CURRENT_TIMESTAMP
            WHEN NOT MATCHED THEN INSERT 
                (HOSTNAME, TYPE, FG_COLL_INTVL_SEC, STREAM_INTVL_SEC, TAGS, UPDATED_BY)
            VALUES (:hostname, :type, 5, 60, '{"fleet":"MAA_Lab"}', 'refresh_job')
        """, {
            'hostname': host,
            'type': host_type
        })
        conn.commit()
        cursor.close()
        conn.close()
        print(f"✓ Global settings updated")
    except Exception as e:
        print(f"⚠ Global settings update failed: {e}")
    
    print(f"✓ {host} refresh complete!")
    return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Refresh RTI configurations from live hosts')
    parser.add_argument('--host', help='Refresh specific host only')
    parser.add_argument('--all', action='store_true', help='Refresh all hosts')
    parser.add_argument('--storage-only', action='store_true', help='Only refresh storage cells')
    parser.add_argument('--compute-only', action='store_true', help='Only refresh compute nodes')
    
    args = parser.parse_args()
    
    print("="*60)
    print("RTI Configuration Refresh Job")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("="*60)
    
    if args.host:
        # Refresh specific host
        host_type = 'STORAGE' if 'CEL' in args.host.upper() else 'COMPUTE'
        success = refresh_host(args.host, host_type)
        sys.exit(0 if success else 1)
    
    # Get all servers
    servers = get_rti_servers()
    
    if not servers:
        print("✗ No servers found in SYSTEM_ALLOCATIONS")
        sys.exit(1)
    
    # Filter if needed
    if args.storage_only:
        servers = [s for s in servers if s['type'] == 'STORAGE']
    elif args.compute_only:
        servers = [s for s in servers if s['type'] == 'COMPUTE']
    
    print(f"\nFound {len(servers)} servers to refresh")
    
    success_count = 0
    fail_count = 0
    
    for server in servers:
        if refresh_host(server['hostname'], server['type']):
            success_count += 1
        else:
            fail_count += 1
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total servers: {len(servers)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {fail_count}")
    print(f"Completed: {datetime.now(timezone.utc).isoformat()}")
    print("="*60)
    
    sys.exit(0 if fail_count == 0 else 1)

if __name__ == '__main__':
    main()
