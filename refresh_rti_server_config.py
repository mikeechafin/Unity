#!/usr/bin/env python3
"""
refresh_rti_server_config.py
Final production version with correct endpoint handling:
- Only stores endpoint if the host actually has metricStreamURL configured
- Otherwise stores blank (NULL) so the UI shows empty for most hosts
"""

import subprocess
import tempfile
import os
from maa_libraries import logger
from maa_db_pool import get_db_pool_connection, release_db_pool_connection

def create_temp_group(hosts):
    fd, path = tempfile.mkstemp(prefix="rti_group_", suffix=".txt")
    with os.fdopen(fd, 'w') as f:
        for h in hosts:
            f.write(h + "\n")
    return path

def run_dcli_with_group(group_file, cmd, is_storage=True):
    cli = "dcli" if is_storage else "dcli_compute"
    ssh_opts = "-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no"
    try:
        result = subprocess.run(
            [cli, "-g", group_file, "-l", "root", "-s", ssh_opts, cmd],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1

def parse_dcli_output(output):
    """Parse dcli output. Returns endpoint ONLY if host has it configured."""
    config = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or ':' not in line:
            continue
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue
        host = parts[0].strip().upper()
        values = parts[1].strip().split()

        fg = int(values[0]) if len(values) > 0 and values[0].isdigit() else 5
        stream = int(values[1]) if len(values) > 1 and values[1].isdigit() else 60
        tags = values[2] if len(values) > 2 else '{"fleet":"MAA_Lab"}'

        # Only store endpoint if it looks like a real URL (not blank or default)
        endpoint = ""
        if len(values) > 3:
            val = values[3].strip()
            if val and val.startswith("http"):
                endpoint = val

        config[host] = (fg, stream, tags, endpoint)
    return config

def refresh_rti_server_config():
    print("\n=== RTI Server Config Refresh Started ===")
    logger.info("=== Starting RTI Server Config Refresh (correct endpoint handling) ===")

    conn = None
    cell_group = None
    compute_group = None

    try:
        conn = get_db_pool_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT DISTINCT UPPER(SYSTEM_NAME)
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE UPPER(SYSTEM_NAME) LIKE '%CEL%'
            ORDER BY 1
        """)
        storage_hosts = [row[0] for row in cur.fetchall()]

        cur.execute("""
            SELECT DISTINCT UPPER(SYSTEM_NAME)
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE UPPER(SYSTEM_NAME) LIKE '%DB%' OR UPPER(SYSTEM_NAME) LIKE '%ADM%'
            ORDER BY 1
        """)
        compute_hosts = [row[0] for row in cur.fetchall()]

        print(f"Found {len(storage_hosts)} storage cells + {len(compute_hosts)} compute nodes")

        all_config = {}

        if storage_hosts:
            print(f"\nCollecting from {len(storage_hosts)} storage cells via dcli...")
            cell_group = create_temp_group(storage_hosts)
            cmd = "cellcli -e 'list cell attributes metricFGCollIntvlInSec, metricStreamIntvlInSec, metricStreamTags, metricStreamURL'"
            out, err, rc = run_dcli_with_group(cell_group, cmd, is_storage=True)
            all_config.update(parse_dcli_output(out))

        if compute_hosts:
            print(f"Collecting from {len(compute_hosts)} compute nodes via dcli_compute...")
            compute_group = create_temp_group(compute_hosts)
            cmd = "dbmcli -e 'list dbserver attributes metricFGCollIntvlInSec, metricStreamIntvlInSec, metricStreamTags, metricStreamURL'"
            out, err, rc = run_dcli_with_group(compute_group, cmd, is_storage=False)
            all_config.update(parse_dcli_output(out))

        print(f"\n✅ Successfully collected config from {len(all_config)} hosts")

        # Update database
        updated = 0
        for hostname, (fg, stream, tags, endpoint) in all_config.items():
            htype = 'STORAGE' if 'CEL' in hostname else 'COMPUTE'
            cur.execute("""
                MERGE INTO MAAMD.RTI_SERVER_CONFIG t
                USING (SELECT :hostname AS HOSTNAME, :type AS TYPE FROM DUAL) s
                ON (t.HOSTNAME = s.HOSTNAME)
                WHEN MATCHED THEN UPDATE SET
                    t.TYPE = s.TYPE,
                    t.FG_COLL_INTVL_SEC = :fg,
                    t.STREAM_INTVL_SEC  = :stream,
                    t.TAGS              = :tags,
                    t.ENDPOINT          = :endpoint,
                    t.LAST_UPDATED      = SYSTIMESTAMP,
                    t.UPDATED_BY        = 'refresh_rti_server_config'
                WHEN NOT MATCHED THEN INSERT (
                    HOSTNAME, TYPE, FG_COLL_INTVL_SEC, STREAM_INTVL_SEC, TAGS, ENDPOINT, LAST_UPDATED, UPDATED_BY
                ) VALUES (
                    s.HOSTNAME, s.TYPE, :fg, :stream, :tags, :endpoint, SYSTIMESTAMP, 'refresh_rti_server_config'
                )
            """, {
                'hostname': hostname,
                'type': htype,
                'fg': fg,
                'stream': stream,
                'tags': tags,
                'endpoint': endpoint
            })
            updated += 1
            if updated % 50 == 0:
                print(f"  Updated {updated} hosts...")

        conn.commit()
        print(f"\n✅ Successfully refreshed {updated} hosts with LIVE configuration")

        # Show how many have real endpoints
        cur.execute("SELECT COUNT(*) FROM MAAMD.RTI_SERVER_CONFIG WHERE ENDPOINT IS NOT NULL AND ENDPOINT != ''")
        with_endpoint = cur.fetchone()[0]
        print(f"📊 Hosts with real endpoint configured: {with_endpoint} / {updated}")

        cur.execute("""
            SELECT COUNT(*), AVG(FG_COLL_INTVL_SEC), AVG(STREAM_INTVL_SEC)
            FROM MAAMD.RTI_SERVER_CONFIG
        """)
        total, avg_fg, avg_stream = cur.fetchone()
        print(f"📊 Total in DB: {total} | Avg FG: {avg_fg:.1f}s | Avg STREAM: {avg_stream:.1f}s")

        logger.info(f"✅ RTI Server Config refreshed for {updated} hosts")

    except Exception as e:
        print(f"❌ ERROR: {e}")
        logger.error(f"RTI Server Config refresh failed: {e}")
        if conn:
            conn.rollback()
    finally:
        for g in [cell_group, compute_group]:
            if g and os.path.exists(g):
                os.remove(g)
        if conn:
            release_db_pool_connection(conn)
        print("=== RTI Server Config Refresh Finished ===\n")

if __name__ == "__main__":
    refresh_rti_server_config()
