#!/usr/bin/env python3
"""
MAA Unified - Exadata Discovery (CLI-first version)
Version: 2026-02-26 v5.9.3
Changes: Real rack serials from ILOM data (multi-rack support). Dynamic ORACLE_HOME discovery from inventory.xml + oraInst.loc. olsnodes run from correct Grid home on every COMPUTE node. Parse EVERY collected databasemachine.xml for cluster verification. Debug output for clusters. Real serial per rack in summary. Logical clusters identified for every rack (using serial from each host's ILOM, no reliance on single XML). All racks created first. COMMIT after racks + servers before logical clusters to fix ORA-02291.
"""
import argparse
import re
import xml.etree.ElementTree as ET
import sys
import logging
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko
import threading
import io
import subprocess
from collections import Counter, defaultdict
from maa_libraries import logger, get_db_connection_standalone, get_credential_silent, derive_rack_name, decrypt_data
logger.setLevel(logging.INFO)
print_lock = threading.Lock()
paramiko.util.log_to_file('/dev/null', level='WARNING')
#####
#####
def robust_ssh_connect(hostname, username='root', key_filename="/home/maatest/.ssh/id_rsa", timeout=25, logger=None):
    """Connect via SSH with key preference, fallback to password. Logs to provided logger (no stdout prints)."""
    if logger is None:
        logger = logging.getLogger('exadata_discovery')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_key = get_ssh_private_key_for_user(hostname, username)
        if ssh_key:
            for key_class in [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]:
                try:
                    pkey = key_class.from_private_key(io.StringIO(ssh_key))
                    ssh.connect(hostname, username=username, pkey=pkey, timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
                    return ssh, "SSH key"
                except Exception as e:
                    if "q must be exactly 160, 224, or 256 bits long" in str(e) or "unhandled type 3" in str(e):
                        logger.info(f" DSA key error on {hostname} — falling back to default password")
                    continue
        ssh.connect(hostname, username=username, key_filename=key_filename, timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
        return ssh, "SSH key"
    except Exception as e:
        if "q must be exactly 160, 224, or 256 bits long" in str(e) or "unhandled type 3" in str(e):
            logger.info(f" DSA key error on {hostname} — falling back to default password")
        else:
            raise
    # Password fallback
    password = None
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    for ct in ['PHYSICAL_HOST', 'GUEST', 'default', 'ILOM']:
        password = get_credential_silent(cursor, ct, hostname, username) or get_credential_silent(cursor, ct, 'default', username)
        if password:
            break
    cursor.close()
    conn.close()
    if password:
        try:
            ssh.connect(hostname, username=username, password=password, timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
            return ssh, "password fallback"
        except Exception as e:
            raise Exception(f"password fallback failed: {str(e)[:100]}")
    raise Exception("No password found for fallback")
#####
#####
def resolve_fqdn(hostname):
    if not hostname:
        return ''
    host = hostname.strip().lower()
    if '.' in host:
        return host
    try:
        fqdn = socket.getfqdn(host)
        if fqdn and '.' in fqdn and fqdn != host:
            return fqdn.lower()
    except:
        pass
    return host + '.us.oracle.com'
def build_ilom_fqdn(hostname, suffix):
    short = hostname.split('.')[0]
    domain = '.' + '.'.join(hostname.split('.')[1:]) if '.' in hostname else ''
    return short + suffix + domain
def get_short_name(hostname):
    return hostname.split('.')[0] if '.' in hostname else hostname
def resolve_ip(hostname):
    if not hostname:
        return 'UNKNOWN'
    try:
        return socket.gethostbyname(hostname)
    except:
        pass
    try:
        out = subprocess.check_output(['host', hostname], timeout=5).decode('utf-8', errors='ignore')
        for line in out.splitlines():
            if 'has address' in line:
                return line.split()[-1]
    except:
        pass
    return 'UNKNOWN'
def parse_hostname(hostname):
    h = resolve_fqdn(hostname).split('.')[0].lower()
    match = re.match(r'^(?P<location>[a-z]{3})(?P<generation>[a-z]{2,3})(?P<rack>\d{2})(?P<component>[a-z0-9-]+?)(?P<position>\d*)$', h)
    if match:
        return {
            'location_code': match.group('location'),
            'generation_code': match.group('generation'),
            'rack_sequence': match.group('rack'),
            'component_code': match.group('component'),
            'position_number': match.group('position')
        }
    return {'location_code': '', 'generation_code': '', 'rack_sequence': '', 'component_code': '', 'position_number': ''}
def parse_imageinfo(output: str) -> dict:
    info = {}
    for match in re.finditer(r'^(.*?):\s*(.*)$', output, re.MULTILINE):
        key = match.group(1).strip().lower().replace(' ', '_').replace('/', '_').replace('active_', '')
        info[key] = match.group(2).strip()
    node = info.get('node_type') or info.get('active_node_type') or 'UNKNOWN'
    typ_map = {'STORAGE': 'STORAGE', 'KVMHOST': 'KVMHOST', 'GUEST': 'GUEST', 'COMPUTE': 'COMPUTE'}
    return {'node_type': typ_map.get(node, node)}
def parse_databasemachine_xml(xml_content: str) -> dict:
    if not xml_content.strip() or "NO_FILE" in xml_content:
        return {'racks': [], 'status': 'MISSING'}
    try:
        root = ET.fromstring(xml_content)
        racks = []
        for rack_elem in root.findall('.//RACK'):
            rack = {
                'id': rack_elem.get('ID'),
                'serial': rack_elem.findtext('RACK_SERIAL'),
                'machine_type': rack_elem.findtext('MACHINETYPE'),
                'machine_usize': int(rack_elem.findtext('MACHINEUSIZE') or 0),
                'items': []
            }
            for item_elem in rack_elem.findall('.//ITEM'):
                item = {child.tag.lower(): (child.text or '').strip() for child in item_elem}
                if 'type' in item:
                    tmap = {'cellnode': 'STORAGE', 'computenode': 'COMPUTE', 'roce': 'SWITCH', 'cisco': 'SWITCH', 'pdu': 'PDU'}
                    item['component_type'] = tmap.get(item['type'], item['type'].upper())
                rack['items'].append(item)
            racks.append(rack)
        return {'racks': racks, 'status': 'SUCCESS'}
    except Exception:
        return {'racks': [], 'status': 'ERROR'}
def parse_ilom_system(sp_out: str, system_out: str) -> dict:
    combined = sp_out + "\n" + system_out
    info = {}
    for line in combined.splitlines():
        if '=' in line:
            key, value = [x.strip() for x in line.split('=', 1)]
            info[key.lower()] = value
    u_str = info.get('system_location', '')
    u_loc = int(re.sub(r'[^0-9]', '', u_str)) if 'RU' in u_str.upper() else None
    return {
        'rack_serial_number': info.get('serial_number'),
        'host_serial_number': info.get('component_serial_number'),
        'component_model': info.get('component_model'),
        'model': info.get('model'),
        'system_identifier': info.get('system_identifier'),
        'u_location': u_loc
    }
def format_openssh_key(raw_key):
    if not raw_key:
        return None
    if isinstance(raw_key, bytes):
        raw_key = raw_key.decode('utf-8', errors='ignore')
    lines = [line.strip() for line in raw_key.replace('\r\n', '\n').replace('\r', '\n').split('\n') if line.strip()]
    if not lines or not lines[0].startswith('-----BEGIN'):
        return None
    header = lines[0]
    footer = lines[-1] if lines[-1].startswith('-----END') else '-----END OPENSSH PRIVATE KEY-----'
    b64_content = ''.join(line for line in lines[1:-1] if not line.startswith('-----'))
    wrapped = '\n'.join(b64_content[i:i+70] for i in range(0, len(b64_content), 70))
    return f"{header}\n{wrapped}\n{footer}\n"
def get_ssh_private_key_for_user(hostname, username):
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        for comp_type in ['PHYSICAL_HOST', 'GUEST']:
            cursor.execute("""
                SELECT ENCRYPTED_KEY
                FROM ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = :1
                  AND COMPONENT_NAME = :2
                  AND USERNAME = :3
                ORDER BY NVL(LAST_UPDATED_DATE, CREATED_DATE) DESC NULLS LAST
            """, (comp_type, hostname, username))
            row = cursor.fetchone()
            if row and row[0]:
                key = decrypt_data(row[0].read())
                if key:
                    cleaned = format_openssh_key(key)
                    if cleaned and cleaned.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
                        return cleaned
        for comp_type in ['PHYSICAL_HOST', 'GUEST']:
            cursor.execute("""
                SELECT ENCRYPTED_KEY
                FROM ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = :1
                  AND COMPONENT_NAME = 'default'
                  AND USERNAME = :2
                ORDER BY NVL(LAST_UPDATED_DATE, CREATED_DATE) DESC NULLS LAST
            """, (comp_type, username))
            row = cursor.fetchone()
            if row and row[0]:
                key = decrypt_data(row[0].read())
                if key:
                    cleaned = format_openssh_key(key)
                    if cleaned and cleaned.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
                        return cleaned
        return None
    finally:
        cursor.close()
        conn.close()
def get_ilom_password(ilom_host):
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        for ct in ['ILOM', 'Database Server ILOM', 'Storage Server ILOM', 'default']:
            cursor.execute("""
                SELECT ENCRYPTED_PASSWORD
                FROM ACCESS_CREDENTIALS
                WHERE COMPONENT_TYPE = :ct
                  AND (COMPONENT_NAME = :h OR COMPONENT_NAME = 'default')
                  AND USERNAME = 'root'
                FETCH FIRST 1 ROW ONLY
            """, {'ct': ct, 'h': ilom_host})
            row = cursor.fetchone()
            if row and row[0]:
                return decrypt_data(row[0].read())
        return None
    finally:
        cursor.close()
        conn.close()
def find_grid_home(ssh):
    try:
        _, stdout, _ = ssh.exec_command('cat /etc/oraInst.loc 2>/dev/null', timeout=10)
        ora_inst = stdout.read().decode('utf-8', errors='replace')
        inventory_loc = None
        for line in ora_inst.splitlines():
            if line.startswith('inventory_loc='):
                inventory_loc = line.split('=')[1].strip()
                break
        if not inventory_loc:
            return None
        _, stdout, _ = ssh.exec_command(f'cat {inventory_loc}/ContentsXML/inventory.xml 2>/dev/null', timeout=10)
        xml = stdout.read().decode('utf-8', errors='replace')
        for match in re.finditer(r'<HOME NAME="([^"]*)" LOC="([^"]*)" TYPE="O"[^>]*CRS="true"', xml):
            return match.group(2)
        for match in re.finditer(r'<HOME NAME="([^"]*)" LOC="([^"]*)" TYPE="O"', xml):
            if 'grid' in match.group(2).lower() or 'gi' in match.group(2).lower():
                return match.group(2)
        return None
    except:
        return None

#####
#####
def identify_logical_clusters(cursor, rack_id, parsed_xml=None, logger=None):
    if logger is None:
        logger = logging.getLogger('exadata_discovery')

    logger.info(f" → Identifying logical/RAC clusters for rack {rack_id}...")

    cursor.execute("""
        SELECT server_id, hostname, node_type
        FROM MAAMD.EXA_SERVERS
        WHERE rack_id = :rack_id
          AND node_type IN ('COMPUTE', 'KVMHOST', 'GUEST')
    """, {'rack_id': rack_id})
    members = cursor.fetchall()

    from collections import defaultdict
    logical_clusters = defaultdict(lambda: {'server_ids': [], 'type': 'PHYSICAL'})

    for server_id, hostname, node_type in members:
        rac_name = None
        try:
            ssh, _ = robust_ssh_connect(hostname, logger=logger)
            grid_home = find_grid_home(ssh)
            if grid_home:
                logger.info(f"   → Grid home on {hostname}: {grid_home}")
                cmd = f'export ORACLE_HOME={grid_home}; $ORACLE_HOME/bin/olsnodes -c 2>/dev/null | head -1'
                _, stdout, _ = ssh.exec_command(cmd, timeout=15)
                out = stdout.read().decode('utf-8', errors='replace').strip()
                if out and len(out) > 2:
                    rac_name = out.strip()

            if not rac_name:
                for cmd in [
                    'olsnodes -c 2>/dev/null | head -1',
                    'cat /opt/oracle.SupportTools/onecommand/databasemachine.xml 2>/dev/null | grep -oP "(?<=<CLUSTERNAME>)[^<]+"'
                ]:
                    _, stdout, _ = ssh.exec_command(cmd, timeout=12)
                    out = stdout.read().decode('utf-8', errors='replace').strip()
                    if out and len(out) > 2:
                        rac_name = out.strip()
                        break
            ssh.close()
        except:
            pass

        # Option B: supplementary info from best XML (no change to primary logic)
        if not rac_name and parsed_xml and 'clusters' in parsed_xml:
            for cluster in parsed_xml['clusters']:
                if hostname in cluster.get('nodes', []):
                    rac_name = cluster['name']
                    logger.info(f"   → XML fallback for {hostname}: {rac_name}")
                    break

        if not rac_name:
            rac_name = f"Cluster_Rack_{rack_id}"

        if node_type in ('GUEST', 'KVMHOST'):
            logical_clusters[rac_name]['type'] = 'VIRTUAL'
        logical_clusters[rac_name]['server_ids'].append(server_id)

    # Your original MERGE logic (unchanged)
    for name, data in logical_clusters.items():
        cursor.execute("""
            MERGE INTO MAAMD.EXA_CLUSTERS c
            USING (SELECT :rack_id r, :name n FROM DUAL) src
            ON (c.rack_id = src.r AND c.cluster_name = src.n)
            WHEN MATCHED THEN UPDATE SET cluster_type = :typ
            WHEN NOT MATCHED THEN INSERT
                (rack_id, cluster_name, cluster_type, max_guests)
            VALUES (src.r, src.n, :typ, 50)
        """, {'rack_id': rack_id, 'name': name, 'typ': data['type']})

        cursor.execute("""
            SELECT cluster_id FROM MAAMD.EXA_CLUSTERS
            WHERE rack_id = :rack_id AND cluster_name = :name
        """, {'rack_id': rack_id, 'name': name})
        cluster_id = cursor.fetchone()[0]

        for sid in data['server_ids']:
            cursor.execute("""
                MERGE INTO MAAMD.EXA_RAC_MEMBERSHIPS m
                USING (SELECT :cid cid, :sid sid, :name n FROM DUAL) src
                ON (m.cluster_id = src.cid AND m.server_id = src.sid)
                WHEN NOT MATCHED THEN INSERT
                    (rac_name, server_id, cluster_id)
                VALUES (src.n, src.sid, src.cid)
            """, {'cid': cluster_id, 'sid': sid, 'name': name})

    # Storage associations (unchanged)
    cursor.execute("""
        SELECT server_id FROM MAAMD.EXA_SERVERS
        WHERE rack_id = :rack_id AND node_type = 'STORAGE'
    """, {'rack_id': rack_id})
    storage_ids = [row[0] for row in cursor.fetchall()]

    for name in logical_clusters.keys():
        cursor.execute("""
            SELECT cluster_id FROM MAAMD.EXA_CLUSTERS
            WHERE rack_id = :rack_id AND cluster_name = :name
        """, {'rack_id': rack_id, 'name': name})
        cid = cursor.fetchone()[0]
        for sid in storage_ids:
            cursor.execute("""
                MERGE INTO MAAMD.EXA_STORAGE_ASSOCS a
                USING (SELECT :cid cid, :sid sid FROM DUAL) src
                ON (a.cluster_id = src.cid AND a.storage_server_id = src.sid)
                WHEN NOT MATCHED THEN INSERT
                    (cluster_id, storage_server_id)
                VALUES (src.cid, src.sid)
            """, {'cid': cid, 'sid': sid})

    logger.info(f" → Identified {len(logical_clusters)} logical clusters for rack {rack_id}")

    # Option B: extra info from best XML
    if parsed_xml and 'clusters' in parsed_xml:
        xml_clusters = [c.get('name', 'unknown') for c in parsed_xml['clusters']]
        logger.info(f"   → Best XML reports {len(xml_clusters)} clusters: {xml_clusters}")
#####
#####
def full_exadata_discovery(hosts=None, dry_run=False, verbose=False, generate_xml=False, rack=None):
    """
    MAA Unified - Exadata Discovery
    Version: 2026-02-27 v5.9.5-silent-final
    - Console is 100% silent except for the two clean lines (start + complete)
    - ALL output (DSA errors, progress, grid home, summary, failed hosts, etc.) goes ONLY to ./output/exadata_discovery.log
    - Rotating log with 6 backups
    - Enriched racks, fixed summary, stable logical clusters
    """
    import os
    import logging
    from logging.handlers import RotatingFileHandler
    from collections import defaultdict, Counter
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime

    # === STANDARD LOGGING WITH ROLLOVER ===
    log_dir = './output'
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, 'exadata_discovery.log')

    logger = logging.getLogger('exadata_discovery')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=6,
        encoding='utf-8'
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # === MINIMAL CONSOLE OUTPUT ONLY ===
    print(f"=== Exadata Discovery v5.9.5-silent-final Started at {datetime.now()} ===")
    print(f"→ ALL output is being written to: {log_path} (rotating, 6 backups kept)")
    print()

    logger.info(f"=== Exadata Discovery v5.9.5-silent-final Started at {datetime.now()} ===")

    conn = get_db_connection_standalone()
    cursor = conn.cursor()

    if generate_xml:
        xml = generate_databasemachine_xml(cursor, rack)
        logger.info(xml)
        cursor.close()
        conn.close()
        logger.handlers.clear()
        print(f"XML generation complete. See log file: {log_path}")
        return

    if hosts:
        all_hosts = [resolve_fqdn(h.strip()) for h in hosts]
        logger.info(f"Using provided hosts only: {len(all_hosts)}")
    else:
        cursor.execute("""
            SELECT DISTINCT SYSTEM_NAME AS hostname
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE CURRENT_ALLOCATION IS NOT NULL
              AND (END_DATE IS NULL OR END_DATE > SYSDATE)
            ORDER BY 1
        """)
        all_hosts = [resolve_fqdn(row[0]) for row in cursor.fetchall()]

    logger.info(f"Discovered {len(all_hosts)} hosts for scan.")

    if dry_run:
        logger.info("DRY-RUN mode — no SSH, no DB write")
        cursor.close()
        conn.close()
        logger.handlers.clear()
        print(f"Dry-run complete. Log saved to: {log_path}")
        return

    xml_candidates = []
    host_results = []
    first_rack_serial = None

    def discover_host(hostname):
        nonlocal first_rack_serial
        result = {'hostname': hostname, 'success': False, 'node_type': 'UNKNOWN', 'xml_status': 'MISSING', 'ilom_name': None, 'xml_content': None,
                  'rack_serial_number': None, 'host_serial_number': None, 'component_model': None, 'model': None, 'system_identifier': None,
                  'u_location': None, 'admin_ip': None, 'ilom_ip': None, 'rac_name': None, 'guests': [], 'connect_method': None}
        ssh = None
        try:
            ssh, method = robust_ssh_connect(hostname, logger=logger)
            result['connect_method'] = method
            logger.info(f" ✓ {hostname} — connected via {method}")
            try:
                result['admin_ip'] = resolve_ip(hostname)
            except:
                result['admin_ip'] = 'UNKNOWN'
            _, stdout, _ = ssh.exec_command('imageinfo', timeout=45)
            result['node_type'] = parse_imageinfo(stdout.read().decode('utf-8', errors='replace'))['node_type']
            if result['node_type'] in ('COMPUTE', 'KVMHOST', 'GUEST'):
                _, stdout, _ = ssh.exec_command(
                    'cat /opt/oracle.SupportTools/onecommand/databasemachine.xml 2>/dev/null || echo "NO_FILE"', timeout=30)
                xml_out = stdout.read().decode('utf-8', errors='replace')
                if xml_out.strip() != "NO_FILE":
                    result['xml_content'] = xml_out
                    result['xml_status'] = 'SUCCESS'
                    xml_candidates.append((len(xml_out), hostname, xml_out))
                    logger.info(f" → Collected databasemachine.xml from {hostname}")
            if result['node_type'] in ('COMPUTE', 'KVMHOST', 'STORAGE'):
                logger.info(f" → Trying ILOM discovery for {hostname} ({result['node_type']})...")
                suffixes = ['-ilom', '-c']
                ilom_success = False
                for suffix in suffixes:
                    ilom_host = build_ilom_fqdn(hostname, suffix)
                    logger.info(f" Trying {ilom_host}...")
                    try:
                        ilom_ssh, ilom_method = robust_ssh_connect(ilom_host, logger=logger)
                        _, stdout, _ = ilom_ssh.exec_command('show /SP', timeout=20)
                        sp_out = stdout.read().decode('utf-8', errors='replace')
                        _, stdout, _ = ilom_ssh.exec_command('show /System', timeout=20)
                        system_out = stdout.read().decode('utf-8', errors='replace')
                        ilom_info = parse_ilom_system(sp_out, system_out)
                        result['ilom_name'] = ilom_host
                        result['rack_serial_number'] = ilom_info['rack_serial_number']
                        result['host_serial_number'] = ilom_info['host_serial_number']
                        result['component_model'] = ilom_info['component_model']
                        result['model'] = ilom_info['model']
                        result['system_identifier'] = ilom_info['system_identifier']
                        result['u_location'] = ilom_info.get('u_location')
                        result['ilom_ip'] = resolve_ip(ilom_host)
                        if not first_rack_serial and ilom_info['rack_serial_number']:
                            first_rack_serial = ilom_info['rack_serial_number']
                        logger.info(f"connected ✓ (rack_serial={ilom_info['rack_serial_number']}, U={result['u_location']}, ILOM_IP={result['ilom_ip']}) via {ilom_method}")
                        ilom_ssh.close()
                        ilom_success = True
                        break
                    except Exception:
                        logger.info("no creds")
                if not ilom_success:
                    logger.info(" → ILOM discovery failed")
            if result['node_type'] in ('COMPUTE', 'KVMHOST'):
                _, stdout, _ = ssh.exec_command('olsnodes -s 2>/dev/null || echo "NO_RAC"', timeout=20)
                ols_out = stdout.read().decode('utf-8', errors='replace')
                if ols_out.strip() != "NO_RAC":
                    result['rac_name'] = ols_out.strip()
            if result['node_type'] == 'KVMHOST':
                _, stdout, _ = ssh.exec_command('virsh list --all --name 2>/dev/null || echo "NO_VIRSH"', timeout=20)
                virsh_out = stdout.read().decode('utf-8', errors='replace')
                result['guests'] = [resolve_fqdn(line.strip()) for line in virsh_out.splitlines() if line.strip() and line.strip() != "NO_VIRSH"]
                logger.info(f" → Found {len(result['guests'])} guests on {hostname}")
            result['success'] = True
        except Exception as e:
            logger.info(f" ✗ {hostname} — {str(e)[:100]}")
            result['error'] = str(e)
        finally:
            if ssh:
                ssh.close()
        return result

    with ThreadPoolExecutor(max_workers=25) as executor:
        future_to_host = {executor.submit(discover_host, h): h for h in all_hosts}
        for future in as_completed(future_to_host):
            host_results.append(future.result())

    best_xml = None
    if xml_candidates:
        xml_candidates.sort(reverse=True)
        best_xml = xml_candidates[0][2]
        logger.info(f" → Using best databasemachine.xml ({len(best_xml)} bytes)")

    # REAL RACK SERIAL AGGREGATION
    rack_serial_map = defaultdict(Counter)
    for r in host_results:
        serial = r.get('rack_serial_number')
        if serial and serial not in ('UNKNOWN', ''):
            rack_key = derive_rack_name(r['hostname'])
            rack_serial_map[rack_key][serial] += 1

    rack_serial_summary = {}
    for rack_key, counter in rack_serial_map.items():
        most_common = counter.most_common(1)[0][0] if counter else 'UNKNOWN'
        rack_serial_summary[rack_key] = most_common
        logger.info(f" → Rack {rack_key} serial: {most_common}")

    # ENRICHED RACK CREATION
    rack_id_map = {}
    for rack_key, serial in rack_serial_summary.items():
        rack_hosts = [r for r in host_results if derive_rack_name(r['hostname']) == rack_key and r.get('rack_serial_number') == serial]
        machine_type = next((h.get('model') for h in rack_hosts if h.get('model')), 'UNKNOWN')
        machine_usize = next((h.get('u_location') for h in rack_hosts if h.get('u_location') is not None), None)
        model = next((h.get('component_model') for h in rack_hosts if h.get('component_model')), None)
        sys_id = next((h.get('system_identifier') for h in rack_hosts if h.get('system_identifier')), None)

        cursor.execute("""
            MERGE INTO MAAMD.EXA_RACKS r
            USING (SELECT :serial s FROM DUAL) src
            ON (r.serial = src.s)
            WHEN MATCHED THEN UPDATE SET
                rack_name = :rack_name,
                machine_type = :mtype,
                machine_usize = :usize,
                model = :model,
                system_identifier = :sysid,
                discovery_ts = SYSTIMESTAMP
            WHEN NOT MATCHED THEN INSERT
                (serial, rack_name, machine_type, machine_usize, model, system_identifier, discovery_ts)
            VALUES (:serial, :rack_name, :mtype, :usize, :model, :sysid, SYSTIMESTAMP)
        """, {
            'serial': serial,
            'rack_name': rack_key,
            'mtype': machine_type,
            'usize': machine_usize,
            'model': model,
            'sysid': sys_id
        })

        cursor.execute("SELECT rack_id FROM MAAMD.EXA_RACKS WHERE serial = :serial", {'serial': serial})
        rack_id = cursor.fetchone()[0]
        rack_id_map[rack_key] = rack_id
        logger.info(f" → Rack {rack_key} mapped to rack_id {rack_id} (serial {serial})")

    # Create clusters
    cluster_id_map = {}
    for rack_key, rack_id in rack_id_map.items():
        cursor.execute("""
            MERGE INTO MAAMD.EXA_CLUSTERS c
            USING (SELECT :rack_id r FROM DUAL) src
            ON (c.rack_id = src.r)
            WHEN NOT MATCHED THEN INSERT (rack_id, cluster_name, cluster_type, max_guests)
            VALUES (:rack_id, 'Cluster_' || :rack_id, 'PHYSICAL', 50)
        """, {'rack_id': rack_id})
        cursor.execute("SELECT cluster_id FROM MAAMD.EXA_CLUSTERS WHERE rack_id = :rack_id", {'rack_id': rack_id})
        cluster_id = cursor.fetchone()[0]
        cluster_id_map[rack_id] = cluster_id

    # Server insertion
    stored = 0
    for r in host_results:
        if not r['success']:
            continue
        rack_id = rack_id_map.get(derive_rack_name(r['hostname']))
        cluster_id = cluster_id_map.get(rack_id)
        parsed = parse_hostname(r['hostname'])
        try:
            cursor.execute("""
                MERGE INTO MAAMD.EXA_SERVERS s
                USING (SELECT :hostname hostname FROM DUAL) src
                ON (s.HOSTNAME = src.hostname)
                WHEN MATCHED THEN UPDATE SET
                    NODE_TYPE = :node_type,
                    ILOM_NAME = :ilom_name,
                    RACK_ID = :rack_id,
                    CLUSTER_ID = :cluster_id,
                    HOST_SERIAL_NUMBER = :host_serial,
                    COMPONENT_MODEL = :comp_model,
                    SYSTEM_IDENTIFIER = :sys_id,
                    ULOCATION = :u_location,
                    ADMIN_IP = :admin_ip,
                    ILOM_IP = :ilom_ip,
                    HYPERVISOR_HOSTNAME = :hypervisor,
                    LOCATION_CODE = :location_code,
                    GENERATION_CODE = :generation_code,
                    RACK_SEQUENCE = :rack_sequence,
                    COMPONENT_CODE = :component_code,
                    POSITION_NUMBER = :position_number,
                    DISCOVERY_TS = SYSTIMESTAMP,
                    RAC_NAME = :rac_name
                WHEN NOT MATCHED THEN INSERT
                    (HOSTNAME, NODE_TYPE, ILOM_NAME, RACK_ID, CLUSTER_ID, HOST_SERIAL_NUMBER, COMPONENT_MODEL, SYSTEM_IDENTIFIER, ULOCATION, ADMIN_IP, ILOM_IP, HYPERVISOR_HOSTNAME, LOCATION_CODE, GENERATION_CODE, RACK_SEQUENCE, COMPONENT_CODE, POSITION_NUMBER, DISCOVERY_TS, RAC_NAME)
                VALUES (:hostname, :node_type, :ilom_name, :rack_id, :cluster_id, :host_serial, :comp_model, :sys_id, :u_location, :admin_ip, :ilom_ip, :hypervisor, :location_code, :generation_code, :rack_sequence, :component_code, :position_number, SYSTIMESTAMP, :rac_name)
            """, {
                'hostname': r['hostname'],
                'node_type': r['node_type'],
                'ilom_name': r['ilom_name'],
                'rack_id': rack_id,
                'cluster_id': cluster_id,
                'host_serial': r['host_serial_number'],
                'comp_model': r['component_model'],
                'sys_id': r['system_identifier'],
                'u_location': r['u_location'],
                'admin_ip': r['admin_ip'],
                'ilom_ip': r['ilom_ip'],
                'hypervisor': r.get('hypervisor_hostname'),
                'location_code': parsed['location_code'],
                'generation_code': parsed['generation_code'],
                'rack_sequence': parsed['rack_sequence'],
                'component_code': parsed['component_code'],
                'position_number': parsed['position_number'],
                'rac_name': r.get('rac_name')
            })
            stored += 1
            if r['ilom_name']:
                cursor.execute("""
                    DELETE FROM MAAMD.EXA_SERVERS
                    WHERE node_type = 'ILOM'
                      AND parent_hostname = :parent
                """, {'parent': r['hostname']})
                cursor.execute("""
                    MERGE INTO MAAMD.EXA_SERVERS s
                    USING (SELECT :ilom hostname FROM DUAL) src
                    ON (s.HOSTNAME = src.hostname)
                    WHEN MATCHED THEN UPDATE SET PARENT_HOSTNAME = :parent, RACK_ID = :rack_id, CLUSTER_ID = :cluster_id, ROLE = 'ILOM'
                    WHEN NOT MATCHED THEN INSERT (HOSTNAME, NODE_TYPE, PARENT_HOSTNAME, RACK_ID, CLUSTER_ID, ROLE)
                    VALUES (:ilom, 'ILOM', :parent, :rack_id, :cluster_id, 'ILOM')
                """, {'ilom': r['ilom_name'], 'parent': r['hostname'], 'rack_id': rack_id, 'cluster_id': cluster_id})
        except Exception as e:
            logger.info(f" DB store failed for {r['hostname']}: {e}")

    conn.commit()

    for r in host_results:
        if not r['success'] or not r['guests']:
            continue
        for guest in r['guests']:
            try:
                cursor.execute("""
                    MERGE INTO MAAMD.EXA_SERVERS s
                    USING (SELECT :hostname hostname FROM DUAL) src
                    ON (s.HOSTNAME = src.hostname)
                    WHEN NOT MATCHED THEN INSERT
                        (HOSTNAME, NODE_TYPE, HYPERVISOR_HOSTNAME, RACK_ID, CLUSTER_ID, DISCOVERY_TS)
                    VALUES (:hostname, 'GUEST', :hypervisor, :rack_id, :cluster_id, SYSTIMESTAMP)
                """, {
                    'hostname': guest,
                    'hypervisor': r['hostname'],
                    'rack_id': rack_id_map.get(derive_rack_name(r['hostname'])),
                    'cluster_id': cluster_id_map.get(rack_id_map.get(derive_rack_name(r['hostname'])))
                })
            except Exception as e:
                logger.info(f" Guest store failed for {guest}: {e}")

    cursor.execute("""
        INSERT INTO MAAMD.EXA_XML_STORES (rack_id, xml_content, collected_from, status)
        VALUES (:1, :2, :3, :4)
    """, [list(rack_id_map.values())[0] if rack_id_map else 13, best_xml, 'collected', 'SUCCESS'])

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    cursor.execute("""
        INSERT INTO MAAMD.EXA_DISCOVERY_LOGS (hostname, command, output, success, run_id)
        VALUES (:1, :2, :3, :4, :5)
    """, ['discovery_run', 'full_exadata_discovery', 'Success', 'Y', 'v5.9.5-run-' + timestamp])

    for r_id in set(rack_id_map.values()):
        identify_logical_clusters(cursor, r_id, parsed, logger=logger)  

    key_success = sum(1 for r in host_results if r.get('success') and r.get('connect_method') == 'SSH key')
    password_success = sum(1 for r in host_results if r.get('success') and r.get('connect_method') == 'password fallback')
    failed = len(all_hosts) - (key_success + password_success)

    cursor.execute("SELECT COUNT(*) FROM MAAMD.EXA_CLUSTERS")
    logical_count = cursor.fetchone()[0] or 0

    logger.info("\n" + "=" * 80)
    logger.info("=== Exadata Discovery Summary v5.9.5-standard-logging ===")
    logger.info("=" * 80)
    logger.info(f"{'Total Hosts Scanned':<40} {len(all_hosts):>8} 100.0%")
    logger.info(f"{'Connected via SSH Key':<40} {key_success:>8} {key_success/len(all_hosts)*100:5.1f}%")
    logger.info(f"{'Connected via Password Fallback':<40} {password_success:>8} {password_success/len(all_hosts)*100:5.1f}%")
    logger.info(f"{'Failed to Connect':<40} {failed:>8} {failed/len(all_hosts)*100:5.1f}%")
    logger.info(f"{'databasemachine.xml Collected':<40} {len(xml_candidates):>8}")
    logger.info(f"{'Logical Clusters Identified':<40} {logical_count:>8}")
    logger.info("=" * 80)

    if failed > 0:
        logger.info("\n=== Failed Hosts (grouped by reason) ===")
        fail_groups = {}
        for r in host_results:
            if not r.get('success'):
                reason = r.get('error', 'Unknown error')[:80]
                fail_groups.setdefault(reason, []).append(r['hostname'])
        for reason, hosts in sorted(fail_groups.items(), key=lambda x: len(x[1]), reverse=True):
            logger.info(f"\n{len(hosts)} hosts failed with: {reason}")
            for h in sorted(hosts)[:15]:
                logger.info(f" • {h}")
            if len(hosts) > 15:
                logger.info(f" ... and {len(hosts)-15} more")

    logger.info(f"\n=== Discovery Complete ===\nFull detailed log saved to: {log_path}\n")

    conn.commit()
    cursor.close()
    conn.close()
    logger.handlers.clear()

    # Final console message only
    print(f"\n=== Discovery Complete ===\nFull detailed log saved to: {log_path}")
    return stored
#####
######
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAA Exadata Discovery - CLI tool")
    parser.add_argument('--hosts', nargs='*', help='Specific hostnames (space separated). If omitted, scans ALL allocated hosts.')
    parser.add_argument('--dry-run', action='store_true', help='Show hosts only — no SSH, no DB write')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show XML details')
    parser.add_argument('--generate-xml', action='store_true', help='Generate databasemachine.xml from current DB data and exit')
    parser.add_argument('--rack', default=None, help='Rack name (e.g. scaqal02, scaqal05) for --generate-xml')
    args = parser.parse_args()
    full_exadata_discovery(hosts=args.hosts, dry_run=args.dry_run, verbose=args.verbose, generate_xml=args.generate_xml, rack=args.rack)
