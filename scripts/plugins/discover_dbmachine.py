#!/usr/bin/env python3
# Filename: discover_dbmachine.py
# Version: 2026-04-24 v2.2.8
# Changes:
#   - CRITICAL FIX: Initialize `logger = logging.getLogger(__name__)` at module level (before any function definitions).
#     This prevents NameError during import/registration when `main()` has not yet been called.
#   - Registration code at bottom of file now succeeds on every app startup.
#   - All existing functionality (RoCE discovery, virsh guest fix, switch mapping, etc.) unchanged.

import os
import sys
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
from environment_setup_registry import register_function
from maa_libraries import get_db_pool_connection, get_credential, release_db_connection
import re
import logging
from logging.handlers import RotatingFileHandler
import subprocess
from collections import defaultdict
import paramiko
import fcntl
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import textwrap
from shared_state import execution_logs, log_lock

# === CRITICAL FIX v2.2.8: Module-level logger (prevents NameError on import) ===
logger = logging.getLogger(__name__)

KNOWN_ROCE_IFACES = ['re0', 'stre0', 're1', 'stre1']
LLDP_TOOL = '/opt/oracle.SupportTools/ibdiagtools/utils/lldp_cap.py'

def normalize_mac(mac_str):
    if not mac_str:
        return ''
    cleaned = re.sub(r'[:.-]', '', mac_str.lower())
    return cleaned[0:4] + '.' + cleaned[4:8] + '.' + cleaned[8:12]

def clean_management_hostname(hostname):
    if not hostname or hostname == "N/A":
        return hostname
    h = hostname.lower()
    h = re.sub(r'-(vmstr-)?priv[12].us.oracle.com$', '.us.oracle.com', h)
    h = re.sub(r'-priv[12].us.oracle.com$', '.us.oracle.com', h)
    return h

def remote_exec_on_seed(seed_host, cmd, timeout=8):
    ssh_options = [
        'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes',
        '-o', f'ConnectTimeout={timeout}', '-o', 'ConnectionAttempts=2',
        '-o', 'ServerAliveInterval=5', '-o', 'ControlMaster=auto', '-o', 'ControlPersist=60s'
    ]
    try:
        result = subprocess.run(
            ssh_options + [f'root@{seed_host}', cmd],
            capture_output=True, text=True, timeout=timeout * 1.5
        )
        if result.returncode != 0:
            logger.warning(f"Remote command failed with code {result.returncode}: {result.stderr.strip()[:200]}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"Remote command timed out after {timeout}s")
        return ''
    except Exception as e:
        logger.error(f"Seed SSH error: {e}")
        return ''

def get_leaf_switches(seed_host):
    switches = []
    for iface in ['re0', 're1']:
        cmd = f"{LLDP_TOOL} {iface} 2>/dev/null | grep SWITCH_NAME:"
        raw = remote_exec_on_seed(seed_host, cmd)
        match = re.search(r'SWITCH_NAME:\s*([^\s]+)', raw)
        if match:
            switches.append(match.group(1))
    switches = list(set(switches))
    logger.info(f"Dynamically discovered leaf switches via LLDP: {switches}")
    return switches

def wake_roce_network(seed_host):
    logger.info("Waking RoCE network...")
    cmd = f"for i in {{1..254}}; do ping -c1 -W1 192.168.1.$i >/dev/null 2>&1 & done; wait"
    remote_exec_on_seed(seed_host, cmd)
    time.sleep(3)

def get_roce_interface_and_neighbors(seed_host):
    wake_roce_network(seed_host)
    neighbors = []
    seen_ips = set()
    for candidate in KNOWN_ROCE_IFACES:
        neigh_output = remote_exec_on_seed(seed_host, f"ip -4 neigh show dev {candidate}")
        for line in neigh_output.splitlines():
            if line.strip():
                parts = re.split(r'\s+', line.strip())
                if 'lladdr' in parts:
                    idx = parts.index('lladdr') + 1
                    if idx < len(parts):
                        ip = parts[0]
                        if ip in seen_ips:
                            continue
                        seen_ips.add(ip)
                        mac = parts[idx].upper()
                        neighbors.append((ip, mac))
    logger.info(f"Collected {len(neighbors)} unique RoCE neighbors (authoritative dbmachine boundary)")
    return "re0/re1", neighbors

def get_switch_mapping(admin_password, leaf_switches, seed_norm_macs):
    mac_to_hostname = {}
    for switch in leaf_switches:
        logger.info(f"Querying discovered switch {switch}")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(switch, username='admin', password=admin_password, timeout=10)
            stdin, stdout, stderr = client.exec_command("show mac address-table dynamic | no-more")
            mac_output = stdout.read().decode('utf-8', errors='ignore')
            stdin, stdout, stderr = client.exec_command("show interface description | no-more")
            desc_output = stdout.read().decode('utf-8', errors='ignore')
            mac_to_port = {}
            for line in mac_output.splitlines():
                match = re.search(r'([0-9a-f]{4}.[0-9a-f]{4}.[0-9a-f]{4})\s+dynamic.*\s+(Eth1/\d+)', line, re.I)
                if match:
                    mac_dot = match.group(1)
                    port = match.group(2)
                    norm_mac = normalize_mac(mac_dot)
                    if norm_mac in seed_norm_macs:
                        mac_to_port[norm_mac] = port
            port_to_hostname = {}
            for line in desc_output.splitlines():
                match = re.search(r'(Eth1/\d+)\s+.*?\b([a-z0-9.-]+.us.oracle.com)\b', line, re.I)
                if match:
                    port = match.group(1)
                    hostname = match.group(2)
                    port_to_hostname[port] = hostname
            for norm_mac, port in mac_to_port.items():
                if port in port_to_hostname:
                    mac_to_hostname[norm_mac] = port_to_hostname[port]
            client.close()
        except Exception as e:
            logger.warning(f"Switch {switch} processing error: {e}")
    return mac_to_hostname

def get_guest_mac_to_hostname_from_hypervisors(hypervisors):
    guest_mac_to_hostname = {}
    for hyp in hypervisors:
        logger.info(f"Querying virsh guests on hypervisor {hyp}")
        try:
            cmd = textwrap.dedent("""
for vm in $(virsh list --name --all | grep -v '^$'); do
    virsh domiflist "$vm" 2>/dev/null | tail -n +3 | while read -r iface type source model mac; do
        [[ -z "$mac" ]] && continue
        ip=$(ip neigh show | grep -i "$mac" | awk '{print $1}' | head -1)
        [[ -z "$ip" ]] && ip=$(arp -an | grep -i "$mac" | awk '{print $2}' | tr -d '()')
        echo "$mac|$vm"
    done
done
""").strip()
            raw = remote_exec_on_seed(hyp, cmd)
            for line in raw.splitlines():
                if '|' in line:
                    mac, vm = line.split('|', 1)
                    norm_mac = normalize_mac(mac)
                    if norm_mac:
                        guest_mac_to_hostname[norm_mac] = vm
        except Exception as e:
            logger.warning(f"virsh query on {hyp} failed: {e}")
    return guest_mac_to_hostname

@lru_cache(maxsize=64)
def get_real_node_type(management_hostname):
    if management_hostname == "N/A":
        return "UNKNOWN"
    try:
        cmd = 'imageinfo | grep -E "Node type:|Active node type:"'
        result = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', f"root@{management_hostname}", cmd],
            capture_output=True, text=True, timeout=15
        )
        raw_output = result.stdout.strip()
        if not raw_output:
            return "UNKNOWN"
        line = raw_output.lower()
        if "storage cell" in line or "storage" in line:
            return "STORAGE CELL"
        if "guest" in line:
            return "KVM GUEST"
        if "kvmhost" in line or "kvm host" in line:
            return "KVM HYPERVISOR"
        if "compute node" in line or "compute" in line:
            return "COMPUTE NODE"
        return line.split(":")[-1].strip().upper()
    except Exception:
        pass
    return "UNKNOWN"

@lru_cache(maxsize=64)
def get_management_ip(hostname):
    if hostname == "N/A":
        return "N/A"
    try:
        cmd = f"getent hosts {hostname} | awk '{{print $1}}' | head -1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        ip = result.stdout.strip()
        if ip and not ip.startswith("127."):
            return ip
    except:
        pass
    return "N/A"

def main(seed_host, pool=None, task_id=None, sid=None, socketio=None, **kwargs):
    if seed_host is None and len(sys.argv) > 1:
        seed_host = sys.argv[1]
    if seed_host is None:
        emit_message(task_id, sid, socketio, "Usage: ./discover_dbmachine.py <seed_host> [--debug] [--json]", "error")
        sys.exit(1)
    import config
    LOG_DIR = config.OUTPUT_DIR
    os.makedirs(LOG_DIR, exist_ok=True)
    safe_host = re.sub(r'[^a-zA-Z0-9_.-]', '_', seed_host)
    LOG_PATH = os.path.join(LOG_DIR, f'discover_dbmachine_{safe_host}.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[RotatingFileHandler(LOG_PATH, maxBytes=1048576, backupCount=5), logging.StreamHandler(sys.stdout)],
        force=True
    )
    global logger
    logger = logging.getLogger(__name__)
    debug_mode = '--debug' in sys.argv
    if debug_mode:
        logger.setLevel(logging.DEBUG)
    lock_path = f'/tmp/discover_dbmachine_{safe_host}.lock'
    lock_file = open(lock_path, 'w')
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        emit_message(task_id, sid, socketio, f"Another instance is already running for host {seed_host}.", "error")
        sys.exit(1)
    emit_message(task_id, sid, socketio, f"Starting virtual rack discovery for seed host: {seed_host}")
    if pool is None:
        logger.warning("CLI mode: DB pool not available - using dummy credentials for testing")
        admin_password = 'admin'
    else:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        admin_password = get_credential(cursor, 'SWITCH', 'default', 'admin')
        release_db_connection(conn, pool)
    emit_message(task_id, sid, socketio, "🔄 Waking RoCE network...")
    iface, neighbors = get_roce_interface_and_neighbors(seed_host)
    emit_message(task_id, sid, socketio, f"✅ Found {len(neighbors)} RoCE neighbors")
    if len(neighbors) == 0:
        emit_message(task_id, sid, socketio, "⚠️ No RoCE neighbors found - this is normal on some hypervisors or if RoCE is not active on this node.", "warning")
    time.sleep(1)
    emit_message(task_id, sid, socketio, "🔄 Querying leaf switches via LLDP...")
    leaf_switches = get_leaf_switches(seed_host)
    emit_message(task_id, sid, socketio, f"✅ Found {len(leaf_switches)} leaf switches")
    time.sleep(1)
    emit_message(task_id, sid, socketio, "🔄 Building switch MAC-to-hostname mapping...")
    seed_norm_macs = {normalize_mac(mac) for _, mac in neighbors}
    mac_to_hostname = get_switch_mapping(admin_password, leaf_switches, seed_norm_macs)
    emit_message(task_id, sid, socketio, "✅ Switch mapping complete")
    time.sleep(1)
    def get_node_type_for_host(h):
        return h, get_real_node_type(h)
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_host = {executor.submit(get_node_type_for_host, h): h for _, mac in neighbors if (h := mac_to_hostname.get(normalize_mac(mac), "N/A")) != "N/A"}
        node_types = {}
        for future in as_completed(future_to_host):
            h, nt = future.result()
            node_types[h] = nt
    seed_type = node_types.get(clean_management_hostname(seed_host), get_real_node_type(seed_host))
    emit_message(task_id, sid, socketio, f"✅ Seed node type: {seed_type}")
    hypervisors = {h for h, nt in node_types.items() if nt == "KVM HYPERVISOR"}
    emit_message(task_id, sid, socketio, f"✅ Found {len(hypervisors)} hypervisors")
    guest_mac_to_hostname = get_guest_mac_to_hostname_from_hypervisors(hypervisors)
    emit_message(task_id, sid, socketio, "🔄 Building final virtual rack members...")
    seed_hostname = remote_exec_on_seed(seed_host, "hostname -f").strip() or seed_host
    def build_member(ip_mac):
        ip, mac = ip_mac
        norm_mac = normalize_mac(mac)
        if norm_mac not in seed_norm_macs:
            return None
        if mac.startswith('52:54:00') and norm_mac in guest_mac_to_hostname:
            final_hostname = clean_management_hostname(guest_mac_to_hostname[norm_mac])
            node_type = "KVM GUEST"
            mgmt_ip = get_management_ip(final_hostname)
            return {
                "roce_ip": ip,
                "mac": mac,
                "type": node_type,
                "management_hostname": final_hostname,
                "management_ip": mgmt_ip
            }
        final_hostname = mac_to_hostname.get(norm_mac, "N/A")
        if final_hostname == "N/A":
            fallback_cmd = f"getent hosts {ip} | awk '{{print $2}}' | head -1"
            fallback = remote_exec_on_seed(seed_host, fallback_cmd, timeout=2)
            if fallback:
                final_hostname = fallback
            else:
                try:
                    hostname_cmd = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 root@{ip} 'hostname -f' 2>/dev/null"
                    fallback = remote_exec_on_seed(seed_host, hostname_cmd, timeout=2)
                    if fallback:
                        final_hostname = fallback
                except:
                    pass
        if final_hostname == "N/A":
            return None
        final_hostname = clean_management_hostname(final_hostname)
        node_type = node_types.get(final_hostname, get_real_node_type(final_hostname))
        if node_type != "UNKNOWN":
            mgmt_ip = get_management_ip(final_hostname)
            return {
                "roce_ip": ip,
                "mac": mac,
                "type": node_type,
                "management_hostname": final_hostname,
                "management_ip": mgmt_ip
            }
        return None
    with ThreadPoolExecutor(max_workers=4) as executor:
        host_data = list(executor.map(build_member, neighbors))
    host_data = [m for m in host_data if m is not None]
    # FORCE-ADD any guest discovered by virsh (fixes missing vm01 regression)
    for norm_mac, vm in guest_mac_to_hostname.items():
        final_hostname = clean_management_hostname(vm)
        if not any(m['management_hostname'] == final_hostname for m in host_data):
            mgmt_ip = get_management_ip(final_hostname)
            host_data.append({
                "roce_ip": "N/A (guest)",
                "mac": "N/A (virsh)",
                "type": "KVM GUEST",
                "management_hostname": final_hostname,
                "management_ip": mgmt_ip
            })
    seed_in_list = any(m['management_hostname'] == clean_management_hostname(seed_hostname) for m in host_data)
    if not seed_in_list or seed_type in ["COMPUTE NODE", "KVM HYPERVISOR"]:
        seed_ips_cmd = "ip -4 addr show | grep -E 're[0-9]|stre[0-9]' | awk '{print $2}' | cut -d/ -f1"
        seed_ips_raw = remote_exec_on_seed(seed_host, seed_ips_cmd)
        seed_ips = [ip.strip() for ip in seed_ips_raw.splitlines() if ip.strip().startswith('192.168.')]
        seed_mgmt_ip = get_management_ip(clean_management_hostname(seed_hostname))
        seed_hostname_clean = clean_management_hostname(seed_hostname)
        existing = {(m['management_hostname'], m['roce_ip']) for m in host_data}
        for sip in seed_ips:
            key = (seed_hostname_clean, sip)
            if key not in existing:
                host_data.append({
                    "roce_ip": sip,
                    "mac": "N/A (seed)",
                    "type": seed_type,
                    "management_hostname": seed_hostname_clean,
                    "management_ip": seed_mgmt_ip
                })
                existing.add(key)
    members = host_data
    emit_message(task_id, sid, socketio, "✅ Final member list built")
    lines = []
    lines.append("### 🧬 Virtual Rack Discovery Complete")
    lines.append("")
    lines.append("<table border='1' style='border-collapse: collapse; width:100%;'>")
    lines.append("<thead><tr><th>Management Hostname</th><th>Type</th><th>Management IP</th><th>RoCE IPs</th></tr></thead>")
    lines.append("<tbody>")
    host_map = defaultdict(list)
    host_type_map = {}
    host_ip_map = {}
    for m in members:
        host_map[m['management_hostname']].append(m['roce_ip'])
        if m['management_hostname'] not in host_type_map:
            if m['type'] in ["KVM HYPERVISOR", "COMPUTE NODE"]:
                comp_type = "Database Server"
            elif m['type'] == "STORAGE CELL":
                comp_type = "Storage Server"
            elif m['type'] == "KVM GUEST":
                comp_type = "Guest"
            else:
                comp_type = m['type']
            host_type_map[m['management_hostname']] = comp_type
            host_ip_map[m['management_hostname']] = m['management_ip']
    for hostname, ips in sorted(host_map.items()):
        if hostname != "N/A":
            comp_type = host_type_map.get(hostname, "Unknown")
            mgmt_ip = host_ip_map.get(hostname, "N/A")
            lines.append(f"<tr><td>{hostname}</td><td>{comp_type}</td><td>{mgmt_ip}</td><td>{', '.join(sorted(set(ips)))}</td></tr>")
    lines.append("</tbody></table>")
    lines.append(f"<p><strong>Total members discovered:</strong> {len(members)}</p>")
    output = '\n'.join(lines)
    fcntl.flock(lock_file, fcntl.LOCK_UN)
    lock_file.close()
    return output

def emit_message(task_id, sid, socketio, msg, status='info'):
    clean_msg = re.sub(r'\x1B[[0-?]*[ -/]*[@-~]', '', str(msg))
    if socketio and sid:
        socketio.emit('message', {
            'task_id': task_id,
            'line': clean_msg,
            'status': status
        }, room=sid, namespace='/')
    else:
        print(clean_msg)
    logger.info(f"[Discover] {clean_msg}")
    if status in ('error', 'success'):
        with log_lock:
            if task_id in execution_logs:
                execution_logs[task_id]['status'] = status

def discover_dbmachine(component_name, params, **kwargs):
    task_id = kwargs.pop('task_id', None) or kwargs.pop('taskId', None) or 'discover_dbmachine'
    sid = kwargs.pop('sid', None)
    socketio = kwargs.pop('socketio', None)
    pool = kwargs.pop('pool', None)
    original_argv = sys.argv[:]
    sys.argv = [sys.argv[0] if sys.argv else 'discover_dbmachine.py', component_name]
    if params.get('debug'):
        sys.argv.append('--debug')
    if params.get('json'):
        sys.argv.append('--json')
    try:
        result = main(component_name, pool=pool, task_id=task_id, sid=sid, socketio=socketio, **kwargs)
        emit_message(task_id, sid, socketio, "✅ Discovery completed successfully for seed host: " + component_name, "success")
        return result
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"CRITICAL ERROR in discover_dbmachine: {e}\n{tb}")
        emit_message(task_id, sid, socketio, f"❌ CRITICAL ERROR: {str(e)}", "error")
        return f"❌ ERROR running discovery:<br>{str(e)}<br><br>Full traceback:<br><pre>{tb}</pre>"
    finally:
        sys.argv = original_argv

if not hasattr(discover_dbmachine, '_registered'):
    try:
        discover_dbmachine.name = "discover_dbmachine"
        discover_dbmachine.display_name = "Discover DBMachine"
        discover_dbmachine.description = "Discovers the complete virtual rack (compute + storage + guests) via RoCE neighbors and switch MAC table mapping"
        discover_dbmachine.params = []
        discover_dbmachine = register_function(component_types=["Global", "Database Server"])(discover_dbmachine)
        discover_dbmachine._registered = True
        logger.info("discover_dbmachine successfully registered as Global + Database Server function")
    except Exception as e:
        logger.error(f"Registration failed: {e}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
