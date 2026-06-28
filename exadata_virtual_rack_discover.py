#!/usr/bin/env python3
import os
import sys
import re
import logging
from logging.handlers import RotatingFileHandler
import json
import subprocess
from collections import defaultdict
import paramiko
import fcntl
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maa_db_pool import get_db_pool_connection, release_db_pool_connection
from maa_libraries import get_credential

LOG_DIR = '/home/maatest/MAA_APPS_NEW/output'
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, 'discover_virtual_rack.log')

log_handler = RotatingFileHandler(LOG_PATH, maxBytes=1048576, backupCount=5)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[log_handler, logging.StreamHandler(sys.stdout) if '--debug' in sys.argv else logging.NullHandler()]
)
logger = logging.getLogger(__name__)

KNOWN_ROCE_IFACES = ['re0', 'stre0', 're1', 'stre1', 'bondroce0']
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
    h = re.sub(r'-(vmstr-)?priv[12]\.us\.oracle\.com$', '.us.oracle.com', h)
    h = re.sub(r'-priv[12]\.us\.oracle\.com$', '.us.oracle.com', h)
    return h

def remote_exec_on_seed(seed_host, cmd, timeout=30):
    try:
        result = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', '-o', f'ConnectTimeout={timeout}', f'root@{seed_host}', cmd],
            capture_output=True, text=True, timeout=timeout*2
        )
        if result.returncode != 0 and '--debug' in sys.argv:
            logger.warning(f"Remote command failed with code {result.returncode}: {result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        if '--debug' in sys.argv:
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
            client.connect(switch, username='admin', password=admin_password, timeout=30)
            stdin, stdout, stderr = client.exec_command("show mac address-table dynamic | no-more")
            mac_output = stdout.read().decode('utf-8', errors='ignore')
            stdin, stdout, stderr = client.exec_command("show interface description | no-more")
            desc_output = stdout.read().decode('utf-8', errors='ignore')
            mac_to_port = {}
            for line in mac_output.splitlines():
                match = re.search(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+dynamic.*\s+(Eth1/\d+)', line, re.I)
                if match:
                    mac_dot = match.group(1)
                    port = match.group(2)
                    norm_mac = normalize_mac(mac_dot)
                    if norm_mac in seed_norm_macs:
                        mac_to_port[norm_mac] = port
            port_to_hostname = {}
            for line in desc_output.splitlines():
                match = re.search(r'(Eth1/\d+)\s+.*?\b([a-z0-9.-]+\.us\.oracle\.com)\b', line, re.I)
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
            cmd = """
for vm in $(virsh list --name --all | grep -v '^$'); do
    virsh domiflist "$vm" 2>/dev/null | tail -n +3 | while read -r iface type source model mac; do
        [[ -z "$mac" ]] && continue
        ip=$(ip neigh show | grep -i "$mac" | awk '{print $1}' | head -1)
        [[ -z "$ip" ]] && ip=$(arp -an | grep -i "$mac" | awk '{print $2}' | tr -d '()')
        echo "$mac|$vm"
    done
done
"""
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

def get_real_node_type(management_hostname):
    if management_hostname == "N/A":
        return "UNKNOWN"
    try:
        cmd = 'imageinfo | grep -E "Node type:|Active node type:"'
        result = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=30', f"root@{management_hostname}", cmd],
            capture_output=True, text=True, timeout=60
        )
        raw_output = result.stdout.strip()
        if '--debug' in sys.argv:
            logger.debug(f"Raw imageinfo on {management_hostname}:\n{raw_output}")
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

def main():
    if len(sys.argv) < 2:
        print("Usage: ./exadata_virtual_rack_discover.py <seed_host> [--debug] [--json]")
        sys.exit(1)
    seed_host = sys.argv[1]
    debug_mode = '--debug' in sys.argv
    json_only = '--json' in sys.argv
    if debug_mode:
        logger.setLevel(logging.DEBUG)

    lock_file = open('/tmp/exadata_virtual_rack_discover.lock', 'w')
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logger.error("Another instance is already running.")
        sys.exit(1)

    logger.info(f"Starting virtual rack discovery for seed host: {seed_host}")
    
    conn = get_db_pool_connection()
    cursor = conn.cursor()
    admin_password = get_credential(cursor, 'SWITCH', 'default', 'admin')
    root_password = get_credential(cursor, 'PHYSICAL_HOST', 'default', 'root')
    release_db_pool_connection(conn)
    
    iface, neighbors = get_roce_interface_and_neighbors(seed_host)
    seed_norm_macs = {normalize_mac(mac) for _, mac in neighbors}
    leaf_switches = get_leaf_switches(seed_host)
    mac_to_hostname = get_switch_mapping(admin_password, leaf_switches, seed_norm_macs)
    
    seed_type = get_real_node_type(seed_host)
    logger.info(f"Seed node type detected: {seed_type}")
    
    hypervisors = set()
    for ip, mac in neighbors:
        norm_mac = normalize_mac(mac)
        if norm_mac not in seed_norm_macs:
            continue
        h = mac_to_hostname.get(norm_mac, "N/A")
        if h != "N/A":
            node_type = get_real_node_type(h)
            if node_type == "KVM HYPERVISOR":
                hypervisors.add(h)
    
    guest_mac_to_hostname = get_guest_mac_to_hostname_from_hypervisors(hypervisors)
    
    members = []
    logger.info("=== FINAL MEMBER CONSTRUCTION (RoCE neighbors + switch description hostname mapping + guest override + aggressive bare-metal fallback) ===")
    seed_hostname = remote_exec_on_seed(seed_host, "hostname -f").strip() or seed_host
    for ip, mac in neighbors:
        norm_mac = normalize_mac(mac)
        if norm_mac not in seed_norm_macs:
            continue
        final_hostname = mac_to_hostname.get(norm_mac, "N/A")
        if final_hostname == "N/A":
            fallback_cmd = f"getent hosts {ip} | awk '{{print $2}}' | head -1"
            fallback = remote_exec_on_seed(seed_host, fallback_cmd)
            if fallback:
                final_hostname = fallback
            else:
                try:
                    hostname_cmd = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=30 root@{ip} 'hostname -f' 2>/dev/null"
                    fallback = remote_exec_on_seed(seed_host, hostname_cmd)
                    if fallback:
                        final_hostname = fallback
                except:
                    pass
        if final_hostname == "N/A":
            if debug_mode:
                logger.debug(f"MAC {norm_mac} ({ip}) excluded - no hostname from switch or fallback")
            continue
        final_hostname = clean_management_hostname(final_hostname)
        node_type = get_real_node_type(final_hostname)
        if mac.startswith('52:54:00') and norm_mac in guest_mac_to_hostname:
            guest_vm = guest_mac_to_hostname[norm_mac]
            final_hostname = clean_management_hostname(guest_vm)
            node_type = "KVM GUEST"
        if node_type != "UNKNOWN":
            mgmt_ip = get_management_ip(final_hostname)
            members.append({
                "roce_ip": ip,
                "mac": mac,
                "type": node_type,
                "management_hostname": final_hostname,
                "management_ip": mgmt_ip
            })
            if debug_mode:
                logger.debug(f"INCLUDED MAC {norm_mac} ({ip}) -> {final_hostname} ({node_type})")
    
    seed_in_list = any(m['management_hostname'] == clean_management_hostname(seed_hostname) for m in members)
    if not seed_in_list or seed_type in ["COMPUTE NODE", "KVM HYPERVISOR"]:
        seed_ips_cmd = "ip -4 addr show | grep -E 're[0-9]|stre[0-9]' | awk '{print $2}' | cut -d/ -f1"
        seed_ips_raw = remote_exec_on_seed(seed_host, seed_ips_cmd)
        seed_ips = [ip.strip() for ip in seed_ips_raw.splitlines() if ip.strip().startswith('192.168.')]
        seed_mgmt_ip = get_management_ip(clean_management_hostname(seed_hostname))
        for sip in seed_ips:
            members.append({
                "roce_ip": sip,
                "mac": "N/A (seed)",
                "type": seed_type,
                "management_hostname": clean_management_hostname(seed_hostname),
                "management_ip": seed_mgmt_ip
            })
        if debug_mode:
            logger.debug(f"Force-included seed {seed_hostname} with its RoCE IPs: {seed_ips}")
    
    result = {
        "seed_host": seed_host,
        "roce_interface": iface,
        "member_count": len(members),
        "members": members
    }
    
    if json_only:
        print(json.dumps(result, indent=2))
    else:
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
        
        print("\n=== UNIQUE HOSTS SUMMARY (no duplicates) ===")
        print(f"{'Management Hostname':<40} {'Component Type':<18} {'Management IP':<18} RoCE IPs")
        print("-" * 120)
        for hostname, ips in sorted(host_map.items()):
            if hostname != "N/A":
                comp_type = host_type_map.get(hostname, "Unknown")
                mgmt_ip = host_ip_map.get(hostname, "N/A")
                print(f"{hostname:<40} {comp_type:<18} {mgmt_ip:<18} {', '.join(sorted(set(ips)))}")

    fcntl.flock(lock_file, fcntl.LOCK_UN)
    lock_file.close()

if __name__ == "__main__":
    main()
