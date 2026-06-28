#!/usr/bin/env python3
# textVersion: 2026-05-26 v2.4
# Changes: Fixed .scl execution to use 'scl' command + stdin instead of dcli -x (eliminates temp .sh errors on remote)
import os
import importlib.util
from collections import defaultdict
import logging
import subprocess
import tempfile
import time
from flask import current_app

logger = logging.getLogger(__name__)

import config

print("=== REGISTRY v1.5 STARTING - DISCOVER_DBMACHINE WILL REGISTER AS GLOBAL ===")
print(f"=== SCRIPT_BASE = {config.APP_ROOT} ===")

# ====================== EASY-TO-EDIT DISPLAY NAMES FOR ENVIRONMENT SETUP PAGE ======================
DISPLAY_NAME_MAP = {
    # Storage Server
    'reset_ms_snmp.scl': 'Reset MS SNMP Subscriber',
    'get_snmp.scl': 'Get SNMP Configuration',
    'restart_cell_services.scl': 'Restart Cell Services',
    'setup_test_asrm.scl': 'Setup Test ASRM Subscription',
    'set_smtp.scl': 'Set SMTP Configuration',
    'set_v3user.scl': 'Set SNMP v3 User',
    'change_celladministrator_password.scl': 'Change CellAdministrator Password',
    'remove_software_update.scl': 'Remove Software Update',
    'set_ms_configuration.scl': 'Set MS Configuration Parameters',
    'create_celladministrator.scl': 'Create CellAdministrator User',
    'patch_storage': 'Patch Storage Servers (Group)',
    'imageinfo.scl': 'Show Image Info',

    # Database Server
    'reset_dbsnmp.scl': 'Reset DBSNMP Password in All Databases',
    'reset_asmsnmp_password.scl': 'Reset ASMSNMP Password in ASM Instances',
    'check_exascale.scl': 'Check if Database Server is Exascale',
    'check_storage_type.scl': 'Check Storage Network Type (RoCE/InfiniBand)',
    'check_virtual.scl': 'Check if Hypervisor or Physical',
    'pre_patch_shutdown_dbserver': 'Pre-Patch Shutdown (VM/CRS + Exascale)',
    'patch_database': 'Patch Database Servers (Group)',
    'install_falcon_sensor': 'Install/Upgrade CrowdStrike Falcon Sensor',

    # Guest
    'patch_vm': 'Patch Virtual Machines/Guests (Group)',

    # ILOM (both DB and Storage)
    'reset_snmp.ilom': 'Reset SNMP Subscriptions (preserves Rule 1)',
    'get_snmp.ilom': 'Get SNMP Subscriptions',
    'show_snmp_subscriptions.ilom': 'Show All SNMP Alert Rules',
    'show_snmp_users.ilom': 'Show All SNMP Users with Details',
    'set_v2c.ilom': 'Set SNMP v2c Rule',
    'set_v3.ilom': 'Set SNMP v3 Rule',
    'enable_ssh_login': 'Enable Direct SSH Login to Cell',
    'disable_ssh_login': 'Disable Direct SSH Login to Cell',

    # Global
    'copy_latest_patches': 'Copy Latest Patches from Staging Environment',
    'install_falcon_sensor_all': 'Install Falcon Sensor on ALL Guests + non-hypervisor Physical DB Servers',
    'discover_dbmachine': 'Discover DBMachine',
}

# ====================== BASE DIRECTORIES (exact path you showed with pwd) ======================
SCRIPT_BASE = config.APP_ROOT
SCL_DIR = config.SCL_DIR
ILOM_DIR = config.ILOM_DIR
SHELL_DIR = config.SHELL_DIR
PLUGIN_DIR = config.PLUGIN_DIR

for d in [SCL_DIR, ILOM_DIR, SHELL_DIR, PLUGIN_DIR,
          os.path.join(SCL_DIR, "Database Server"),
          os.path.join(SCL_DIR, "Storage Server"),
          os.path.join(SHELL_DIR, "Guest")]:
    os.makedirs(d, exist_ok=True)

# Optional yaml
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False
    logger.warning("PyYAML not installed. YAML metadata sidecar files will be ignored.")

# Global registry
_registry = defaultdict(dict)
_loaded = False

def register_function(component_types, params=None, group_sequence=None):
    def decorator(func):
        name = func.__name__
        metadata = {
            'name': name,
            'display_name': DISPLAY_NAME_MAP.get(name, name.replace('_', ' ').title()),
            'description': (func.__doc__ or "No description provided").strip(),
            'component_types': component_types,
            'params': params or [],
            'type': 'plugin',
            'function': func,
            'group_sequence': group_sequence
        }
        for ctype in component_types:
            _registry[ctype][name] = metadata
        logger.info(f"Registered plugin: {name} for {component_types}")
        return func
    return decorator

# Default test function (shows on page immediately)
@register_function(component_types=["Database Server", "Storage Server", "Guest"], params=[{"name": "test", "label": "Test Value", "type": "text"}])
def test_function(component_name, params, **kwargs):
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    line = f"[{component_name}] Test function ran with value: {params.get('test', 'none')}"
    if socketio and sid:
        socketio.emit('message', {'task_id': task_id, 'line': line, 'status': 'success'}, room=sid)
    return line

def load_registry():
    global _loaded
    if _loaded:
        return _registry

    print("=== REGISTRY v1.5 LOADED - DISCOVER_DBMACHINE WILL REGISTER AS GLOBAL ===")
    logger.info(f"[REGISTRY] PLUGIN_DIR resolved to: {PLUGIN_DIR}")

    # Auto-discover scripts
    for base_dir, ext, ftype in [(SCL_DIR, '.scl', 'scl'), (ILOM_DIR, '.ilom', 'ilom'), (SHELL_DIR, '.sh', 'shell')]:
        for root, _, files in os.walk(base_dir):
            ctype = os.path.basename(root)
            if ctype == 'scripts':
                continue
            for file in files:
                if file.endswith(ext):
                    name = file
                    path = os.path.join(root, file)
                    _registry[ctype][name] = {
                        'name': name,
                        'display_name': DISPLAY_NAME_MAP.get(name, name.replace(ext, '').replace('_', ' ').title()),
                        'description': f"Auto-discovered {ext[1:]} script",
                        'component_types': [ctype],
                        'params': [],
                        'type': ftype,
                        'path': path
                    }
                    logger.info(f"Auto-registered {ftype}: {name} → {ctype}")

    # Load plugins
    if os.path.exists(PLUGIN_DIR):
        logger.info(f"[REGISTRY] Found {len(os.listdir(PLUGIN_DIR))} files in PLUGIN_DIR")
        for file in os.listdir(PLUGIN_DIR):
            if file.endswith('.py') and not file.startswith('__'):
                module_name = file[:-3]
                full_path = os.path.join(PLUGIN_DIR, file)
                logger.info(f"[REGISTRY] Loading plugin: {full_path}")
                try:
                    spec = importlib.util.spec_from_file_location(module_name, full_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    logger.info(f"[REGISTRY] SUCCESS loaded plugin: {module_name}")
                except Exception as e:
                    logger.error(f"[REGISTRY] FAILED to load plugin {file}: {e}", exc_info=True)
    else:
        logger.error(f"[REGISTRY] PLUGIN_DIR {PLUGIN_DIR} does NOT exist!")

    # FORCE-LOAD discover_dbmachine.py
    discover_path = os.path.join(PLUGIN_DIR, "discover_dbmachine.py")
    if os.path.exists(discover_path):
        logger.info(f"[REGISTRY] Force-loading discover_dbmachine.py from {discover_path}")
        try:
            spec = importlib.util.spec_from_file_location("discover_dbmachine", discover_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            logger.info("[REGISTRY] SUCCESS: Force-loaded discover_dbmachine → now registered as Global")
        except Exception as e:
            logger.error(f"[REGISTRY] Force-load of discover_dbmachine failed: {e}", exc_info=True)
    else:
        logger.error(f"[REGISTRY] discover_dbmachine.py NOT FOUND at {discover_path}")

    _loaded = True
    total = sum(len(v) for v in _registry.values())
    logger.info(f"[REGISTRY] FINAL: {total} functions loaded. Global functions: {[f.get('display_name', f.get('name')) for f in _registry.get('Global', {}).values()]}")
    return _registry

def get_functions_for_type(ctype: str):
    load_registry()
    return list(_registry.get(ctype, {}).values())

def get_all_component_types():
    load_registry()
    return sorted(_registry.keys())

def get_component_type(hostname):
    if hostname == 'global':
        return 'Global'
    hostname_lower = hostname.lower()
    if hostname_lower.endswith(('-ilom.us.oracle.com', '-c.us.oracle.com')):
        base = hostname_lower.replace('-ilom.us.oracle.com', '').replace('-c.us.oracle.com', '')
        if 'celadm' in base:
            return 'Storage Server ILOM'
        elif 'adm' in base:
            return 'Database Server ILOM'
    if 'celadm' in hostname_lower or 'cell' in hostname_lower:
        return 'Storage Server'
    if 'vm' in hostname_lower or 'client' in hostname_lower:
        return 'Guest'
    if 'adm' in hostname_lower:
        return 'Database Server'
    if 'sw-' in hostname_lower:
        return 'Switch'
    return 'Unknown'

def run_script_file(script_path, component_name, params, **kwargs):
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    dcli_cmd = '/usr/bin/dcli_compute' if 'Database Server' in get_component_type(component_name) else '/usr/bin/dcli'
    group_path = tempfile.mktemp()
    with open(group_path, 'w') as f:
        f.write(component_name + "\n")

    is_scl = script_path.endswith('.scl')

    try:
        if is_scl:
            # For .scl files: run via 'scl' command and pipe content (avoids dcli temp .sh wrapper issues)
            with open(script_path, 'r') as scl_f:
                scl_content = scl_f.read()

            cmd = [dcli_cmd, '-l', 'root', '-g', group_path, 'scl']
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            stdout, _ = process.communicate(input=scl_content, timeout=300)
            output_lines = [f"[{component_name}] {line}" for line in stdout.splitlines() if line.strip()]
        else:
            # For regular scripts: use -x to copy and execute
            cmd = [dcli_cmd, '-l', 'root', '-g', group_path, '-x', script_path]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            output_lines = []
            for line in process.stdout:
                line = line.rstrip()
                output_lines.append(f"[{component_name}] {line}")

            process.wait(timeout=300)

        success = process.returncode == 0
        final_line = f"[{component_name}] {os.path.basename(script_path)}: {'SUCCESS' if success else 'FAILED'}"
        output_lines.append(final_line)

        if socketio and sid:
            for line in output_lines:
                socketio.emit('message', {'task_id': task_id, 'line': line, 'status': 'success' if success else 'error'}, room=sid)

        return '\n'.join(output_lines)

    finally:
        if os.path.exists(group_path):
            os.unlink(group_path)

def run_ilom_script(script_path, component_name, params, **kwargs):
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    try:
        import pexpect
        from maa_libraries import get_credential_silent
        conn = kwargs.get('pool')
        cursor = conn.cursor() if conn else None
        password = get_credential_silent(cursor, 'ILOM', component_name, 'root') or get_credential_silent(cursor, 'ILOM', 'default', 'root')
        if cursor:
            cursor.close()
        child = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no root@{component_name}')
        child.timeout = 30
        i = child.expect([pexpect.TIMEOUT, 'password:', '-> '])
        if i == 1:
            child.sendline(password)
            child.expect('-> ', timeout=30)
        lines = []
        with open(script_path) as f:
            for cmd in f:
                cmd = cmd.strip()
                if cmd:
                    child.sendline(cmd)
                    child.expect('-> ', timeout=30)
                    output = child.before.decode().strip()
                    cleaned = '\n'.join(line for line in output.splitlines() if line.strip() and not line.strip().startswith(cmd))
                    if cleaned.strip():
                        lines.append(cleaned)
                        if socketio and sid:
                            socketio.emit('message', {'task_id': task_id, 'line': cleaned, 'status': 'running'}, room=sid)
        child.sendline('exit')
        child.close()
        return '\n'.join(lines)
    except Exception as e:
        return f"ILOM script error: {str(e)}"

def execute_function(component_name: str, func_name: str, params: dict = None, **kwargs):
    load_registry()
    ctype = get_component_type(component_name)
    if ctype not in _registry or func_name not in _registry[ctype]:
        raise ValueError(f"Function '{func_name}' not found for component type '{ctype}'")
    meta = _registry[ctype][func_name]
    ftype = meta['type']
    if ftype == 'plugin':
        return meta['function'](component_name, params or {}, **kwargs)
    elif ftype in ('scl', 'shell'):
        return run_script_file(meta['path'], component_name, params or {}, **kwargs)
    elif ftype == 'ilom':
        return run_ilom_script(meta['path'], component_name, params or {}, **kwargs)
    raise ValueError(f"Unknown function type: {ftype}")
