# Filename: setup_scl_loader.py
# Version: 2026-04-24 v1.2
# Changes:
#   - Added SHELL_DIR support for /scripts/shell/{Database,Guest,Storage}/*.scl
#   - Shell scripts (imageinfo, check_*, set_ms_*, etc.) now appear in UI under correct component type
#   - Subdir mapping: Database -> Database Server, Storage -> Storage Server, Guest -> Guest
#   - No change to CellCLI detection or execution logic (still handled in setup_execution.py v1.82+)
#   - Backward compatible with existing scl/ and ilom/ directories

import os
from maa_libraries import logger
from flask import current_app

SCL_DIR = "/home/maatest/mchafin/MAA_APPS_NEW/scripts/scl"
ILOM_DIR = "/home/maatest/mchafin/MAA_APPS_NEW/scripts/ilom"
SHELL_DIR = "/home/maatest/mchafin/MAA_APPS_NEW/scripts/shell"

scl_functions = {}

def _load_scl_files():
    global scl_functions
    scl_functions = {
        'Storage Server': [], 'Database Server': [], 'Guest': [],
        'ILOM Components': [],
        'Switch': [], 'Global': []
    }

    # === Original SCL directory (CellCLI scripts) ===
    if os.path.exists(SCL_DIR):
        for fname in sorted(os.listdir(SCL_DIR)):
            if not fname.endswith('.scl'):
                continue
            path = os.path.join(SCL_DIR, fname)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    cmd = f.read().strip()
                if fname.endswith('_db.scl'):
                    ctype = 'Database Server'
                    if any(x in fname.lower() for x in ['reset_dbsnmp', 'reset_asmsnmp', 'imageinfo']):
                        ctype = 'Guest'
                else:
                    ctype = 'Storage Server'
                desc = fname.replace('.scl', '').replace('_', ' ').title()
                scl_functions[ctype].append((fname, cmd, desc))
                if ctype == 'Guest':
                    scl_functions['Database Server'].append((fname, cmd, desc))
            except Exception as e:
                logger.error(f"Failed to load {fname}: {e}")

    # === ILOM directory ===
    if os.path.exists(ILOM_DIR):
        for fname in sorted(os.listdir(ILOM_DIR)):
            if not fname.endswith('.ilom'):
                continue
            path = os.path.join(ILOM_DIR, fname)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    cmd = f.read().strip()
                desc = fname.replace('.ilom', '').replace('_', ' ').title()
                scl_functions['ILOM Components'].append((fname, cmd, desc))
            except Exception as e:
                logger.error(f"Failed to load {fname}: {e}")

    # === NEW: Shell directory (imageinfo, check_*, set_ms_*, etc.) ===
    # These are real shell scripts → executed WITHOUT -x flag
    shell_type_map = {
        'Database': 'Database Server',
        'Guest': 'Guest',
        'Storage': 'Storage Server'
    }
    if os.path.exists(SHELL_DIR):
        for subdir, ctype_full in shell_type_map.items():
            cdir = os.path.join(SHELL_DIR, subdir)
            if not os.path.exists(cdir):
                continue
            for fname in sorted(os.listdir(cdir)):
                if not fname.endswith('.scl'):
                    continue
                path = os.path.join(cdir, fname)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        cmd = f.read().strip()
                    desc = fname.replace('.scl', '').replace('_', ' ').title()
                    scl_functions[ctype_full].append((fname, cmd, desc))
                    if ctype_full == 'Guest':
                        scl_functions['Database Server'].append((fname, cmd, desc))
                except Exception as e:
                    logger.error(f"Failed to load shell script {fname}: {e}")

    total = sum(len(v) for v in scl_functions.values())
    logger.info(f"Loaded {total} SCL/ILOM/Shell functions (including {len(scl_functions.get('Storage Server', []))} Storage, {len(scl_functions.get('Database Server', []))} Database, {len(scl_functions.get('Guest', []))} Guest)")

def get_component_type(hostname):
    if hostname == 'global':
        return 'Global'
    hostname_lower = hostname.lower()
    if hostname_lower.endswith('-ilom.us.oracle.com') or hostname_lower.endswith('-c.us.oracle.com'):
        return 'ILOM Components'
    if 'celadm' in hostname_lower:
        return 'Storage Server'
    if 'vm' in hostname_lower:
        return 'Guest'
    if 'adm' in hostname_lower:
        return 'Database Server'
    if 'sw-' in hostname_lower:
        return 'Switch'
    return 'Unknown'

def get_functions_for_type(ctype):
    from environment_setup_registry import get_functions_for_type as registry_get
    registry_funcs = registry_get(ctype)
    scl_list = scl_functions.get(ctype, [])
    scl_dicts = [
        {'name': name, 'display_name': desc, 'type': 'embedded', 'description': desc}
        for name, cmd, desc in scl_list
    ]
    return registry_funcs + scl_dicts

def safe_emit_progress(task_id, message, status='running', hostname=None, sid=None):
    prefix = f"[{hostname}] " if hostname else "[global] "
    full_msg = prefix + message
    try:
        if current_app and hasattr(current_app, 'socketio'):
            current_app.socketio.emit('message', {
                'task_id': task_id,
                'line': full_msg,
                'status': status
            }, room=sid, namespace='/')
    except Exception as e:
        logger.error(f"safe_emit_progress failed: {e}")

# Auto-load on import
_load_scl_files()
