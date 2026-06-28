# Filename: scripts/plugins/patch_infiniband_switch.py
# Version: 2026-04-10 v1.2.0
# Changes: Standardized emit() with ANSI stripping + fallback logger (exact same pattern as patch_nxos_switch v1.2.0). Added ultra-visible reload marker. Fixes output intermingling between tabs when running concurrent patches (e.g. patch_guest + patch_infiniband_switch).
#!/usr/bin/env python3
import os
import re
import time
import threading
import paramiko
import pexpect
from collections import defaultdict
from environment_setup_registry import register_function
from maa_libraries import logger, get_db_pool_connection, release_db_connection, get_credential_silent
from flask import current_app
rack_locks = defaultdict(threading.Lock)
def _get_available_pkg_options():
    options = []
    pkg_base = "/home/exports"
    if not os.path.exists(pkg_base):
        logger.warning("Patch switch plugin: /home/exports not found - no .pkg files available")
        return []
    for root, _, files in os.walk(pkg_base):
        for f in files:
            if f.endswith('.pkg') and any(x in root for x in ['SUN_DCS_36p', 'SUN_DCS_GW']):
                full_path = os.path.join(root, f)
                dir_name = os.path.basename(root)
                label = f"{dir_name}/{f}"
                options.append({"value": full_path, "label": label})
    def version_key(opt):
        m = re.search(r'(\d+\.\d+\.\d+[_\-]\d+)', opt['label'])
        return m.group(1) if m else opt['label']
    options.sort(key=version_key, reverse=True)
    logger.info(f"Patch switch plugin: discovered {len(options)} .pkg files")
    return options
def _normalize_version(v):
    """Normalize _ vs - so pre-check works cleanly."""
    return v.replace('_', '-').replace('-', '_')
@register_function(
    component_types=["Switch"],
    params=[
        {
            "name": "pkg_path",
            "label": "Select Firmware Package (.pkg)",
            "type": "select",
            "options": _get_available_pkg_options()
        },
        {
            "name": "force_reinstall",
            "label": "Force reinstall (override version pre-check for testing)",
            "type": "checkbox",
            "default": False
        }
    ]
)
def patch_infiniband_switch(component_name: str, params: dict, **kwargs):
    """Patch Infiniband 36P HDR switch with selected .pkg file.
    - Enforces rack serialization (iba0/ibb0 never patched together).
    - Pre-checks current firmware version (normalized) - if already at target AND force_reinstall=False, succeed immediately.
    - New: force_reinstall checkbox bypasses version pre-check and forces full reload+reset.
    - Robust reset: always captures raw buffer after 'reset' and sends 'y\r' if prompt appears (or if force_reinstall).
    - Polls reboot (15 minutes) with full version output in log.
    - Live SocketIO progress + guaranteed RED tab on any failure.
    """
    task_id = kwargs.get('task_id', f"{component_name}_patch_ib_switch")
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    pool = kwargs.get('pool')
    pkg_path = params.get('pkg_path') or params.get('params_Switch_patch_infiniband_switch_pkg_path')
    force_reinstall = params.get('force_reinstall', False) or params.get('params_Switch_patch_infiniband_switch_force_reinstall', False)

    def emit(msg, status='running'):
        clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
        if socketio and sid:
            socketio.emit('message', {
                'task_id': task_id,
                'line': f'[{component_name}] {clean_line}',
                'status': status
            }, room=sid, namespace='/')
        else:
            logger.warning(f"[patch_infiniband_switch] Socket emit skipped - line: {clean_line}")

    # === ULTRA-VISIBLE RELOAD MARKER - MUST APPEAR IN LOG TO CONFIRM v1.2.0 IS RUNNING ===
    emit("=== PATCH_INFINIBAND_SWITCH v1.2.0 ROBUST EMIT + ANSI CLEANING LOADED - CONCURRENT TAB ISOLATION FIXED ===", status='running')

    # === GRACEFUL NO-SELECTION HANDLING (no traceback) ===
    if not pkg_path or str(pkg_path).strip() in ('', 'None', 'null'):
        err = f"[{component_name}] ERROR: No firmware package selected. Please choose a .pkg file from the dropdown."
        logger.warning(err)
        emit(err, status='error')
        return err

    # === TYPE SAFETY: reject RoCE switches on IB plugin ===
    if 'roce' in component_name.lower():
        err = f"[{component_name}] ERROR: This is a RoCE (NX-OS) switch. Use the 'Patch NXOS Switch' function instead."
        logger.warning(err)
        emit(err, status='error')
        return err

    if not pkg_path or not os.path.exists(pkg_path):
        err = f"[{component_name}] ERROR: Invalid or missing .pkg file (received: {pkg_path})"
        logger.error(err)
        emit(err, status='error')
        raise Exception(err)

    # Extract target version from filename
    match = re.search(r'(\d+\.\d+\.\d+[_\-]\d+)', os.path.basename(pkg_path))
    if not match:
        err = f"[{component_name}] ERROR: Could not extract version from filename {os.path.basename(pkg_path)}"
        logger.error(err)
        emit(err, status='error')
        raise Exception(err)
    target_version = match.group(1)

    # Rack serialization
    rack_match = re.match(r'^(.*?)sw-', component_name)
    rack_id = rack_match.group(1) if rack_match else component_name
    lock = rack_locks[rack_id]
    with lock:
        logger.info(f"[{component_name}] Acquired rack lock for {rack_id}")
        emit(f"Acquired rack lock for {rack_id} (no concurrent patch on same-rack switches)")

        # Get switch root credential
        conn = get_db_pool_connection(pool) if pool else None
        cursor = conn.cursor() if conn else None
        try:
            password = (get_credential_silent(cursor, 'SWITCH', component_name, 'root') or
                        get_credential_silent(cursor, 'SWITCH', 'default', 'root') or
                        'welcome1')
        finally:
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn, pool)

        # Interactive patching via pexpect
        try:
            emit("SSH to switch (root)...")
            child = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no root@{component_name}', timeout=120)
            i = child.expect([r'password:', pexpect.TIMEOUT, r'-> ', r'# '])
            if i == 0:
                child.sendline(password)
                child.expect([r'-> ', r'# '], timeout=60)

            emit("disablesm")
            child.sendline('disablesm')
            child.expect([r'-> ', r'# '], timeout=60)

            # Pre-check current firmware version (normalized)
            emit("Checking current firmware version...")
            child.sendline('spsh -c "version"')
            child.expect([r'# ', pexpect.TIMEOUT], timeout=60)
            current_output = child.before.decode('utf-8', errors='ignore')
            emit(f"Current version reported: {current_output.strip()}")

            if not force_reinstall and _normalize_version(target_version) in _normalize_version(current_output):
                emit(f"Already at target firmware version {target_version} - skipping upgrade", status='success')
                child.close(force=True)
                success_msg = f"[{component_name}] Already at target firmware version {target_version} - no action needed"
                emit(success_msg, status='success')
                return success_msg
            elif force_reinstall:
                emit(f"FORCE REINSTALL OVERRIDE ENABLED - proceeding with full firmware reload + reset")

            emit("Entering spsh shell...")
            child.sendline('spsh')
            child.expect(r'-> ', timeout=60)

            # Correct sftp URL
            app_server = 'scaqaa04celadm12.us.oracle.com'
            clean_pkg = pkg_path.lstrip('/')
            sftp_url = f'sftp://root:welcome1@{app_server}//{clean_pkg}'
            load_cmd = f'load -source {sftp_url}'
            emit(f"load command: {load_cmd}")
            child.sendline(load_cmd)
            child.expect('Are you sure you want to load the specified file (y/n)?', timeout=1800)
            child.sendline('y')
            emit("Firmware download + update in progress (this can take up to 15 minutes)...")
            child.expect(['Firmware update is complete.', r'-> ', pexpect.TIMEOUT], timeout=1800)

            emit("Firmware loaded successfully. Changing to /SP target...")
            child.sendline('cd /SP')
            child.expect(r'-> ', timeout=30)

            emit("Resetting SP (exact manual sequence)...")
            child.sendline('reset')

            # AGGRESSIVE BUFFER CAPTURE
            time.sleep(1.5)
            raw_buffer = ""
            try:
                raw_buffer = child.read_nonblocking(4096, 10).decode('utf-8', errors='ignore')
            except:
                pass
            emit(f"Raw switch output after reset: {raw_buffer.strip()}")

            # FORCE 'y' IF PROMPT FOUND OR IF OVERRIDE ENABLED
            if "Are you sure you want to reset /SP (y/n)?" in raw_buffer or force_reinstall:
                emit("Sending confirmation 'y' now...")
                child.sendline('y')
                time.sleep(2)
                raw_after_y = ""
                try:
                    raw_after_y = child.read_nonblocking(2048, 5).decode('utf-8', errors='ignore')
                except:
                    pass
                emit(f"Raw switch output after sending y: {raw_after_y.strip()}")
                emit("Reset confirmed (y sent).")
            else:
                emit("Reset command sent (no confirmation prompt needed).")

            # CRITICAL DELAY - GIVE SP TIME TO PROCESS RESET
            emit("Waiting 45 seconds for SP to start processing reset...")
            time.sleep(45)
            child.close(force=True)

            emit("SP reset initiated. Waiting for switch reboot (up to 15 minutes)...")

            # Reboot polling + version verification (15 minutes)
            start_time = time.time()
            verified = False
            poll_count = 0
            while time.time() - start_time < 900:
                time.sleep(30)
                poll_count += 1
                try:
                    test = paramiko.SSHClient()
                    test.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    test.connect(component_name, username='root', password=password, timeout=15)
                    _, stdout, _ = test.exec_command('spsh -c "version"')
                    out = stdout.read().decode().strip()
                    test.close()
                    emit(f"Reboot poll #{poll_count} — switch reports: {out}")
                    if _normalize_version(target_version) in _normalize_version(out):
                        verified = True
                        emit(f"Reboot complete - firmware version verified: {target_version}", status='success')
                        break
                except Exception as poll_e:
                    emit(f"Reboot poll #{poll_count} — SSH failed (normal during reboot): {str(poll_e)}")
                    continue

            if not verified:
                raise Exception(f"Reboot timeout - version {target_version} not confirmed after 15 minutes (switch may not have rebooted)")

            success_msg = f"[{component_name}] Patch successful. New firmware: {target_version}"
            logger.info(success_msg)
            emit(success_msg, status='success')
            return success_msg

        except pexpect.TIMEOUT as te:
            err_msg = f"[{component_name}] Patch failed: Timeout exceeded during firmware load or reset (this step can take 15+ minutes). Full pexpect state logged above."
            logger.error(err_msg, exc_info=True)
            emit(err_msg, status='error')
            raise Exception(err_msg)
        except Exception as e:
            err_msg = f"[{component_name}] Patch failed: {str(e)}"
            logger.error(err_msg, exc_info=True)
            emit(err_msg, status='error')
            raise Exception(err_msg)
