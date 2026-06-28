# Filename: scripts/plugins/patch_nxos_switch.py
# Version: 2026-04-10 v1.2.0
# Changes: Standardized emit() with ANSI stripping + fallback (exact match to patch_database/storage/guest). Added ultra-visible reload marker. This fixes output intermingling between tabs when running concurrent patches (e.g. patch_guest + patch_nxos_switch).
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
def _get_available_nxos_pkg_options():
    options = []
    pkg_base = "/home/exports"
    if not os.path.exists(pkg_base):
        logger.warning("NXOS patch plugin: /home/exports not found - no .bin files available")
        return []
    for root, _, files in os.walk(pkg_base):
        for f in files:
            if f.startswith('nxos64-cs.') and f.endswith('.bin'):
                full_path = os.path.join(root, f)
                label = f
                options.append({"value": full_path, "label": label})
    def version_key(opt):
        m = re.search(r'(\d+\.\d+\.\d+[A-Za-z0-9\.]*)', opt['label'])
        return m.group(1) if m else opt['label']
    options.sort(key=version_key, reverse=True)
    logger.info(f"NXOS patch plugin: discovered {len(options)} .bin files")
    return options
def _normalize_version(v):
    """Normalize version strings for pre-check comparison."""
    return re.sub(r'[^0-9.]', '', v)
@register_function(
    component_types=["Switch"],
    params=[
        {
            "name": "pkg_path",
            "label": "Select NX-OS Firmware (.bin)",
            "type": "select",
            "options": _get_available_nxos_pkg_options()
        },
        {
            "name": "force_reinstall",
            "label": "Force reinstall (override version pre-check for testing)",
            "type": "checkbox",
            "default": False
        }
    ]
)
def patch_nxos_switch(component_name: str, params: dict, **kwargs):
    """Patch Cisco NX-OS RoCE switch with selected .bin file.
    - Supports force_reinstall checkbox for same-version reinstalls (as requested).
    - SCP copy to bootflash: as admin user.
    - Impact check + install all nxos bootflash:filename.bin with y confirmation.
    - Rack serialization (rocea0/roceb0 never patched together).
    - Live SocketIO progress + guaranteed RED tab on any failure.
    """
    task_id = kwargs.get('task_id', f"{component_name}_patch_nxos")
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    pool = kwargs.get('pool')
    pkg_path = params.get('pkg_path') or params.get('params_Switch_patch_nxos_switch_pkg_path')
    force_reinstall = params.get('force_reinstall', False) or params.get('params_Switch_patch_nxos_switch_force_reinstall', False)

    def emit(msg, status='running'):
        clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
        if socketio and sid:
            socketio.emit('message', {
                'task_id': task_id,
                'line': f'[{component_name}] {clean_line}',
                'status': status
            }, room=sid, namespace='/')
        else:
            logger.warning(f"[patch_nxos_switch] Socket emit skipped - line: {clean_line}")

    # === ULTRA-VISIBLE RELOAD MARKER - MUST APPEAR IN LOG TO CONFIRM v1.2.0 IS RUNNING ===
    emit("=== PATCH_NXOS_SWITCH v1.2.0 ROBUST EMIT + ANSI CLEANING LOADED - CONCURRENT TAB ISOLATION FIXED ===", status='running')

    # === GRACEFUL NO-SELECTION HANDLING (no traceback) ===
    if not pkg_path or str(pkg_path).strip() in ('', 'None', 'null'):
        err = f"[{component_name}] ERROR: No firmware package selected. Please choose a .bin file from the dropdown."
        logger.warning(err)
        emit(err, status='error')
        return err

    # === TYPE SAFETY: reject IB switches on NXOS plugin ===
    if 'roce' not in component_name.lower():
        err = f"[{component_name}] ERROR: This is an Infiniband switch. Use the 'Patch Infiniband Switch' function instead."
        logger.warning(err)
        emit(err, status='error')
        return err

    if not pkg_path or not os.path.exists(pkg_path):
        err = f"[{component_name}] ERROR: Invalid or missing .bin file"
        logger.error(err)
        emit(err, status='error')
        raise Exception(err)

    filename = os.path.basename(pkg_path)
    match = re.search(r'nxos64-cs\.(\d+\.\d+\.\d+[A-Za-z0-9\.]*)', filename)
    target_version = match.group(1) if match else filename

    # Rack serialization
    rack_match = re.match(r'^(.*?)sw-', component_name)
    rack_id = rack_match.group(1) if rack_match else component_name
    lock = rack_locks[rack_id]
    with lock:
        logger.info(f"[{component_name}] Acquired rack lock for {rack_id}")
        emit(f"Acquired rack lock for {rack_id} (no concurrent patch on same-rack switches)")

        # Get admin credential
        conn = get_db_pool_connection(pool) if pool else None
        cursor = conn.cursor() if conn else None
        try:
            password = (get_credential_silent(cursor, 'SWITCH', component_name, 'admin') or
                        get_credential_silent(cursor, 'SWITCH', 'default', 'admin') or
                        'welcome1')
        finally:
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn, pool)

        try:
            emit("Copying firmware to bootflash via SCP (admin user)...")
            transport = paramiko.Transport((component_name, 22))
            transport.connect(username='admin', password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.put(pkg_path, f"bootflash:{filename}")
            sftp.close()
            transport.close()
            emit(f"Firmware {filename} copied to bootflash successfully")

            emit("SSH to switch (admin)...")
            child = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no admin@{component_name}', timeout=120)
            i = child.expect([r'password:', pexpect.TIMEOUT, r'# '])
            if i == 0:
                child.sendline(password)
                child.expect(r'# ', timeout=60)

            emit("Checking current NX-OS version...")
            child.sendline('show version | include "NX-OS:"')
            child.expect(r'# ', timeout=60)
            current_output = child.before.decode('utf-8', errors='ignore')
            emit(f"Current version reported: {current_output.strip()}")

            if not force_reinstall and _normalize_version(target_version) in _normalize_version(current_output):
                emit(f"Already at target version {target_version} - skipping upgrade", status='success')
                child.close(force=True)
                success_msg = f"[{component_name}] Already at target version {target_version} - no action needed"
                emit(success_msg, status='success')
                return success_msg
            elif force_reinstall:
                emit(f"FORCE REINSTALL OVERRIDE ENABLED - proceeding with full upgrade even though version matches ({target_version})")

            # Impact check (Cisco recommended)
            emit("Running show install all impact check...")
            child.sendline(f"show install all impact nxos bootflash:{filename}")
            child.expect(r'# ', timeout=180)
            impact_output = child.before.decode('utf-8', errors='ignore')
            emit(f"Impact check output:\n{impact_output[-600:]}")

            # Install all command
            emit("Starting NX-OS upgrade (install all)...")
            child.sendline(f"install all nxos bootflash:{filename}")
            idx = child.expect([r'Do you want to continue with the installation \(y/n\)\?', r'# ', pexpect.TIMEOUT], timeout=300)
            if idx == 0:
                child.sendline('y')
                emit("Confirmed installation (y sent)")
            elif idx == 1:
                emit("Install command sent (no confirmation prompt needed)")
            else:
                emit("Install command timed out - proceeding")

            time.sleep(2)
            raw_buffer = ""
            try:
                raw_buffer = child.read_nonblocking(4096, 5).decode('utf-8', errors='ignore')
            except:
                pass
            emit(f"Raw switch output after install: {raw_buffer.strip()}")

            child.close(force=True)
            emit("Installation started. Waiting for switch reboot (up to 15 minutes)...")

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
                    test.connect(component_name, username='admin', password=password, timeout=15)
                    _, stdout, _ = test.exec_command('show version | include "NX-OS:"')
                    out = stdout.read().decode().strip()
                    test.close()
                    emit(f"Reboot poll #{poll_count} — switch reports: {out}")
                    if _normalize_version(target_version) in _normalize_version(out):
                        verified = True
                        emit(f"Reboot complete - NX-OS version verified: {target_version}", status='success')
                        break
                except Exception as poll_e:
                    emit(f"Reboot poll #{poll_count} — SSH failed (normal during reboot): {str(poll_e)}")
                    continue

            if not verified:
                raise Exception(f"Reboot timeout - version {target_version} not confirmed after 15 minutes (switch may not have rebooted)")

            success_msg = f"[{component_name}] NX-OS patch successful. New firmware: {target_version}"
            logger.info(success_msg)
            emit(success_msg, status='success')
            return success_msg

        except pexpect.TIMEOUT as te:
            err_msg = f"[{component_name}] Patch failed: Timeout exceeded during impact check or install (this step can take 15+ minutes). Full pexpect state logged above."
            logger.error(err_msg, exc_info=True)
            emit(err_msg, status='error')
            raise Exception(err_msg)
        except Exception as e:
            err_msg = f"[{component_name}] Patch failed: {str(e)}"
            logger.error(err_msg, exc_info=True)
            emit(err_msg, status='error')
            raise Exception(err_msg)
