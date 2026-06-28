# Version: 2026-06-02 v1.11
# Changes: Removed entire broad fallback (Phase 2) per user request — only specific named files from primary patterns are now copied; added exadata_ol9_*.zip support for new series; offload packages remain omitted

# Filename: copy_latest_patches.py
# Version: 2026-06-02 v1.11
# Changes:
#   - Removed broad fallback completely (no more Ocmd-*.zip or other unexpected files)
#   - Primary patterns updated with exadata_ol9_*.zip for OSS_PT.EXAOL9 series
#   - Still omits offload server packages as previously requested
#   - Only copies files that exactly match the explicit patterns you want
#   - Clean, production-ready, no placeholders

from environment_setup_registry import register_function
import subprocess
import os
import hashlib
import fnmatch
import shutil
import time
import paramiko
from maa_libraries import logger
from flask import current_app
from shared_state import execution_logs, log_lock
import re

from ade_kerberos_helper import run_ade_command


def emit_message(task_id, sid, socketio, msg, status='info'):
    clean_msg = re.sub(r'\x1B(?:[@-Z\-*]|[[0-9?]*[ -/]*[@-~])', '', str(msg))
    if socketio and sid:
        socketio.emit('message', {
            'task_id': task_id,
            'line': clean_msg,
            'status': status
        }, room=sid, namespace='/')
    logger.info(f"[CopyPatches] {clean_msg}")
    if status in ('error', 'success', 'warning'):
        with log_lock:
            if task_id in execution_logs:
                execution_logs[task_id]['status'] = status


@register_function(
    component_types=["Global"],
    params=[
        {
            "name": "series",
            "label": "Series",
            "type": "select",
            "options_from": "/setup/api/series",
            "placeholder": "Select series (e.g. OSS_MAIN_LINUX.X64)"
        },
        {
            "name": "label",
            "label": "Label",
            "type": "select",
            "options_from": "/setup/api/labels?series={series}",
            "placeholder": "Select label after choosing series"
        }
    ]
)
def copy_latest_patches(component_name, params, **kwargs):
    task_id = kwargs.pop('task_id', None) or kwargs.pop('taskId', None) or 'copy_latest_patches'
    sid = kwargs.pop('sid', None)
    socketio = kwargs.pop('socketio', None)
    app_obj = kwargs.pop('app', None) or kwargs.pop('app_obj', None)

    emit_message(task_id, sid, socketio, "=== COPY_LATEST_PATCHES v1.11 STARTED ===", "running")

    series = params.get('series') or params.get('params_Global_copy_latest_patches_series')
    label = params.get('label') or params.get('params_Global_copy_latest_patches_label')

    if not series or not label:
        msg = f"Error: Series and label are required"
        emit_message(task_id, sid, socketio, msg, 'error')
        raise Exception(msg)

    emit_message(task_id, sid, socketio, f"Starting copy for {series} / {label}...", 'running')

    try:
        if app_obj:
            with app_obj.app_context():
                _do_copy(task_id, sid, socketio, series, label)
        else:
            _do_copy(task_id, sid, socketio, series, label)
    except Exception as e:
        error_msg = f"Critical error: {str(e)}"
        logger.exception(error_msg)
        emit_message(task_id, sid, socketio, error_msg, 'error')
        raise


def _do_copy(task_id, sid, socketio, series, label):
    emit_message(task_id, sid, socketio, f"Querying ADE for label: {label}", 'running')

    cmd = f"ade describe -label {label} -labelserver"
    stdout, stderr, rc = run_ade_command(cmd, pool=current_app.config.get('DB_POOL'))
    if rc != 0:
        raise Exception(f"ADE describe failed: {stderr or stdout}")

    latest_dir = f"{stdout.strip().rstrip('/')}/oss/bin"
    emit_message(task_id, sid, socketio, f"Target directory on ADE host: {latest_dir}", 'running')

    # Hosts
    ade_host   = 'phoenix95023.dev3sub2phx.databasede3phx.oraclevcn.com'  # Source
    dest_host  = 'scaqaa04celadm12.us.oracle.com'                         # Destination (APP server)
    ssh_user   = 'mchafin'                                                # ADE connections use mchafin
    dest_user  = 'maatest'
    local_dir  = '/home/maatest/mchafin/TEST_CONFIG_SCRIPTS/PATCHING'

    os.makedirs(local_dir, exist_ok=True)
    emit_message(task_id, sid, socketio, f"Local target directory: {local_dir}", 'running')

    file_patterns = ['*.patch.zip', '*switch.patch.zip', 'dbserver.patch.zip', 'exadata_ol8_*.zip', 'exadata_ol9_*.zip', 'exadata_ovs_*.zip']

    processed_files = []
    failed_files = []

    # Connect to ADE host as mchafin (passwordless key or DB fallback expected)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ade_host, username=ssh_user, look_for_keys=True, allow_agent=True)
    emit_message(task_id, sid, socketio, f"Connected to ADE host as {ssh_user}", 'running')

    all_found_files = set()

    def list_remote_files(pattern):
        _, stdout, stderr = client.exec_command(f"ls {latest_dir}/{pattern} 2>/dev/null || true")
        return [f.strip() for f in stdout.read().decode().splitlines() if f.strip()]

    # Phase 1: original patterns
    for pattern in file_patterns:
        emit_message(task_id, sid, socketio, f"Listing files matching: {pattern}", 'running')
        files = list_remote_files(pattern)
        if not files:
            emit_message(task_id, sid, socketio, f"No files found for pattern: {pattern} (normal for many modern labels)", 'info')
            continue
        for f in files:
            all_found_files.add(f)

    if not all_found_files:
        emit_message(task_id, sid, socketio, "No matching files found on ADE host. Nothing to copy.", 'warning')
        client.close()
        return "No files found"

    emit_message(task_id, sid, socketio, f"Discovered {len(all_found_files)} file(s) on ADE host", 'running')

    for remote_file in sorted(all_found_files):
        file_name = os.path.basename(remote_file)
        local_path = os.path.join(local_dir, file_name)
        emit_message(task_id, sid, socketio, f"Processing: {file_name}", 'running')

        if file_name == 'dbserver.patch.zip' and os.path.exists(local_path):
            try:
                os.remove(local_path)
                emit_message(task_id, sid, socketio, f"Deleted existing {file_name}", 'running')
            except Exception as e:
                emit_message(task_id, sid, socketio, f"Failed to delete {file_name}: {e}", 'warning')
                failed_files.append(file_name)
                continue

        # MD5 on ADE host
        _, stdout, stderr = client.exec_command(f"md5sum {remote_file}")
        md5_line = stdout.read().decode().strip()
        remote_md5 = md5_line.split()[0] if md5_line else None
        if not remote_md5:
            emit_message(task_id, sid, socketio, f"MD5 failed for {file_name}", 'warning')
            failed_files.append(file_name)
            continue

        # Skip if local copy matches (except dbserver.patch.zip)
        if file_name != 'dbserver.patch.zip' and os.path.exists(local_path):
            local_md5 = hashlib.md5()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    local_md5.update(chunk)
            if local_md5.hexdigest() == remote_md5:
                emit_message(task_id, sid, socketio, f"Skipping {file_name} (MD5 match)", 'running')
                processed_files.append(file_name)
                continue

        # Push from ADE host to destination server
        copied = False
        for attempt in range(3):
            try:
                scp_cmd = f"scp {remote_file} {dest_user}@{dest_host}:{local_path}"
                stdin, stdout, stderr = client.exec_command(scp_cmd)
                err = stderr.read().decode().strip()
                if err:
                    raise Exception(err)
                emit_message(task_id, sid, socketio, f"Copied {file_name} → {dest_host}", 'running')
                processed_files.append(file_name)
                copied = True
                break
            except Exception as e:
                emit_message(task_id, sid, socketio, f"SCP attempt {attempt+1} failed: {e}", 'warning')
                if attempt == 2:
                    failed_files.append(file_name)
                time.sleep(2)

    client.close()
    emit_message(task_id, sid, socketio, "Disconnected from ADE host", 'running')

    # Unzip phase on destination
    if processed_files:
        emit_message(task_id, sid, socketio, "Unzipping patch files...", 'running')
        for fname in processed_files:
            if not any(fnmatch.fnmatch(fname, p) for p in ['*.patch.zip', '*switch.patch.zip', 'dbserver.patch.zip']):
                continue
            zip_path = os.path.join(local_dir, fname)
            if not os.path.exists(zip_path):
                continue
            unzip_name = fname.replace('.zip', '').replace('.switch.patch', '_switch')
            unzip_dir = os.path.join(local_dir, unzip_name)
            if os.path.exists(unzip_dir):
                shutil.rmtree(unzip_dir, ignore_errors=True)
            try:
                subprocess.run(['unzip', '-o', zip_path, '-d', local_dir], check=True, capture_output=True, text=True, timeout=300)
                emit_message(task_id, sid, socketio, f"Unzipped {fname}", 'running')
            except Exception as e:
                emit_message(task_id, sid, socketio, f"Unzip failed for {fname}: {e}", 'error')
                failed_files.append(fname)

    if failed_files:
        emit_message(task_id, sid, socketio, f"Completed with {len(failed_files)} issues", 'warning')
    else:
        emit_message(task_id, sid, socketio, "Successfully copied and processed all patches", 'success')
        if socketio and sid:
            socketio.emit('refresh_cache', {'task_id': task_id}, room=sid)

    return "done"
