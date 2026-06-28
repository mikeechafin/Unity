# Filename: scripts/plugins/patch_database.py
# Version: 2026-04-13 v1.4.6
# Changes: Replaced Python agent_env wrapper with single bash -c + eval ssh-agent (most reliable inheritance pattern) + added explicit pre-flight dcli equivalence test before launching patchmgr + loud unique marker so you can confirm the new version is running.
from environment_setup_registry import register_function
import tempfile
import os
import subprocess
import datetime
import re
import uuid
from maa_libraries import logger
from shared_state import execution_logs, log_lock

STAGING_DIR = "/home/maatest/mchafin/TEST_CONFIG_SCRIPTS/PATCHING"
MAA_SSH_KEY = "/home/maatest/.ssh/id_ed25519_maa"

def emit_message(task_id, sid, socketio, msg, status='running'):
    clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', str(msg))
    if socketio and sid:
        socketio.emit('message', {
            'task_id': task_id,
            'line': clean_line,
            'status': status
        }, room=sid, namespace='/')
    logger.info(f"[patch_database] {clean_line}")
    with log_lock:
        if task_id in execution_logs:
            execution_logs[task_id]['status'] = status

@register_function(
    component_types=["Database Server"],
    params=[
        {
            "name": "patch_zip",
            "label": "Patch Zip File (OL8 - same as Guest)",
            "type": "select",
            "options_source": "series"
        }
    ]
)
def patch_database(component_name=None, nodes=None, params=None, **kwargs):
    """Database Server patching - FULL GROUP MODE + single bash -c ssh-agent wrapper (v1.4.6)."""
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    params = params or kwargs.get('params') or {}
    patch_zip = params.get('patch_zip')
    if nodes is None:
        nodes = [component_name] if component_name else []
    exec_uuid = uuid.uuid4().hex[:8]
    emit_message(task_id, sid, socketio, "=== v1.4.6 LOADED - Database group mode active ===", status='running')
    emit_message(task_id, sid, socketio, f"*** NEW INDEPENDENT EXECUTION STARTED *** task_id={task_id} | exec_uuid={exec_uuid} | nodes={nodes} | timestamp={datetime.datetime.now().isoformat()}", status='running')
    emit_message(task_id, sid, socketio, f"DEBUG: Starting GROUP patch_database for {len(nodes)} DB servers", status='running')
    emit_message(task_id, sid, socketio, f"DEBUG: task_id={task_id}, zip={patch_zip}", status='running')
    if not nodes:
        error_msg = "ERROR: No nodes provided for patching"
        logger.error(error_msg)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        return error_msg
    if not patch_zip:
        error_msg = "ERROR: No patch zip selected"
        logger.error(error_msg)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        return error_msg
    emit_message(task_id, sid, socketio, f"Starting Database Server patch for {len(nodes)} DB(s) with {patch_zip}", status='running')
    try:
        # === ROBUST SINGLE BASH WRAPPER (most reliable for patchmgr) ===
        emit_message(task_id, sid, socketio, "DEBUG: v1.4.6 - Launching patchmgr inside single bash -c ssh-agent wrapper", status='running')
        version_part = None
        if patch_zip and isinstance(patch_zip, str):
            try:
                if 'ol8_' in patch_zip:
                    version_part = patch_zip.split('ol8_')[1].split('_Linux-x86-64.zip')[0]
                elif 'ovs_' in patch_zip:
                    version_part = patch_zip.split('ovs_')[1].split('_Linux-x86-64.zip')[0]
                else:
                    version_part = patch_zip.replace('.zip', '')
            except Exception:
                version_part = patch_zip.replace('.zip', '') if patch_zip else None
        if not version_part or version_part == 'unknown':
            raise Exception(f"Could not extract version from zip name: {patch_zip}")
        patch_dir = os.path.join(STAGING_DIR, f'dbserver_patch_{version_part}')
        if not os.path.exists(patch_dir):
            raise Exception(f"Patch directory {patch_dir} does not exist. Run copy_latest_patches first.")
        zip_path = os.path.join(STAGING_DIR, patch_zip)
        if not os.path.exists(zip_path):
            raise Exception(f"Repo zip {zip_path} does not exist")
        patchmgr_path = os.path.join(patch_dir, 'patchmgr')
        if os.path.exists(patchmgr_path):
            os.chmod(patchmgr_path, 0o755)
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as list_file:
            for node in nodes:
                list_file.write(node + '\n')
            list_path = list_file.name
        log_dir = os.path.join(STAGING_DIR, f'logs_database_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}')
        os.makedirs(log_dir, exist_ok=True)
        rel_repo = os.path.relpath(zip_path, patch_dir)
        patchmgr_args = f'--dbnodes "{list_path}" --upgrade --repo "{rel_repo}" --target_version {version_part} --log_dir "{log_dir}" --nobackup'
        # Single bash command with full ssh-agent eval + pre-flight dcli test
        shell_cmd = f'''
set -e
eval "$(ssh-agent -s)" > /dev/null 2>&1
ssh-add {MAA_SSH_KEY} > /dev/null 2>&1 || {{ echo "FATAL: ssh-add FAILED for key {MAA_SSH_KEY}"; exit 1; }}
echo "=== SSH AGENT + MAA KEY LOADED SUCCESSFULLY (v1.4.6) ==="
echo "=== PRE-FLIGHT DCLI TEST ==="
cd "{patch_dir}"
dcli -l root -c "$(cat {list_path} | tr '\\n' ',')" -s "-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no" "echo PREFLIGHT_OK_$(date +%s)" || {{ echo "FATAL: Pre-flight dcli failed"; exit 1; }}
echo "Running patchmgr now..."
./patchmgr {patchmgr_args}
'''
        process = subprocess.Popen(
            ["bash", "-c", shell_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        for line in iter(process.stdout.readline, ''):
            line = line.rstrip()
            if line.strip():
                emit_message(task_id, sid, socketio, line)
        process.wait()
        if process.returncode != 0:
            raise Exception(f"patchmgr failed with exit code {process.returncode}")
        success_msg = f"Database patching completed successfully for all {len(nodes)} DB(s)"
        logger.info(success_msg)
        emit_message(task_id, sid, socketio, success_msg, status='success')
        return success_msg
    except Exception as e:
        error_msg = f"ERROR during Database patch: {str(e)}"
        logger.error(error_msg, exc_info=True)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        raise
    finally:
        if 'list_path' in locals() and os.path.exists(list_path):
            try:
                os.unlink(list_path)
            except:
                pass
        subprocess.run("ssh-agent -k 2>/dev/null || true", shell=True)
