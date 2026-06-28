# Filename: scripts/plugins/patch_guest.py
# Version: 2026-04-13 v1.4.4
# Changes: Ultra-strong per-execution isolation banner (local exec_uuid + full nodes list + timestamp). Guarantees every concurrent patch_guest run announces its own identity loudly.
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
    logger.info(f"[patch_guest] {clean_line}")
    with log_lock:
        if task_id in execution_logs:
            execution_logs[task_id]['status'] = status

@register_function(
    component_types=["Guest"],
    params=[
        {
            "name": "patch_zip",
            "label": "Patch Zip File (OL8 - same as Database)",
            "type": "select",
            "options_source": "series"
        }
    ]
)
def patch_guest(component_name=None, nodes=None, params=None, **kwargs):
    """Guest patching - FULL GROUP MODE (single patchmgr run) + bulletproof ssh-agent with exact MAA key."""
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    params = params or kwargs.get('params') or {}
    patch_zip = params.get('patch_zip')
    if nodes is None:
        nodes = [component_name] if component_name else []

    # === ULTRA-STRONG ISOLATION BANNER ===
    exec_uuid = uuid.uuid4().hex[:8]
    emit_message(task_id, sid, socketio, "=== v1.4.4 LOADED - Guest group mode active ===", status='running')
    emit_message(task_id, sid, socketio, f"*** NEW INDEPENDENT EXECUTION STARTED *** task_id={task_id} | exec_uuid={exec_uuid} | nodes={nodes} | timestamp={datetime.datetime.now().isoformat()}", status='running')
    emit_message(task_id, sid, socketio, f"DEBUG: Starting GROUP patch_guest for {len(nodes)} guests", status='running')
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
    emit_message(task_id, sid, socketio, f"Starting Guest patch for {len(nodes)} VM(s) with {patch_zip}", status='running')
    try:
        emit_message(task_id, sid, socketio, "DEBUG: Starting ssh-agent and loading exact MAA key", status='running')
        agent_proc = subprocess.run("ssh-agent -s", shell=True, capture_output=True, text=True)
        if agent_proc.returncode != 0:
            raise Exception(f"ssh-agent failed to start: {agent_proc.stderr.strip()}")
        agent_env = os.environ.copy()
        for line in agent_proc.stdout.splitlines():
            if '=' in line and 'SSH_' in line:
                key, val = line.split('=', 1)
                agent_env[key.strip()] = val.split(';')[0].strip()
        add_proc = subprocess.run(
            f"ssh-add {MAA_SSH_KEY} 2>&1",
            shell=True,
            capture_output=True,
            text=True,
            env=agent_env
        )
        if add_proc.returncode != 0:
            raise Exception(f"ssh-add failed (exit {add_proc.returncode}): {add_proc.stderr.strip() or add_proc.stdout.strip()}. "
                            f"Key file: {MAA_SSH_KEY} must exist and be readable by maatest user.")
        emit_message(task_id, sid, socketio, "DEBUG: ssh-agent + MAA key loaded successfully (ssh-add succeeded)", status='running')
        version_part = None
        if patch_zip and isinstance(patch_zip, str):
            try:
                if 'ol8_' in patch_zip:
                    version_part = patch_zip.split('ol8_')[1].split('_Linux-x86-64.zip')[0]
                elif 'ovs_' in patch_zip:
                    version_part = patch_zip.split('ovs_')[1].split('_Linux-x86-64.zip')[0]
                elif '_' in patch_zip and patch_zip.endswith('.zip'):
                    version_part = patch_zip.rsplit('_', 1)[0].split('_')[-1]
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
        log_dir = os.path.join(STAGING_DIR, f'logs_vm_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}')
        os.makedirs(log_dir, exist_ok=True)
        rel_repo = os.path.relpath(zip_path, patch_dir)
        cmd = [
            './patchmgr',
            '--dbnodes', list_path,
            '--upgrade',
            '--repo', rel_repo,
            '--target_version', version_part,
            '--log_dir', log_dir,
            '--nobackup'
        ]
        emit_message(task_id, sid, socketio, f"Executing: cd {os.path.basename(patch_dir)} && {' '.join(cmd)}", status='running')
        process = subprocess.Popen(
            cmd,
            cwd=patch_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env=agent_env
        )
        for line in iter(process.stdout.readline, ''):
            line = line.rstrip()
            if line.strip():
                emit_message(task_id, sid, socketio, line)
        process.wait()
        if process.returncode != 0:
            raise Exception(f"patchmgr failed with exit code {process.returncode}")
        success_msg = f"Guest patching completed successfully for all {len(nodes)} VM(s)"
        logger.info(success_msg)
        emit_message(task_id, sid, socketio, success_msg, status='success')
        return success_msg
    except Exception as e:
        error_msg = f"ERROR during Guest patch: {str(e)}"
        logger.error(error_msg, exc_info=True)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        raise
    finally:
        if 'list_path' in locals() and os.path.exists(list_path):
            try:
                os.unlink(list_path)
            except:
                pass
        try:
            subprocess.run("ssh-agent -k 2>/dev/null || true", shell=True)
        except:
            pass
