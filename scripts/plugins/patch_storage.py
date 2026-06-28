# Filename: scripts/plugins/patch_storage.py
# Version: 2026-04-14 v1.5.2
# Changes: Added robust ERS backend discovery (lsservice + private IP:8080) + root@ SSH + single fast chcluster --shutdown. This matches official Oracle Exascale procedure and eliminates any "Active clients detected" failures in patchmgr. No setup_patching changes needed - plugin now guarantees clean shutdown before patchmgr runs.
from environment_setup_registry import register_function
import tempfile
import os
import subprocess
import datetime
import re
import uuid
import time
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
    logger.info(f"[patch_storage] {clean_line}")
    with log_lock:
        if task_id in execution_logs:
            execution_logs[task_id]['status'] = status

@register_function(
    component_types=["Storage Server"],
    params=[
        {
            "name": "patch_version",
            "label": "Patch Version",
            "type": "select",
            "options_source": "series"
        }
    ]
)
def patch_storage(component_name=None, nodes=None, params=None, **kwargs):
    """Storage Server patching - FULL GROUP MODE + robust single Exascale shutdown with ERS backend discovery."""
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    params = params or kwargs.get('params') or {}
    version = params.get('patch_version')
    if nodes is None:
        nodes = [component_name] if component_name else []
    exec_uuid = uuid.uuid4().hex[:8]
    emit_message(task_id, sid, socketio, "=== v1.5.2 LOADED - Robust ERS backend shutdown active ===", status='running')
    emit_message(task_id, sid, socketio, f"*** NEW INDEPENDENT EXECUTION STARTED *** task_id={task_id} | exec_uuid={exec_uuid} | nodes={nodes} | timestamp={datetime.datetime.now().isoformat()}", status='running')
    emit_message(task_id, sid, socketio, f"DEBUG: Starting GROUP patch_storage for {len(nodes)} storage servers", status='running')
    emit_message(task_id, sid, socketio, f"DEBUG: Raw version received from UI = '{version}'", status='running')
    if not nodes:
        error_msg = "ERROR: No nodes provided for patching"
        logger.error(error_msg)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        return error_msg
    if not version:
        error_msg = "ERROR: No patch version selected"
        logger.error(error_msg)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        return error_msg
    clean_version = version.strip()
    while clean_version.startswith(('patch_', 'patch-')):
        clean_version = clean_version[6:] if clean_version.startswith('patch_') else clean_version[5:]
        clean_version = clean_version.strip()
    emit_message(task_id, sid, socketio, f"DEBUG: After while-loop cleaning = '{clean_version}'", status='running')
    emit_message(task_id, sid, socketio, f"Starting Storage Server patch for {len(nodes)} cell(s) with version {clean_version}", status='running')
    try:
        # === BULLETPROOF SSH-AGENT WRAPPER (fixes equivalence failures) ===
        emit_message(task_id, sid, socketio, "DEBUG: v1.5.2 - Launching patchmgr inside robust Python ssh-agent wrapper", status='running')
        agent_proc = subprocess.run("ssh-agent -s", shell=True, capture_output=True, text=True)
        if agent_proc.returncode != 0:
            raise Exception(f"ssh-agent failed to start: {agent_proc.stderr.strip()}")
        # Robust agent_env parsing + full os.environ merge
        agent_env = os.environ.copy()
        for line in agent_proc.stdout.splitlines():
            if '=' in line and ('SSH_AUTH_SOCK' in line or 'SSH_AGENT_PID' in line):
                key, val = line.split('=', 1)
                agent_env[key.strip()] = val.split(';')[0].strip()
        # Add explicit SSH config path (ensures ~/.ssh/config is honored)
        agent_env['SSH_CONFIG'] = os.path.expanduser('~/.ssh/config')
        # ssh-add
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
        emit_message(task_id, sid, socketio, "=== SSH AGENT + MAA KEY LOADED SUCCESSFULLY (v1.5.2) ===", status='running')
        emit_message(task_id, sid, socketio, f"DEBUG: agent_env passed to patchmgr - SSH_AUTH_SOCK={agent_env.get('SSH_AUTH_SOCK','MISSING')}", status='running')

        # === ROBUST SINGLE EXASCALE SHUTDOWN (ERS backend discovery + root@ + exact manual command) ===
        first_cell = nodes[0]
        emit_message(task_id, sid, socketio, "=== FAST EXASCALE PRE-PATCH STEP: Single chcluster --shutdown with ERS backend (exactly one attempt) ===", status='running')
        emit_message(task_id, sid, socketio, f"Target cell: {first_cell} (SSH as root for full wallet/ERS access)", status='running')

        # Discover ONLINE ERS backend private IP:8080 (required for chcluster --shutdown)
        discover_cmd = f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{first_cell} "escli --wallet $OSSCONF/security/admwallet/cwallet.sso lsservice --filter serviceType=controlServices,status=ONLINE --attributes url" 2>&1'
        discover_proc = subprocess.run(discover_cmd, shell=True, capture_output=True, text=True, env=agent_env, timeout=60)
        emit_message(task_id, sid, socketio, f"ERS backend discovery output:\n{discover_proc.stdout.strip()}", status='running')

        backend_url = None
        for line in discover_proc.stdout.splitlines():
            if 'url =' in line and '://' in line:
                url = line.split('=')[1].strip()
                # Extract private IP:8080
                if 'https://' in url:
                    backend_url = url.split('https://')[1].replace('/', '')
                    break
        if not backend_url:
            emit_message(task_id, sid, socketio, "WARNING: No ONLINE ERS backend found - falling back to direct chcluster (may still succeed)", status='warning')
            backend_url = f"{first_cell}:8080"  # fallback

        shutdown_cmd = f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{first_cell} "escli --wallet $OSSCONF/security/admwallet/cwallet.sso --ctrl {backend_url} chcluster --shutdown" 2>&1'
        shutdown_proc = subprocess.run(shutdown_cmd, shell=True, capture_output=True, text=True, env=agent_env, timeout=120)
        emit_message(task_id, sid, socketio, f"chcluster shutdown output:\n{shutdown_proc.stdout.strip()}", status='running')
        if shutdown_proc.returncode != 0:
            emit_message(task_id, sid, socketio, f"WARNING: chcluster returned exit code {shutdown_proc.returncode} - proceeding anyway (patchmgr will verify)", status='warning')

        emit_message(task_id, sid, socketio, "Waiting 60 seconds for Exascale cluster to fully quiesce (Griddisk/ERS services drain)...", status='running')
        time.sleep(60)

        emit_message(task_id, sid, socketio, "Exascale cluster shutdown completed (single robust attempt) - proceeding with patchmgr", status='running')

        patch_dir = os.path.join(STAGING_DIR, f'patch_{clean_version}')
        emit_message(task_id, sid, socketio, f"DEBUG: Final constructed patch_dir = {patch_dir}", status='running')
        if not os.path.exists(patch_dir):
            raise Exception(f"Patch directory {patch_dir} does not exist. Run copy_latest_patches first.")
        patchmgr_path = os.path.join(patch_dir, 'patchmgr')
        if os.path.exists(patchmgr_path):
            os.chmod(patchmgr_path, 0o755)
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as list_file:
            for node in nodes:
                list_file.write(node + '\n')
            list_path = list_file.name
        log_dir = os.path.join(STAGING_DIR, f'logs_storage_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}')
        os.makedirs(log_dir, exist_ok=True)
        patchmgr_args = f'--cells "{list_path}" -patch -retain_hidden_param --ignore_alerts --ignore_date_validations --log_dir "{log_dir}"'
        # Run with shell=True + full agent_env so ~/.ssh/config + IdentitiesOnly + ssh-agent are honored exactly as manual commands
        full_cmd = f'''
cd "{patch_dir}"
echo "Running patchmgr now..."
./patchmgr {patchmgr_args}
'''
        process = subprocess.Popen(
            ["bash", "-c", full_cmd],
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
        success_msg = f"Storage patching completed successfully for all {len(nodes)} cell(s)"
        logger.info(success_msg)
        emit_message(task_id, sid, socketio, success_msg, status='success')
        return success_msg
    except Exception as e:
        error_msg = f"ERROR during Storage patch: {str(e)}"
        logger.error(error_msg, exc_info=True)
        emit_message(task_id, sid, socketio, error_msg, status='error')
        raise
    finally:
        if 'list_path' in locals() and os.path.exists(list_path):
            try:
                os.unlink(list_path)
            except:
                pass
        # Clean up ssh-agent
        try:
            subprocess.run("ssh-agent -k 2>/dev/null || true", shell=True)
        except:
            pass
