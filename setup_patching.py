# Filename: setup_patching.py
# Version: 2026-04-14 v1.6.2
# Changes: Made Exascale pre-shutdown conditional - skip 60s wait + message if "Not an Exascale cell." detected (as confirmed by manual cell test). Fixed cleanup to run locally on management server (cd + patchmgr -cleanup) instead of dcli to cells - fixes "No such file or directory" error.
import os
import subprocess
import tempfile
import time
import datetime
import uuid
import oracledb
import importlib.util
import sys
# === ROBUST PLUGIN LOADING (correct path to scripts/plugins/) ===
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
plugin_path = os.path.join(APP_ROOT, "scripts", "plugins", "patch_guest.py")
if not os.path.exists(plugin_path):
    raise ImportError(f"patch_guest.py not found at {plugin_path}")
spec = importlib.util.spec_from_file_location("patch_guest", plugin_path)
patch_guest_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch_guest_module)
patch_guest = patch_guest_module.patch_guest
from maa_libraries import logger
from setup_db_tracking import start_script_run, end_script_run
from shared_state import execution_logs, log_lock
from flask import current_app
MAA_SSH_KEY = "/home/maatest/.ssh/id_ed25519_maa"

def run_group_patch_background(task_id, nodes, func_name, unused, extra_params, app_obj, sid):
    logger.info(f"REAL GROUP PATCH STARTED: task_id={task_id}, func_name={func_name}, nodes={nodes}, extra_params={extra_params}")
    with app_obj.app_context():
        # === CRITICAL: FORCE NEW EXECUTION LOG ENTRY + LOCK (prevents tab collision) ===
        with log_lock:
            execution_logs[task_id] = {
                'status': 'running',
                'lines': [],
                'start_time': time.time()
            }
        # === ULTRA-LOUD ISOLATION BANNER ===
        banner = f"*** NEW INDEPENDENT GROUP PATCH EXECUTION STARTED ***\ntask_id={task_id} | func={func_name} | nodes={len(nodes)} | timestamp={datetime.datetime.now().isoformat()}"
        current_app.socketio.emit('message', {'task_id': task_id, 'line': banner, 'status': 'running'}, room=sid, namespace='/')
        logger.info(banner)

        pool = current_app.config['DB_POOL']
        try:
            if func_name == 'patch_database':
                zip_file, version = extra_params
                logger.info(f"Group patch_database: zip={zip_file}, version={version}")
                patch_database_servers(task_id, nodes, zip_file, version, app_obj, sid, pool)
            elif func_name == 'patch_guest':
                zip_file, version = extra_params
                logger.info(f"Group patch_guest: zip={zip_file}, version={version}")
                patch_guest(
                    nodes=nodes,
                    params={'patch_zip': zip_file},
                    task_id=task_id,
                    sid=sid,
                    socketio=current_app.socketio,
                    pool=pool
                )
            elif func_name == 'patch_storage':
                version = extra_params
                logger.info(f"Group patch_storage: version={version}")
                patch_storage_servers(task_id, nodes, version, app_obj, sid, pool)
            else:
                raise Exception(f"Unknown group function {func_name}")
            with log_lock:
                execution_logs[task_id]['status'] = 'success'
            current_app.socketio.emit('message', {'task_id': task_id, 'line': f"Group patch {func_name} completed successfully", 'status': 'success'}, room=sid, namespace='/')
        except Exception as e:
            error_msg = f"Group patch {func_name} failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            with log_lock:
                if task_id not in execution_logs:
                    execution_logs[task_id] = {'status': 'error', 'lines': [], 'start_time': time.time()}
                execution_logs[task_id]['lines'].append(error_msg)
                execution_logs[task_id]['status'] = 'error'
            current_app.socketio.emit('message', {'task_id': task_id, 'line': error_msg, 'status': 'error'}, room=sid, namespace='/')

def patch_database_servers(task_id, nodes, zip_file, version, app_obj, sid, pool):
    run_id = start_script_run('patch_database_servers', pool=pool)
    try:
        with app_obj.app_context():
            logger.info(f"patch_database_servers: zip_file={zip_file}, version={version}")
            target_dir = '/home/maatest/mchafin/TEST_CONFIG_SCRIPTS/PATCHING'
            clean_version = version.strip()
            while clean_version.startswith(('patch_', 'patch-')):
                clean_version = clean_version[6:] if clean_version.startswith('patch_') else clean_version[5:]
                clean_version = clean_version.strip()
            logger.info(f"DEBUG: patch_database_servers cleaned version '{version}' → '{clean_version}'")
            patch_dir = os.path.join(target_dir, f'dbserver_patch_{clean_version}')
            if not os.path.exists(patch_dir):
                raise Exception(f"Patch directory {patch_dir} does not exist")
            zip_path = os.path.join(target_dir, zip_file)
            if not os.path.exists(zip_path):
                raise Exception(f"Repo zip {zip_path} does not exist")
            patchmgr_path = os.path.join(patch_dir, 'patchmgr')
            if os.path.exists(patchmgr_path):
                os.chmod(patchmgr_path, 0o755)
            else:
                raise Exception(f"patchmgr not found in {patch_dir}")
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as list_file:
                for node in nodes:
                    list_file.write(node + '\n')
                list_path = list_file.name
            log_dir = os.path.join(target_dir, f'logs_database_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}')
            os.makedirs(log_dir, exist_ok=True)
            rel_repo = os.path.relpath(zip_path, patch_dir)
            patchmgr_args = f'--dbnodes "{list_path}" --upgrade --repo "{rel_repo}" --target_version {clean_version} --log_dir "{log_dir}" --nobackup'
            logger.info("Starting proven bash ssh-agent wrapper for patch_database")
            shell_cmd = f'''
set -e
eval "$(ssh-agent -s)" > /dev/null 2>&1
ssh-add {MAA_SSH_KEY} > /dev/null 2>&1 || {{ echo "FATAL: ssh-add FAILED for key {MAA_SSH_KEY}"; exit 1; }}
echo "=== SSH AGENT + MAA KEY LOADED SUCCESSFULLY (setup_patching v1.5.0) ==="
cd "{patch_dir}"
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
                with log_lock:
                    execution_logs[task_id]['lines'].append(line)
                current_app.socketio.emit('message', {'task_id': task_id, 'line': line, 'status': 'running'}, room=sid, namespace='/')
            process.wait()
            if process.returncode != 0:
                raise Exception(f"patchmgr failed with exit code {process.returncode}")
            final_msg = "Patching completed successfully"
            with log_lock:
                execution_logs[task_id]['lines'].append(final_msg)
                execution_logs[task_id]['status'] = 'success'
            current_app.socketio.emit('message', {'task_id': task_id, 'line': final_msg, 'status': 'success'}, room=sid, namespace='/')
            end_script_run(run_id, success=True, message=final_msg, pool=pool)
    except Exception as e:
        err = str(e)
        logger.error(f"patch_database_servers error: {err}")
        with app_obj.app_context():
            with log_lock:
                if task_id not in execution_logs:
                    execution_logs[task_id] = {'status': 'error', 'lines': [], 'start_time': time.time()}
                execution_logs[task_id]['lines'].append(f"Error: {err}")
                execution_logs[task_id]['status'] = 'error'
            current_app.socketio.emit('message', {'task_id': task_id, 'line': f"Error: {err}", 'status': 'error'}, room=sid, namespace='/')
        end_script_run(run_id, success=False, message=err, pool=pool)
        raise
    finally:
        if 'list_path' in locals() and os.path.exists(list_path):
            os.unlink(list_path)

def patch_storage_servers(task_id, nodes, version, app_obj, sid, pool):
    run_id = start_script_run('patch_storage_servers', pool=pool)
    try:
        with app_obj.app_context():
            logger.info(f"patch_storage_servers: version={version}")
            target_dir = '/home/maatest/mchafin/TEST_CONFIG_SCRIPTS/PATCHING'
            clean_version = version.strip()
            while clean_version.startswith(('patch_', 'patch-')):
                clean_version = clean_version[6:] if clean_version.startswith('patch_') else clean_version[5:]
                clean_version = clean_version.strip()
            logger.info(f"DEBUG: patch_storage_servers cleaned version '{version}' → '{clean_version}'")
            patch_dir = os.path.join(target_dir, f'patch_{clean_version}')
            if not os.path.exists(patch_dir):
                raise Exception(f"Patch directory {patch_dir} does not exist")
            # === SINGLE (EXACTLY ONE) EXASCALE PRE-PATCH - official Oracle script only ===
            def emit(msg, status='running'):
                current_app.socketio.emit('message', {'task_id': task_id, 'line': f'[PRE-PATCH] {msg}', 'status': status}, room=sid, namespace='/')
            emit("=== EXASCALE PRE-PATCH STEP: Running prepareEsOfflineUpgrade.sh (EXACTLY ONE ATTEMPT ONLY) ===")
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as list_file:
                for node in nodes:
                    list_file.write(node + '\n')
                pre_list = list_file.name
            try:
                emit(f"Target cell: {nodes[0]}")
                prep_cmd = ['/usr/bin/dcli', '-l', 'root', '-c', nodes[0], 'bash --login -c "$OSS_SCRIPTS_HOME/prepareEsOfflineUpgrade.sh 2>&1; echo \"EXIT_CODE=$?\""']
                prep_proc = subprocess.run(prep_cmd, capture_output=True, text=True, timeout=180)
                full_output = prep_proc.stdout + prep_proc.stderr
                emit(f"prepareEsOfflineUpgrade.sh output (single attempt only):\n{full_output.strip()}")
                if prep_proc.returncode != 0:
                    emit(f"WARNING: prepareEsOfflineUpgrade.sh exited with code {prep_proc.returncode} - proceeding anyway", status='warning')
                if "Not an Exascale cell." in full_output:
                    emit("Non-Exascale cell detected - no shutdown needed", status='success')
                else:
                    emit("Waiting 60 seconds for Exascale cluster to fully quiesce (Griddisk/ERS services drain)...", status='running')
                    time.sleep(60)
                    emit("Exascale cluster shutdown completed (single attempt only) - proceeding with patchmgr", status='success')
            finally:
                if os.path.exists(pre_list):
                    os.unlink(pre_list)
            # === PATCHMGR EXECUTION ===
            patchmgr_path = os.path.join(patch_dir, 'patchmgr')
            if os.path.exists(patchmgr_path):
                os.chmod(patchmgr_path, 0o755)
            else:
                raise Exception(f"patchmgr not found in {patch_dir}")
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as list_file:
                for node in nodes:
                    list_file.write(node + '\n')
                list_path = list_file.name
            log_dir = os.path.join(target_dir, f'logs_storage_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}')
            os.makedirs(log_dir, exist_ok=True)
            patchmgr_args = f'--cells "{list_path}" -patch -retain_hidden_param --ignore_alerts --ignore_date_validations --log_dir "{log_dir}"'
            logger.info("Starting proven bash ssh-agent wrapper for patch_storage")
            shell_cmd = f'''
set -e
eval "$(ssh-agent -s)" > /dev/null 2>&1
ssh-add {MAA_SSH_KEY} > /dev/null 2>&1 || {{ echo "FATAL: ssh-add FAILED for key {MAA_SSH_KEY}"; exit 1; }}
echo "=== SSH AGENT + MAA KEY LOADED SUCCESSFULLY (setup_patching v1.5.0) ==="
cd "{patch_dir}"
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
                with log_lock:
                    execution_logs[task_id]['lines'].append(line)
                current_app.socketio.emit('message', {'task_id': task_id, 'line': line, 'status': 'running'}, room=sid, namespace='/')
            process.wait()
            if process.returncode != 0:
                output_str = ''.join(execution_logs.get(task_id, {}).get('lines', []))
                if "Cleanup is required before retrying" in output_str:
                    emit("Patchmgr failed - running automatic cleanup...", status='running')
                    # FIXED: run cleanup LOCALLY on management server (not dcli to cells)
                    cleanup_cmd = f'cd "{patch_dir}" && ./patchmgr --cells "{list_path}" -cleanup'
                    cleanup_proc = subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True, timeout=300)
                    emit(f"Cleanup output:\n{cleanup_proc.stdout.strip()}", status='running')
                raise Exception(f"patchmgr failed with exit code {process.returncode}")
            final_msg = "Patching completed successfully"
            with log_lock:
                execution_logs[task_id]['lines'].append(final_msg)
                execution_logs[task_id]['status'] = 'success'
            current_app.socketio.emit('message', {'task_id': task_id, 'line': final_msg, 'status': 'success'}, room=sid, namespace='/')
            end_script_run(run_id, success=True, message=final_msg, pool=pool)
    except Exception as e:
        err = str(e)
        logger.error(f"patch_storage_servers error: {err}")
        with app_obj.app_context():
            with log_lock:
                if task_id not in execution_logs:
                    execution_logs[task_id] = {'status': 'error', 'lines': [], 'start_time': time.time()}
                execution_logs[task_id]['lines'].append(f"Error: {err}")
                execution_logs[task_id]['status'] = 'error'
            current_app.socketio.emit('message', {'task_id': task_id, 'line': f"Error: {err}", 'status': 'error'}, room=sid, namespace='/')
        end_script_run(run_id, success=False, message=err, pool=pool)
        raise
    finally:
        if 'list_path' in locals() and os.path.exists(list_path):
            os.unlink(list_path)
