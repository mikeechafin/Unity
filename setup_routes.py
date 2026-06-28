# Filename: setup_routes.py
# Version: 2026-05-20 v2.6.2
# Changes:
#   - /setup/api/series command changed to "ade showseries -prod OSS -plat linux" (no shell grep) to prevent rc=1 when no lines match
#   - ade_kerberos_helper.py v1.9 now uses BROADEST password search for mchafin (all rows in ACCESS_CREDENTIALS)
#   - All previous fixes preserved (forced remote SSH, strict Kerberos, etc.)

from flask import Blueprint, redirect, render_template, url_for, flash, request, session, current_app, jsonify
from flask_login import login_required, current_user
import threading
import time
from collections import defaultdict
from flask_socketio import emit
from functools import partial
from maa_libraries import logger, derive_rack_name, get_db_pool_connection, release_db_connection
from setup_scl_loader import get_functions_for_type, get_component_type
from setup_cache import get_storage_versions, get_db_patch_zips, get_guest_patch_zips
from setup_db_tracking import start_script_run, end_script_run
from setup_execution import execute_function, run_script_background, run_custom_command_background
from setup_patching import run_group_patch_background
from environment_setup_registry import load_registry
from shared_state import execution_logs, log_lock
import os
import uuid
import paramiko
import re
import json
from scripts.plugins.setup_exascale_monitoring import setup_exascale_monitoring
import traceback

# NEW: Use the robust ADE helper (automatic Kerberos ticket renewal)
from ade_kerberos_helper import run_ade_command

# ====================== DEDUPLICATION FOR GLOBAL FUNCTIONS (per-request only) ======================
# We intentionally do NOT use a persistent module-level set here.
# A persistent set caused "copy_latest_patches" (and other pure global functions)
# to become permanently blocked after the first click until the worker process restarted.
# Per-request protection via launched_this_request is sufficient to guard against
# double-clicks / duplicate events from the same socket message.
# If we later need to prevent *concurrent* runs of the same global function,
# we should track running state in execution_logs instead.

# ====================== PERSISTENT SERIES CACHE ======================
SERIES_CACHE_FILE = "/tmp/maa_series_cache.json"
_series_cache = None
_series_cache_time = 0
_series_cache_lock = threading.Lock()

setup_bp = Blueprint('setup', __name__, url_prefix='/setup', template_folder='templates')

@setup_bp.route('/cdn-cgi/challenge-platform/scripts/jsd/main.js')
def cloudflare_challenge_dummy():
    return '', 204

@setup_bp.record_once
def register_socketio_handlers(state):
    socketio = state.app.socketio

    @socketio.on('run_functions')
    def handle_run_functions(data):
        try:
            logger.info("=== ULTRA_LOUD_MARKER_v2.6.1_LOADED - handle_run_functions STARTED ===")
            sid = request.sid
            components = data.get('components', [])
            functions_per_type = data.get('functions_per_type', {})
            raw_params = data.get('params', {})
            socketio.emit('message', {'task_id': 'debug', 'line': '=== v2.6.1 LOADED - Global-only allowed with empty components ===', 'status': 'running'}, room=sid)
            socketio.emit('message', {'task_id': 'debug', 'line': f"DEBUG [RAW functions_per_type received]: {json.dumps(functions_per_type, default=str)}", 'status': 'running'}, room=sid)
            logger.info(f"DEBUG [RAW functions_per_type received]: {functions_per_type}")

            known_global = {'discover_dbmachine', 'copy_latest_patches', 'setup_exascale_monitoring'}
            global_funcs = []
            if 'Global' in functions_per_type:
                global_funcs = functions_per_type.pop('Global', [])

            for k in list(functions_per_type.keys()):
                if k == 'Global':
                    continue
                funcs = functions_per_type[k]
                for f in list(funcs):
                    fname = f.get('name', '') if isinstance(f, dict) else f
                    if fname in known_global:
                        global_funcs.append(f)
                        funcs.remove(f)

            logger.info(f"GROUP LAUNCH: Global functions detected: {global_funcs}")

            for k in list(functions_per_type.keys()):
                if k == 'Global':
                    continue
                funcs = functions_per_type[k]
                functions_per_type[k] = [f for f in funcs if not (isinstance(f, dict) and f.get('name', '') in known_global or isinstance(f, str) and f in known_global)]
                if not functions_per_type[k]:
                    del functions_per_type[k]

            logger.info(f"FINAL CLEANUP v2.6.1: functions_per_type after cleanup = {functions_per_type}")

            if not components:
                if not global_funcs and functions_per_type:
                    socketio.emit('message', {'task_id': 'error', 'line': 'No components selected', 'status': 'error'}, room=sid)
                    return
                logger.info("Pure Global function(s) detected with empty components - proceeding")

            launched_this_request = set()
            for func in global_funcs:
                fname = func.get('name', '') if isinstance(func, dict) else func
                if fname == 'discover_dbmachine' and components:
                    seed = components[0]
                else:
                    seed = 'global'
                launch_key = (fname, seed)
                if launch_key in launched_this_request:
                    logger.info(f"DUPLICATE SKIP v2.6.1 (per-request): {fname} already launched in this request")
                    continue
                launched_this_request.add(launch_key)
                # NOTE: We no longer add to any persistent global set.
                # This allows legitimate re-runs of global functions like copy_latest_patches
                # on subsequent clicks. Per-request guard still protects against double events.
                task_id = f"global_{fname}_{uuid.uuid4().hex[:8]}"
                captured_params = dict(raw_params)
                socketio.emit('message', {'task_id': task_id, 'line': f'Starting Global function: {fname} (seed={seed})', 'status': 'running'}, room=sid)
                with log_lock:
                    execution_logs[task_id] = {'status': 'running', 'lines': [f'Starting Global function: {fname}'], 'start_time': time.time()}
                task = partial(run_script_background, task_id, seed, fname, captured_params, current_app._get_current_object(), sid, components=components)
                socketio.start_background_task(task)
                logger.info(f"Global function {fname} launched with seed={seed} and {len(components)} components (task_id={task_id})")

            storage_servers = [c for c in components if get_component_type(c) == 'Storage Server']
            if storage_servers and 'patch_storage' in functions_per_type.get('Storage_Server', []):
                version = raw_params.get('params_Storage_Server_patch_storage_patch_version')
                task_id = f"patch_storage_group_{uuid.uuid4().hex[:8]}"
                logger.info(f"GROUP LAUNCH: patch_storage for {len(storage_servers)} servers")
                socketio.emit('message', {'task_id': task_id, 'line': f"Starting GROUP patch_storage for {len(storage_servers)} servers", 'status': 'running'}, room=sid)
                with log_lock:
                    execution_logs[task_id] = {'status': 'running', 'lines': [f"GROUP patch_storage started..."], 'start_time': time.time()}
                thread = threading.Thread(target=run_group_patch_background, args=(task_id, storage_servers, 'patch_storage', None, version, current_app._get_current_object(), sid))
                thread.daemon = True
                thread.start()
                for ctype in functions_per_type:
                    if 'patch_storage' in functions_per_type[ctype]:
                        functions_per_type[ctype].remove('patch_storage')

            db_servers = [c for c in components if get_component_type(c) == 'Database Server']
            if db_servers and 'patch_database' in functions_per_type.get('Database_Server', []):
                zip_file = raw_params.get('params_Database_Server_patch_database_patch_zip')
                version_part = None
                if zip_file and isinstance(zip_file, str):
                    try:
                        if 'ol8_' in zip_file:
                            version_part = zip_file.split('ol8_')[1].split('_Linux-x86-64.zip')[0]
                        elif '_' in zip_file and zip_file.endswith('.zip'):
                            version_part = zip_file.rsplit('_', 1)[0].split('_')[-1]
                        else:
                            version_part = zip_file.replace('.zip', '')
                    except Exception:
                        version_part = zip_file.replace('.zip', '') if zip_file else None
                task_id = f"patch_database_group_{uuid.uuid4().hex[:8]}"
                logger.info(f"GROUP LAUNCH: patch_database for {len(db_servers)} servers")
                socketio.emit('message', {'task_id': task_id, 'line': f"Starting GROUP patch_database for {len(db_servers)} servers", 'status': 'running'}, room=sid)
                with log_lock:
                    execution_logs[task_id] = {'status': 'running', 'lines': [f"GROUP patch_database started..."], 'start_time': time.time()}
                thread = threading.Thread(target=run_group_patch_background, args=(task_id, db_servers, 'patch_database', None, (zip_file, version_part), current_app._get_current_object(), sid))
                thread.daemon = True
                thread.start()
                for ctype in functions_per_type:
                    if 'patch_database' in functions_per_type[ctype]:
                        functions_per_type[ctype].remove('patch_database')

            guest_servers = [c for c in components if get_component_type(c) == 'Guest']
            if guest_servers and 'patch_guest' in functions_per_type.get('Guest', []):
                zip_file = raw_params.get('params_Guest_patch_guest_patch_zip')
                version_part = None
                if zip_file and isinstance(zip_file, str):
                    try:
                        if 'ol8_' in zip_file:
                            version_part = zip_file.split('ol8_')[1].split('_Linux-x86-64.zip')[0]
                        elif 'ovs_' in zip_file:
                            version_part = zip_file.split('ovs_')[1].split('_Linux-x86-64.zip')[0]
                        elif '_' in zip_file and zip_file.endswith('.zip'):
                            version_part = zip_file.rsplit('_', 1)[0].split('_')[-1]
                        else:
                            version_part = zip_file.replace('.zip', '')
                    except Exception:
                        version_part = zip_file.replace('.zip', '') if zip_file else None
                task_id = f"patch_guest_group_{uuid.uuid4().hex[:8]}"
                logger.info(f"GROUP LAUNCH: patch_guest for {len(guest_servers)} guests")
                socketio.emit('message', {'task_id': task_id, 'line': f"Starting GROUP patch_guest for {len(guest_servers)} guests", 'status': 'running'}, room=sid)
                with log_lock:
                    execution_logs[task_id] = {'status': 'running', 'lines': [f"GROUP patch_guest started..."], 'start_time': time.time()}
                thread = threading.Thread(target=run_group_patch_background, args=(task_id, guest_servers, 'patch_guest', None, (zip_file, version_part), current_app._get_current_object(), sid))
                thread.daemon = True
                thread.start()
                for ctype in functions_per_type:
                    if 'patch_guest' in functions_per_type[ctype]:
                        functions_per_type[ctype].remove('patch_guest')

            for comp in components:
                ctype = get_component_type(comp)
                type_key = ctype.replace(' ', '_')
                for func in functions_per_type.get(type_key, []):
                    fname = func.get('name', '') if isinstance(func, dict) else func
                    if fname in known_global:
                        logger.info(f"UNBREAKABLE SKIP v2.6.1: {fname} skipped for {type_key}")
                        continue
                    task_id = f"{comp}_{fname}_{uuid.uuid4().hex[:8]}"
                    captured_params = dict(raw_params)
                    task = partial(run_script_background, task_id, comp, fname, captured_params, current_app._get_current_object(), sid)
                    socketio.start_background_task(task)
                    logger.info(f"Individual task QUEUED: {task_id}")

        except Exception as e:
            error_msg = f"CRITICAL HANDLER ERROR: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg, exc_info=True)
            socketio.emit('message', {'task_id': 'error', 'line': error_msg, 'status': 'error'}, room=sid)

    @socketio.on('run_custom_command')
    def handle_run_custom_command(data):
        sid = request.sid
        task_id = data.get('task_id', f"custom_cmd_{uuid.uuid4().hex[:8]}")
        ctype = data.get('ctype')
        cmd = data.get('cmd')
        components = data.get('components', [])
        if not cmd or not components:
            socketio.emit('message', {'task_id': task_id, 'line': 'ERROR: Missing command or hosts', 'status': 'error'}, room=sid)
            return
        socketio.emit('message', {'task_id': task_id, 'line': f'Starting custom command on {len(components)} {ctype} hosts', 'status': 'running'}, room=sid)
        with log_lock:
            if task_id not in execution_logs:
                execution_logs[task_id] = {'status': 'running', 'lines': [], 'start_time': time.time()}
        thread = threading.Thread(target=run_custom_command_background, args=(task_id, components, cmd, current_app._get_current_object(), sid))
        thread.daemon = True
        thread.start()

    @socketio.on('setup_exascale_monitoring')
    def handle_setup_exascale_monitoring(data):
        sid = request.sid
        task_id = data.get('task_id')
        components = data.get('components', [])
        params = data.get('params', {})
        if not task_id or not components:
            socketio.emit('message', {'task_id': task_id or 'error', 'line': 'ERROR: Missing task_id or components', 'status': 'error'}, room=sid)
            return
        socketio.emit('message', {'task_id': task_id, 'line': '[Exascale] Starting monitoring setup...', 'status': 'running'}, room=sid)
        with log_lock:
            if task_id not in execution_logs:
                execution_logs[task_id] = {'status': 'running', 'lines': ['[Exascale] Starting monitoring setup...'], 'start_time': time.time()}
        thread = threading.Thread(target=setup_exascale_monitoring, args=(task_id, components, params, current_app._get_current_object(), sid))
        thread.daemon = True
        thread.start()

@setup_bp.route('/environment', methods=['GET', 'POST'])
@login_required
def setup_environment():
    load_registry()
    storage_versions = get_storage_versions()
    db_patch_zips = get_db_patch_zips()
    guest_patch_zips = get_guest_patch_zips()
    conn = get_db_pool_connection(current_app.config.get('DB_POOL'))
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT system_name FROM maamd.system_allocations WHERE system_name IS NOT NULL
            UNION ALL SELECT ilom_name FROM maamd.system_allocations WHERE ilom_name IS NOT NULL
            UNION ALL SELECT hostname FROM maamd.agent_hosts
            UNION ALL SELECT hostname FROM maamd.guests WHERE hostname IS NOT NULL
            UNION ALL SELECT hostname FROM maamd.switch_info
        """)
        all_hosts = list(dict.fromkeys(row[0] for row in cursor.fetchall() if row[0]))
        all_hosts.append('global')
        racks = sorted({derive_rack_name(h) for h in all_hosts if derive_rack_name(h)})
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config.get('DB_POOL'))
    selected_rack = request.form.get('rack') or request.args.get('rack', '')
    filter_text = request.form.get('filter') or request.args.get('filter', '')
    components = defaultdict(list)
    component_types = ['Database Server', 'Storage Server', 'Guest', 'ILOM Components', 'Switch']
    for ctype in component_types:
        if ctype == 'ILOM Components':
            type_hosts = [h for h in all_hosts if h.lower().endswith(('-ilom.us.oracle.com', '-c.us.oracle.com')) or 'ilom' in h.lower()]
        else:
            type_hosts = [h for h in all_hosts if get_component_type(h) == ctype]
        if selected_rack:
            type_hosts = [h for h in type_hosts if derive_rack_name(h) == selected_rack]
        if filter_text:
            type_hosts = [h for h in type_hosts if filter_text.lower() in h.lower() or filter_text.lower() in derive_rack_name(h).lower()]
        for h in type_hosts:
            components[ctype].append((h, derive_rack_name(h)))
    functions_by_type = {ctype: get_functions_for_type(ctype) for ctype in components}
    functions_by_type['Global'] = get_functions_for_type('Global')
    GLOBAL_ONLY = {'discover_dbmachine', 'copy_latest_patches', 'setup_exascale_monitoring'}
    for ctype in list(functions_by_type.keys()):
        if ctype != 'Global':
            original_list = functions_by_type.get(ctype, [])
            filtered = []
            for f in original_list:
                if isinstance(f, dict):
                    fname = f.get('name', '')
                else:
                    fname = f
                if fname not in GLOBAL_ONLY:
                    filtered.append(f)
            functions_by_type[ctype] = filtered
    if 'Global' in functions_by_type:
        global_funcs = functions_by_type['Global']
        has_discover = any((isinstance(f, dict) and f.get('name') == 'discover_dbmachine') or (isinstance(f, str) and f == 'discover_dbmachine') for f in global_funcs)
        if not has_discover:
            logger.warning("SAFETY NET v2.6.1: discover_dbmachine was missing from Global - forcing it back in")
            functions_by_type['Global'].append({'name': 'discover_dbmachine', 'display_name': 'Discover DBMachine', 'description': 'Discovers the complete virtual rack (compute + storage + guests) via RoCE neighbors and switch MAC table mapping'})
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'upload_script':
            if current_user.role != 'admin':
                flash("Admin only", "error")
                return redirect(url_for('setup.setup_environment'))
            file = request.files.get('script_file')
            target_type = request.form.get('target_type')
            description = request.form.get('description', '').strip()
            if not file or not target_type:
                flash("Missing file or target type", "error")
                return redirect(url_for('setup.setup_environment'))
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ['.scl', '.ilom', '.sh', '.py']:
                flash("Invalid file type", "error")
                return redirect(url_for('setup.setup_environment'))
            folder_map = {
                '.scl': os.path.join("/home/maatest/mchafin/MAA_APPS_NEW/scripts/scl", target_type),
                '.ilom': "/home/maatest/mchafin/MAA_APPS_NEW/scripts/ilom",
                '.sh': os.path.join("/home/maatest/mchafin/MAA_APPS_NEW/scripts/shell", target_type),
                '.py': "/home/maatest/mchafin/MAA_APPS_NEW/scripts/plugins"
            }
            folder = folder_map.get(ext)
            if not folder:
                flash("Invalid target type", "error")
                return redirect(url_for('setup.setup_environment'))
            os.makedirs(folder, exist_ok=True)
            safe_name = file.filename.replace('..', '').replace('/', '')
            path = os.path.join(folder, safe_name)
            file.save(path)
            flash(f"Uploaded {safe_name} to {target_type} – refresh to see it", "success")
            return redirect(url_for('setup.setup_environment'))
    return render_template(
        'setup_environment.html',
        racks=racks,
        selected_rack=selected_rack,
        components=components,
        component_types=component_types,
        filter_text=filter_text,
        functions_by_type=functions_by_type,
        show_logs=session.get('show_logs', False),
        storage_versions=storage_versions,
        db_patch_zips=db_patch_zips,
        guest_patch_zips=guest_patch_zips
    )

@setup_bp.route('/api/series', methods=['GET'])
def get_series_api():
    global _series_cache, _series_cache_time
    now = time.time()
    logger.info("[SERIES DEBUG] /api/series endpoint called")

    if os.path.exists(SERIES_CACHE_FILE):
        try:
            with open(SERIES_CACHE_FILE, 'r') as f:
                data = json.load(f)
                if (now - data.get('timestamp', 0)) < 86400:
                    _series_cache = data['series']
                    _series_cache_time = data['timestamp']
                    logger.info(f"[SERIES DEBUG] Serving {len(_series_cache)} series from disk cache")
                    return jsonify({'series': _series_cache, 'cached': True, 'source': 'file'})
        except Exception as e:
            logger.warning(f"[SERIES DEBUG] Failed to read cache file: {e}")

    with _series_cache_lock:
        if _series_cache is not None and (now - _series_cache_time) < 86400:
            logger.info(f"[SERIES DEBUG] Serving {len(_series_cache)} series from memory cache")
            return jsonify({'series': _series_cache, 'cached': True, 'source': 'memory'})

        logger.info("[SERIES DEBUG] Cache miss - calling run_ade_command now")
        try:
            cmd = "ade showseries -prod OSS -plat linux"
            logger.info(f"[SERIES DEBUG] Running command: {cmd} (filtering done in Python to avoid grep rc=1)")
            stdout, stderr, rc = run_ade_command(cmd, pool=current_app.config.get('DB_POOL'))
            logger.info(f"[SERIES DEBUG] run_ade_command returned rc={rc}")
            logger.info(f"[SERIES DEBUG] stdout (first 500 chars): {stdout[:500] if stdout else 'EMPTY'}")
            logger.info(f"[SERIES DEBUG] stderr (first 500 chars): {stderr[:500] if stderr else 'EMPTY'}")

            if rc != 0:
                logger.error(f"[SERIES DEBUG] ADE command failed with rc={rc}")
                return jsonify({'series': [], 'cached': False, 'error': f"ADE failed: {stderr or stdout or 'no output'}", 'debug_rc': rc})

            series_raw = [line.strip() for line in stdout.splitlines() if line.strip()]
            logger.info(f"[SERIES DEBUG] Parsed {len(series_raw)} raw series lines")

            filtered = [s for s in series_raw if not any(word.lower() in s.lower() for word in ['OEDA', 'BDSQL', 'AMP'])]
            logger.info(f"[SERIES DEBUG] After filtering: {len(filtered)} series")

            def version_key(s):
                parts = re.split(r'(\d+)', s)
                return [int(p) if p.isdigit() else p for p in parts]
            filtered.sort(key=version_key, reverse=True)

            _series_cache = filtered
            _series_cache_time = now

            try:
                with open(SERIES_CACHE_FILE, 'w') as f:
                    json.dump({'series': filtered, 'timestamp': now}, f)
            except Exception as e:
                logger.warning(f"[SERIES DEBUG] Failed to write cache: {e}")

            logger.info(f"[SERIES DEBUG] SUCCESS - returning {len(filtered)} series")
            return jsonify({'series': filtered, 'cached': False, 'source': 'ade', 'debug': 'success'})

        except Exception as e:
            logger.error(f"[SERIES DEBUG] EXCEPTION in endpoint: {str(e)}", exc_info=True)
            return jsonify({'series': [], 'cached': False, 'error': str(e), 'debug': 'exception'})

@setup_bp.route('/api/labels', methods=['GET'])
def get_labels_api():
    series = request.args.get('series')
    if not series:
        return jsonify({'error': 'Series required'}), 400
    try:
        cmd = f"ade showlabels -series {series}"
        stdout, stderr, rc = run_ade_command(cmd, pool=current_app.config.get('DB_POOL'))
        if rc != 0:
            raise Exception(f"ADE command failed: {stderr or stdout}")
        labels = [line.strip() for line in stdout.splitlines() if line.strip()]
        labels.sort(reverse=True)
        return jsonify({'labels': labels})
    except Exception as e:
        logger.error(f"Failed to get labels for {series}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@setup_bp.route('/api/run_status')
@login_required
def run_status_api():
    with log_lock:
        cutoff = time.time() - 1800
        for tid in list(execution_logs.keys()):
            if execution_logs[tid].get('start_time', 0) < cutoff:
                del execution_logs[tid]
        return jsonify(dict(execution_logs))

@setup_bp.route('/check_session')
@login_required
def check_session():
    return jsonify({'ok': True})

if __name__ == '__main__':
    logger.info("=== setup_routes.py v2.6.1 LOADED ===")
