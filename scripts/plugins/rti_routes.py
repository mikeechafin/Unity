#!/usr/bin/env python3
"""
MAA Unified - Real-Time Insight (RTI) Routes v2.25
- Added aggressive no-cache headers to /rti/stream route
  to force fresh content and eliminate stubborn 997-line cached syntax error
"""
from flask import Blueprint, render_template, request, flash, current_app, redirect, url_for, jsonify, send_from_directory, make_response
from flask_login import login_required, current_user
from flask_socketio import emit, join_room, leave_room
import threading
import json
import os
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from maa_libraries import logger, get_credential_silent
from maa_db_pool import get_db_pool_connection, release_db_pool_connection
import paramiko
import io
import tempfile

BASE_DIR = "/home/maatest/mchafin/MAA_APPS_NEW/output/RTI"
RTI_PERSIST_TO_DB = True
RTI_CONFIG_FILE = os.path.join(BASE_DIR, "rti_config.json")
RTI_CAPTURE_DIR = os.path.join(BASE_DIR, "rti_captures")
os.makedirs(RTI_CAPTURE_DIR, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)

rti_bp = Blueprint('rti', __name__, url_prefix='/rti', template_folder='templates')

RTI_BUFFER = defaultdict(lambda: deque(maxlen=300))
RTI_LOCK = threading.Lock()
RTI_CAPTURE_ACTIVE = False
RTI_CAPTURE_FILE = None
RTI_CAPTURE_LOCK = threading.Lock()

def robust_ssh_connect_rti(hostname, username='root', timeout=20):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, key_filename="/home/maatest/.ssh/id_rsa", timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
        return ssh, "keyfile"
    except:
        pass
    password = None
    try:
        conn = get_db_pool_connection()
        cursor = conn.cursor()
        password = get_credential_silent(cursor, 'default', hostname, username) or get_credential_silent(cursor, 'default', 'default', username)
        cursor.close()
        release_db_pool_connection(conn)
    except:
        pass
    if password:
        try:
            ssh.connect(hostname, username=username, password=password, timeout=timeout, disabled_algorithms={'pubkeys': ['ssh-dss']})
            return ssh, "password"
        except Exception as e:
            logger.error(f"RTI SSH password fail {hostname}: {e}")
            raise Exception(f"RTI SSH failed for {hostname}")
    raise Exception(f"RTI SSH failed for {hostname}")

def run_cellcli_or_dcli(host, cmd, is_storage=True):
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.scl', delete=False) as f:
            f.write(cmd + '\n')
            scl_file = f.name
        os.chmod(scl_file, 0o755)

        try:
            if is_storage:
                full_cmd = f"dcli -l root -c {host} -x {scl_file} 2>&1"
            else:
                full_cmd = f"dcli_compute -l root -c {host} -x {scl_file} 2>&1"

            ssh, _ = robust_ssh_connect_rti('localhost', 'maatest')
            stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=90)
            out = stdout.read().decode('utf-8', errors='ignore').strip()
            err = stderr.read().decode('utf-8', errors='ignore').strip() if stderr else ""
            ssh.close()
            os.unlink(scl_file)

            if 'successfully altered' in out.lower():
                return out, err, 0
            elif 'error' in out.lower() or 'failed' in out.lower() or out.startswith('Error') or out.startswith('CELL-'):
                return out, err or out, 1
            elif out.strip() == '' or 'Cell' in out:
                return out, err, 0
            else:
                return out, err, 1
        except Exception as e:
            if os.path.exists(scl_file):
                os.unlink(scl_file)
            raise e
    except Exception as e:
        logger.error(f"dcli -x failed on {host}: {e}")
        return "", str(e), 1

def get_rti_servers():
    servers = []
    try:
        conn = get_db_pool_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT UPPER(SYSTEM_NAME) as HOSTNAME
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE UPPER(SYSTEM_NAME) LIKE '%CEL%' OR UPPER(SYSTEM_NAME) LIKE '%DB%'
            OR UPPER(SYSTEM_NAME) LIKE '%ADM%' OR UPPER(SYSTEM_NAME) LIKE '%SW%'
            ORDER BY HOSTNAME
        """)
        for row in cursor.fetchall():
            host = row[0]
            typ = 'STORAGE' if 'CEL' in host else 'COMPUTE' if 'DB' in host or 'ADM' in host else 'SWITCH' if 'SW' in host else 'OTHER'
            servers.append({'hostname': host, 'type': typ})
        cursor.close()
        release_db_pool_connection(conn)
    except Exception as e:
        logger.warning(f"RTI server discovery failed: {e}")
        if not servers:
            servers = [
                {'hostname': 'scaqaa04celadm12.us.oracle.com', 'type': 'STORAGE'},
                {'hostname': 'scaqaa04celadm13.us.oracle.com', 'type': 'STORAGE'},
                {'hostname': 'scaqaa04dbadm01.us.oracle.com', 'type': 'COMPUTE'},
            ]
    return servers

def _lob_to_str(lob_value):
    if lob_value is None:
        return None
    if hasattr(lob_value, 'read'):
        lob_value = lob_value.read()
    return str(lob_value) if lob_value else None

def load_rti_config(hostname_filter=None):
    cfg = {"servers": {}, "last_updated": None}
    try:
        conn = get_db_pool_connection()
        cursor = conn.cursor()

        if hostname_filter:
            cursor.execute("""
                SELECT HOSTNAME, TYPE, FG_COLL_INTVL_SEC, STREAM_INTVL_SEC, TAGS, LAST_UPDATED, ENDPOINT
                FROM MAAMD.RTI_SERVER_CONFIG
                WHERE HOSTNAME = :1
            """, [hostname_filter])
        else:
            cursor.execute("SELECT HOSTNAME, TYPE, FG_COLL_INTVL_SEC, STREAM_INTVL_SEC, TAGS, LAST_UPDATED, ENDPOINT FROM MAAMD.RTI_SERVER_CONFIG")

        for row in cursor.fetchall():
            host, typ, fg, si, tags, lu, endpoint = row
            tags_str = _lob_to_str(tags) or '{"fleet":"MAA_Lab"}'
            cfg["servers"][host] = {
                "type": typ or "STORAGE",
                "freq": {
                    "fg_int": str(fg) if fg is not None else "",
                    "stream_int": str(si) if si is not None else "",
                    "tags": tags_str
                },
                "endpoint": endpoint or "",
                "metrics": {}
            }

        if hostname_filter:
            cursor.execute("""
                SELECT HOSTNAME, METRIC_NAME, FINEGRAINED, STREAMING
                FROM MAAMD.RTI_METRIC_SETTINGS
                WHERE HOSTNAME = :1
            """, [hostname_filter])
        else:
            cursor.execute("SELECT HOSTNAME, METRIC_NAME, FINEGRAINED, STREAMING FROM MAAMD.RTI_METRIC_SETTINGS")

        for row in cursor.fetchall():
            host, metric_name, fine, stream = row
            if host in cfg["servers"]:
                cfg["servers"][host]["metrics"][metric_name] = {
                    "finegrained": fine == 'enabled',
                    "streaming": stream == 'enabled'
                }

        cursor.close()
        release_db_pool_connection(conn)
        cfg["last_updated"] = datetime.now(timezone.utc).isoformat()
        return cfg
    except Exception as e:
        logger.warning(f"RTI config load from DB failed: {e}")
        if os.path.exists(RTI_CONFIG_FILE):
            try:
                with open(RTI_CONFIG_FILE) as f:
                    return json.load(f)
            except:
                pass
        return cfg

def save_rti_config(cfg, updated_by="system"):
    try:
        conn = get_db_pool_connection()
        cursor = conn.cursor()

        for host, data in cfg.get("servers", {}).items():
            freq = data.get("freq", {})
            enabled = data.get("metrics", {})
            endpoint = data.get("endpoint", "")

            cursor.execute("""
                MERGE INTO MAAMD.RTI_SERVER_CONFIG t
                USING (SELECT :hostname AS HOSTNAME FROM DUAL) s
                ON (t.HOSTNAME = s.HOSTNAME)
                WHEN MATCHED THEN UPDATE SET
                    TYPE = :type,
                    FG_COLL_INTVL_SEC = :fg_int,
                    STREAM_INTVL_SEC = :stream_int,
                    TAGS = :tags,
                    ENDPOINT = :endpoint,
                    LAST_UPDATED = CURRENT_TIMESTAMP,
                    UPDATED_BY = :updated_by
                WHEN NOT MATCHED THEN INSERT
                    (HOSTNAME, TYPE, FG_COLL_INTVL_SEC, STREAM_INTVL_SEC, TAGS, ENDPOINT, UPDATED_BY)
                    VALUES (:hostname, :type, :fg_int, :stream_int, :tags, :endpoint, :updated_by)
            """, {
                'hostname': host,
                'type': data.get("type", "STORAGE"),
                'fg_int': int(freq.get("fg_int", 5)) if freq.get("fg_int") else 5,
                'stream_int': int(freq.get("stream_int", 60)) if freq.get("stream_int") else 60,
                'tags': freq.get("tags", '{"fleet":"MAA_Lab"}'),
                'endpoint': endpoint,
                'updated_by': updated_by
            })

            # Only delete/replace metrics if explicitly provided (non-empty)
            # Empty enabled dict means "preserve existing metrics" (from Sync button)
            if enabled:
                cursor.execute("DELETE FROM MAAMD.RTI_METRIC_SETTINGS WHERE HOSTNAME = :hostname", {'hostname': host})

                for metric_name, settings in enabled.items():
                    cursor.execute("""
                        INSERT INTO MAAMD.RTI_METRIC_SETTINGS
                        (HOSTNAME, METRIC_NAME, FINEGRAINED, STREAMING, LAST_UPDATED)
                        VALUES (:hostname, :metric, :fine, :stream, CURRENT_TIMESTAMP)
                    """, {
                        'hostname': host,
                        'metric': metric_name,
                        'fine': 'enabled' if settings.get('finegrained') else 'disabled',
                        'stream': 'enabled' if settings.get('streaming') else 'disabled'
                    })

        conn.commit()
        cursor.close()
        release_db_pool_connection(conn)
        return True
    except Exception as e:
        logger.error(f"RTI config save failed: {e}")
        return False

def push_db_to_cell_smart(host, db_metrics, global_settings):
    is_storage = any(x in host.lower() for x in ['cel', 'cell'])
    log_lines = []
    try:
        endpoint = global_settings.get('endpoint', '')
        fg = int(global_settings.get('fg_int', 5))
        si = int(global_settings.get('stream_int', 60))
        tags = global_settings.get('tags', '{"fleet":"MAA_Lab"}')

        ratio = si / fg if fg > 0 else 0
        if ratio < 5 or ratio > 30:
            si = max(fg * 5, 25)
            log_lines.append(f"[0/4] Auto-adjusted stream_int to {si}s (valid ratio)")

        log_lines.append(f"[0/4] Applying all settings to {host}...")
        if endpoint and endpoint.strip():
            endpoint_value = f'((host="{endpoint}",type="json"))'
            global_cmd = f"alter cell metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamTags='{tags}', metricStreamEndPoint={endpoint_value}" if is_storage else \
                         f"alter dbserver metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamEndPoint={endpoint_value}"
            endpoint_msg = "Endpoint set"
        else:
            # Explicitly CLEAR the endpoint to stop streaming
            global_cmd = f"alter cell metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamTags='{tags}', metricStreamEndPoint=''" if is_storage else \
                         f"alter dbserver metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamTags='{tags}', metricStreamEndPoint=''"
            endpoint_msg = "Endpoint CLEARED (streaming stopped)"
        
        out, err, rc = run_cellcli_or_dcli(host, global_cmd, is_storage)
        if rc == 0:
            log_lines.append(f"[0/4] ✓ All settings applied (FG={fg}s, Stream={si}s, {endpoint_msg})")
        else:
            log_lines.append(f"[0/4] ✗ Failed to apply settings: {err or out[:200]}")
            return False, log_lines  # ALTER CELL failed - don't save to DB

        log_lines.append(f"[1/4] Fetching current config from {host}...")
        cmd = "list metricdefinition attributes name,finegrained,streaming"
        out, err, rc = run_cellcli_or_dcli(host, cmd, is_storage)
        if rc != 0 or 'Permission' in out or 'disconnect' in out.lower():
            log_lines.append(f"[1/4] ⚠ Could not fetch current config (will still save to DB): {err or out[:100]}")
            # Don't return False here - ALTER succeeded, we still want to save to DB

        current_cell = {}
        for line in out.splitlines():
            line = line.strip()
            if not line or 'Permission' in line or 'disconnect' in out.lower() or 'denied' in out.lower():
                continue
            if ':' in line:
                line = line.split(':', 1)[1].strip()
            parts = line.split()
            if len(parts) >= 3:
                name = parts[0]
                current_cell[name] = {
                    'finegrained': parts[1].lower() == 'enabled',
                    'streaming': parts[2].lower() == 'enabled'
                }
        log_lines.append(f"[1/4] ✓ Fetched {len(current_cell)} metrics from cell")

        log_lines.append(f"[2/4] Comparing DB config vs cell config...")
        to_update = []
        for metric_name, db_settings in db_metrics.items():
            cell_settings = current_cell.get(metric_name, {'finegrained': True, 'streaming': True})
            db_fine = db_settings.get('finegrained', True)
            db_stream = db_settings.get('streaming', True)
            cell_fine = cell_settings.get('finegrained', True)
            cell_stream = cell_settings.get('streaming', True)
            if db_fine != cell_fine or db_stream != cell_stream:
                to_update.append({
                    'name': metric_name,
                    'old_fine': cell_fine,
                    'new_fine': db_fine,
                    'old_stream': cell_stream,
                    'new_stream': db_stream
                })
        log_lines.append(f"[2/4] ✓ Found {len(to_update)} metrics that need updating")

        if len(to_update) == 0:
            log_lines.append(f"[3/4] ✓ No changes needed - cell already matches DB config")
            log_lines.append(f"[4/4] ✓ Sync complete")
            return True, log_lines

        log_lines.append(f"[3/4] Applying global settings...")
        if endpoint and endpoint.strip():
            endpoint_value = f'((host="{endpoint}",type="json"))'
            global_cmd = f"alter cell metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamTags='{tags}', metricStreamEndPoint={endpoint_value}" if is_storage else \
                         f"alter dbserver metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamEndPoint={endpoint_value}"
        else:
            # Clear endpoint to stop streaming
            global_cmd = f"alter cell metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamTags='{tags}', metricStreamEndPoint=''" if is_storage else \
                         f"alter dbserver metricFGCollIntvlInSec={fg}, metricStreamIntvlInSec={si}, metricStreamTags='{tags}', metricStreamEndPoint=''"
        run_cellcli_or_dcli(host, global_cmd, is_storage)
        log_lines.append(f"[3/4] ✓ Global settings applied")

        log_lines.append(f"[4/4] Pushing {len(to_update)} metric changes...")
        updated_count = 0
        for item in to_update:
            metric_name = item['name']
            fine = 'enabled' if item['new_fine'] else 'disabled'
            stream = 'enabled' if item['new_stream'] else 'disabled'

            cmd = f"alter metricdefinition {metric_name} finegrained={fine}, streaming={stream}"
            out, err, rc = run_cellcli_or_dcli(host, cmd, is_storage)

            if rc == 0:
                updated_count += 1
                if updated_count <= 5:
                    log_lines.append(f" • {metric_name}: finegrained={fine}, streaming={stream}")
            else:
                log_lines.append(f" ✗ Failed: {metric_name}")

        log_lines.append(f"[4/4] ✓ Successfully updated {updated_count} metrics on {host}")
        return True, log_lines
    except Exception as e:
        log_lines.append(f"✗ Error during smart sync: {str(e)}")
        return False, log_lines

@rti_bp.route('/', methods=['GET'])
@login_required
def rti_dashboard():
    cfg = load_rti_config()
    servers = get_rti_servers()
    for s in servers:
        s['config'] = cfg.get('servers', {}).get(s['hostname'], {})
    with RTI_LOCK:
        active = len([k for k in RTI_BUFFER if RTI_BUFFER[k]])
    return render_template('rti/dashboard.html',
                           servers=servers, active_streams=active,
                           capture_active=RTI_CAPTURE_ACTIVE, persist_db=RTI_PERSIST_TO_DB)

@rti_bp.route('/setup', methods=['GET', 'POST'])
@login_required
def rti_setup():
    servers = get_rti_servers()
    selected = request.form.getlist('selected_servers') if request.method == 'POST' else []
    cfg = load_rti_config()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'apply_config':
            new_cfg = {"servers": {}}
            metric_settings_raw = request.form.get('metric_settings')
            # Only parse if explicitly provided - preserves existing metrics when syncing FG/Stream/Endpoint/Tags
            if metric_settings_raw:
                try:
                    metric_settings = json.loads(metric_settings_raw)
                except:
                    metric_settings = {}
            else:
                metric_settings = None  # Signal: don't touch metrics

            fg = request.form.get('fg_int', '5')
            si = request.form.get('stream_int', '60')
            tags = request.form.get('tags', '{"fleet":"MAA_Lab"}')
            endpoint = request.form.get('endpoint', '')
            is_sync_from_cell = request.form.get('sync_from_cell') == 'true'

            for host in selected:
                is_storage = any(x in host.lower() for x in ['cel', 'cell'])
                host_metrics = metric_settings.get(host, {}) if metric_settings else {}
                print(f"RTI DEBUG: sync_from_cell={is_sync_from_cell}, host={host}, metrics_count={len(host_metrics)}, has_metric_settings={metric_settings is not None}")

                if not is_sync_from_cell:
                    global_settings = {'fg_int': fg, 'stream_int': si, 'tags': tags, 'endpoint': endpoint}
                    success, log_lines = push_db_to_cell_smart(host, host_metrics, global_settings)

                    for line in log_lines:
                        logger.info(f"RTI {host}: {line}")
                        print(f"RTI {host}: {line}")

                    if success:
                        if metric_settings is not None:
                            # Only update metrics if explicitly provided
                            enabled_metrics = {}
                            for metric_name, settings in host_metrics.items():
                                enabled_metrics[metric_name] = {
                                    "finegrained": settings.get('finegrained', False),
                                    "streaming": settings.get('streaming', False)
                                }

                            new_cfg = {"servers": {host: {
                                "type": "STORAGE" if is_storage else "COMPUTE",
                                "freq": {"fg_int": fg, "stream_int": si, "tags": tags},
                                "endpoint": endpoint,
                                "metrics": enabled_metrics
                            }}}
                            save_rti_config(new_cfg, current_user.id if current_user else "web")
                        else:
                            # Sync button - only update FG/Stream/Tags/Endpoint, preserve existing metrics
                            new_cfg = {"servers": {host: {
                                "type": "STORAGE" if is_storage else "COMPUTE",
                                "freq": {"fg_int": fg, "stream_int": si, "tags": tags},
                                "endpoint": endpoint,
                                "metrics": {}  # Empty metrics = don't touch in save_rti_config
                            }}}
                            save_rti_config(new_cfg, current_user.id if current_user else "web")

                        flash(f"✓ Pushed to {host} AND saved to database", "success")
                    else:
                        flash(f"✗ Smart sync failed for {host}", "danger")
                        return render_template('rti/setup.html', servers=servers, selected=selected, config=cfg), 400
                else:
                    # Fallback: if no metrics sent from frontend, fetch live metrics from cell
                    if not host_metrics:
                        try:
                            from rti_routes import get_live_metrics  # circular import protection
                        except:
                            pass
                        # For now, log the issue and continue with empty metrics
                        print(f"RTI WARNING: No metrics received for {host} in sync_from_cell, host_metrics is empty")
                        host_metrics = {}

                    enabled_metrics = {}
                    for metric_name, settings in host_metrics.items():
                        enabled_metrics[metric_name] = {
                            "finegrained": settings.get('finegrained', False),
                            "streaming": settings.get('streaming', False)
                        }

                    new_cfg = {"servers": {host: {
                        "type": "STORAGE" if is_storage else "COMPUTE",
                        "freq": {"fg_int": fg, "stream_int": si, "tags": tags},
                        "endpoint": endpoint,
                        "metrics": enabled_metrics
                    }}}
                    saved = save_rti_config(new_cfg, current_user.id if current_user else "web")
                    if saved:
                        flash(f"✓ Saved {len(enabled_metrics)} metrics for {host} to database", "success")
                    else:
                        flash(f"✗ Failed to save metrics for {host} to database", "danger")
                        return render_template('rti/setup.html', servers=servers, selected=selected, config=cfg), 500

            return render_template('rti/setup.html', servers=servers, selected=selected, config=cfg)

    return render_template('rti/setup.html', servers=servers, selected=selected, config=cfg)


@rti_bp.route('/sync_host', methods=['POST'])
@login_required
def sync_host():
    """Dedicated endpoint for Sync button - updates host-level config (FG/STREAM/TAGS/ENDPOINT) on cell AND saves to DB"""
    hostname = request.form.get('hostname')
    fg = request.form.get('fg_int', '5')
    si = request.form.get('stream_int', '60')
    tags = request.form.get('tags', '{"fleet":"MAA_Lab"}')
    endpoint = request.form.get('endpoint', '')

    if not hostname:
        return jsonify({'success': False, 'error': 'No hostname provided'}), 400

    is_storage = any(x in hostname.lower() for x in ['cel', 'cell'])
    global_settings = {'fg_int': fg, 'stream_int': si, 'tags': tags, 'endpoint': endpoint}

    success, log_lines = push_db_to_cell_smart(hostname, {}, global_settings)

    for line in log_lines:
        logger.info(f"RTI {hostname}: {line}")
        print(f"RTI {hostname}: {line}")

    if success:
        new_cfg = {"servers": {hostname: {
            "type": "STORAGE" if is_storage else "COMPUTE",
            "freq": {"fg_int": fg, "stream_int": si, "tags": tags},
            "endpoint": endpoint,
            "metrics": {}
        }}}
        saved = save_rti_config(new_cfg, current_user.id if current_user else "web")
        return jsonify({'success': True, 'message': f'Host config updated for {hostname}', 'saved_to_db': saved})
    else:
        return jsonify({'success': False, 'error': f'Failed to apply settings to {hostname}', 'log': log_lines}), 500

@rti_bp.route('/stream', methods=['GET'])
@login_required
def rti_stream():
    """RTI Analytics Studio - Live + Historical + Comparison with aggressive no-cache"""
    # Force unique render to break any remaining cache layers
    cache_bust = int(time.time())
    resp = make_response(render_template('rti/stream.html', cache_bust=cache_bust))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@rti_bp.route('/toggle_capture', methods=['POST'])
@login_required
def toggle_capture():
    if not RTI_CAPTURE_ACTIVE:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        RTI_CAPTURE_FILE = os.path.join(RTI_CAPTURE_DIR, f"rti_global_{ts}.jsonl")
        RTI_CAPTURE_ACTIVE = True
        flash(f"Global JSON capture started", "success")
    else:
        RTI_CAPTURE_ACTIVE = False
        flash("Capture stopped", "info")
        RTI_CAPTURE_FILE = None
    return redirect(url_for('rti.rti_stream'))

@rti_bp.route('/download_capture')
@login_required
def download_capture():
    f = request.args.get('file')
    if f and os.path.exists(f):
        return send_from_directory(RTI_CAPTURE_DIR, os.path.basename(f), as_attachment=True)
    files = sorted([os.path.join(RTI_CAPTURE_DIR, x) for x in os.listdir(RTI_CAPTURE_DIR) if x.endswith('.jsonl')], reverse=True)
    if files:
        return send_from_directory(RTI_CAPTURE_DIR, os.path.basename(files[0]), as_attachment=True)
    flash("No capture files", "warning")
    return redirect(url_for('rti.rti_stream'))

@rti_bp.route('/receive', methods=['GET', 'POST'])
def receive_rti():
    if request.method == 'GET':
        return """
        <html><head><title>RTI Receive</title><style>body{background:#111;color:#0f0;font-family:monospace;padding:2em}</style></head>
        <body><h1>Exadata Real-Time Insight Receive Endpoint</h1>
        <p>POST JSON here from cells. <a href="/rti/stream">View Live Stream</a></p>
        </body></html>
        """, 200
    try:
        payload = request.get_json(force=True, silent=True) or {}
        now_iso = datetime.now(timezone.utc).isoformat()
        inserted = 0
        with RTI_LOCK:
            for section in ['gauge', 'counter', 'rate', 'instantaneous']:
                for item in payload.get(section, []):
                    server = item.get('dimensions', {}).get('server', request.remote_addr)
                    metric = item.get('metric', 'unknown')
                    key = (server, metric)
                    sample = {
                        'timestamp': item.get('timestamp', int(time.time()*1000)),
                        'value': str(item.get('value', '')),
                        'unit': item.get('unit', ''),
                        'dimensions': item.get('dimensions', {}),
                        'received_at': now_iso
                    }
                    RTI_BUFFER[key].append(sample)
                    if RTI_PERSIST_TO_DB:
                        try:
                            conn = get_db_pool_connection()
                            cur = conn.cursor()
                            cur.execute("""
                                INSERT INTO MAAMD.RTI_METRICS (TIMESTAMP, SERVER, METRIC, VALUE, UNIT, DIMENSIONS, RECEIVED_AT)
                                VALUES (:1, :2, :3, :4, :5, :6, SYSTIMESTAMP)
                            """, (sample['timestamp'], server, metric, sample['value'], sample['unit'], json.dumps(sample['dimensions'])))
                            conn.commit()
                            cur.close()
                            release_db_pool_connection(conn)
                            inserted += 1
                        except:
                            pass
                    try:
                        room = f"rti_{server.upper()}"
                        current_app.socketio.emit('rti_update', {
                            'server': server, 'metric': metric, 'value': sample['value'],
                            'unit': sample['unit'], 'timestamp': sample['timestamp'],
                            'dimensions': sample['dimensions']
                        }, room=room)
                    except Exception as emit_err:
                        logger.debug(f"RTI emit to {room} failed (client may not be subscribed): {emit_err}")
            if RTI_CAPTURE_ACTIVE and RTI_CAPTURE_FILE:
                with RTI_CAPTURE_LOCK:
                    with open(RTI_CAPTURE_FILE, 'a') as f:
                        f.write(json.dumps(payload) + '\n')
        return jsonify({'status': 'ok', 'db_inserted': inserted}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'msg': str(e)}), 400

@rti_bp.route('/api/status')
@login_required
def rti_api_status():
    buf = sum(len(v) for v in RTI_BUFFER.values())
    cfg = load_rti_config()
    return jsonify({
        'capture_active': RTI_CAPTURE_ACTIVE,
        'capture_file': RTI_CAPTURE_FILE,
        'buffered_samples': buf,
        'persist_to_db': RTI_PERSIST_TO_DB,
        'configured_servers': list(cfg.get('servers', {}).keys()),
        'db_tables': 'MAAMD.RTI_SERVER_CONFIG + RTI_METRIC_SETTINGS + RTI_METRICS'
    })

@rti_bp.route('/api/servers')
@login_required
def rti_api_servers():
    return jsonify(get_rti_servers())

@rti_bp.route('/api/metrics')
@login_required
def rti_api_metrics():
    server = request.args.get('server', '')
    if not server:
        return jsonify([])
    try:
        is_storage = any(x in server.lower() for x in ['cel', 'cell', 'storage'])
        if is_storage:
            cmd = f"dcli -c {server} -l root 'cellcli -e \"list metricdefinition attributes name,finegrained,streaming\"' 2>&1"
        else:
            cmd = f"dcli_compute -c {server} -l root 'dbmcli -e \"list metricdefinition attributes name,finegrained,streaming\"' 2>&1"
        ssh, _ = robust_ssh_connect_rti('localhost', 'maatest')
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        out = stdout.read().decode('utf-8', errors='ignore').strip()
        ssh.close()
        if 'Permission' in out or 'disconnect' in out.lower() or 'denied' in out.lower():
            out, err, rc = run_cellcli_or_dcli(server, "list metricdefinition attributes name,finegrained,streaming", is_storage)

        metrics = []
        for line in out.splitlines():
            line = line.strip()
            if not line or 'Permission' in line or 'disconnect' in out.lower() or 'denied' in out.lower():
                continue
            if ':' in line:
                line = line.split(':', 1)[1].strip()
            parts = line.split()
            if len(parts) >= 3:
                name = parts[0]
                fine = parts[1].lower() == 'enabled'
                stream = parts[2].lower() == 'enabled'
                metrics.append({"name": name, "finegrained": fine, "streaming": stream})
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Failed to load metrics for {server}: {e}")
        return jsonify([
            {"name": "CD_IO_BY_R_LG", "finegrained": True, "streaming": True},
            {"name": "CD_IO_BY_R_SM", "finegrained": True, "streaming": True},
            {"name": "CD_IO_BY_W_LG", "finegrained": True, "streaming": True},
            {"name": "CD_IO_BY_W_SM", "finegrained": True, "streaming": True},
        ])

@rti_bp.route('/api/server_config')
@login_required
def rti_api_server_config():
    server = request.args.get('server', '')
    if not server:
        return jsonify({})
    cfg = load_rti_config(hostname_filter=server)
    server_config = cfg.get('servers', {}).get(server, {})
    return jsonify(server_config)

@rti_bp.route('/api/server_config_all')
@login_required
def rti_api_server_config_all():
    cfg = load_rti_config()
    return jsonify(cfg.get('servers', {}))

@rti_bp.route('/api/configured_servers')
@login_required
def rti_api_configured_servers():
    """Return only servers that have a defined (non-null) endpoint in RTI_SERVER_CONFIG"""
    import time
    start = time.time()
    servers = []
    try:
        conn = get_db_pool_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT HOSTNAME, TYPE, ENDPOINT
            FROM MAAMD.RTI_SERVER_CONFIG
            WHERE ENDPOINT IS NOT NULL
            ORDER BY HOSTNAME
        """)
        rows = cursor.fetchall()
        for row in rows:
            hostname, typ, endpoint = row
            servers.append({
                'hostname': hostname,
                'type': typ or 'UNKNOWN',
                'endpoint': endpoint
            })
        cursor.close()
        release_db_pool_connection(conn)
        elapsed = (time.time() - start) * 1000
        logger.info(f"RTI configured_servers: {len(servers)} hosts in {elapsed:.1f}ms")
    except Exception as e:
        logger.warning(f"RTI configured servers query failed: {e}")
    return jsonify(servers)

@rti_bp.route('/api/recent_metrics')
@login_required
def rti_api_recent_metrics():
    """Return the most recent metric samples from the database for live stream display"""
    server = request.args.get('server', '').upper()
    limit = int(request.args.get('limit', 100))
    if not server:
        return jsonify([])
    try:
        conn = get_db_pool_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT TIMESTAMP, METRIC, VALUE, UNIT, RECEIVED_AT
            FROM MAAMD.RTI_METRICS
            WHERE UPPER(SERVER) = UPPER(:1)
            ORDER BY RECEIVED_AT DESC
            FETCH FIRST :2 ROWS ONLY
        """, (server, limit))
        rows = cur.fetchall()
        cur.close()
        release_db_pool_connection(conn)
        result = []
        for row in rows:
            result.append({
                'timestamp': row[0],
                'metric': row[1],
                'value': row[2],
                'unit': row[3],
                'received_at': str(row[4]) if row[4] else ''
            })
        return jsonify(result)
    except Exception as e:
        logger.error(f"Failed to fetch recent metrics for {server}: {e}")
        return jsonify([])

@rti_bp.route('/api/historical_metrics')
@login_required
def api_historical_metrics():
    """Return historical metric data for charts. Supports hours (default) or precise start/end datetimes."""
    server = request.args.get('server', '').upper()
    metric = request.args.get('metric', '%')
    hours = request.args.get('hours')
    start = request.args.get('start')  # ISO format: 2026-05-03T10:00
    end = request.args.get('end')      # ISO format: 2026-05-03T11:00
    limit = int(request.args.get('limit', 2000))  # Reduced from 5000 → better performance for Chart.js + table rendering on large ranges

    if not server:
        return jsonify({'error': 'server parameter required'}), 400

    try:
        conn = get_db_pool_connection()
        cur = conn.cursor()
        
        # Build dynamic WHERE clause based on time range parameters
        where_clauses = ["UPPER(SERVER) = UPPER(:1)", "METRIC LIKE :2"]
        params = [server, metric]
        
        if start and end:
            # Precise datetime range (from frontend datetime-local inputs)
            where_clauses.append("RECEIVED_AT BETWEEN TO_TIMESTAMP(:3, 'YYYY-MM-DD\"T\"HH24:MI') AND TO_TIMESTAMP(:4, 'YYYY-MM-DD\"T\"HH24:MI')")
            params.extend([start, end])
        elif start:
            where_clauses.append("RECEIVED_AT >= TO_TIMESTAMP(:3, 'YYYY-MM-DD\"T\"HH24:MI')")
            params.append(start)
        elif end:
            where_clauses.append("RECEIVED_AT <= TO_TIMESTAMP(:3, 'YYYY-MM-DD\"T\"HH24:MI')")
            params.append(end)
        else:
            # Default: use hours (default 24 hours if not specified, to show recent data)
            h = int(hours) if hours else 24
            where_clauses.append("RECEIVED_AT >= SYSTIMESTAMP - :3/24")
            params.append(h)
        
        where_sql = " AND ".join(where_clauses)
        
        sql = f"""
            SELECT TIMESTAMP, METRIC, VALUE, UNIT, RECEIVED_AT
            FROM MAAMD.RTI_METRICS
            WHERE {where_sql}
            ORDER BY RECEIVED_AT DESC
            FETCH FIRST :{len(params)+1} ROWS ONLY
        """
        params.append(limit)
        
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
        release_db_pool_connection(conn)

        result = []
        for row in rows:
            val = row[2]
            try:
                val = float(val) if val else 0
            except:
                pass
            result.append({
                'timestamp': row[0],
                'metric': row[1],
                'value': val,
                'unit': row[3],
                'received_at': str(row[4]) if row[4] else ''
            })
        return jsonify(result)
    except Exception as e:
        logger.error(f"historical_metrics error: {e}")
        return jsonify({'error': str(e)}), 500


@rti_bp.route('/api/compare_metrics')
@login_required
def api_compare_metrics():
    """Compare metrics between two servers or time periods"""
    server1 = request.args.get('server1', '').upper()
    server2 = request.args.get('server2', '').upper() if request.args.get('server2') else None
    metric = request.args.get('metric', '')
    hours = int(request.args.get('hours', 1))

    if not server1 or not metric:
        return jsonify({'error': 'server1 and metric required'}), 400

    try:
        conn = get_db_pool_connection()
        cur = conn.cursor()

        # Server 1 data
        cur.execute("""
            SELECT RECEIVED_AT, VALUE
            FROM MAAMD.RTI_METRICS
            WHERE UPPER(SERVER) = UPPER(:1) AND METRIC = :2
              AND RECEIVED_AT >= SYSTIMESTAMP - :3/24
            ORDER BY RECEIVED_AT
        """, (server1, metric, hours))
        data1 = [{'time': str(r[0]), 'value': float(r[1]) if str(r[1]).replace('.','').isdigit() else r[1]} for r in cur.fetchall()]

        data2 = []
        if server2:
            cur.execute("""
                SELECT RECEIVED_AT, VALUE
                FROM MAAMD.RTI_METRICS
                WHERE UPPER(SERVER) = UPPER(:1) AND METRIC = :2
                  AND RECEIVED_AT >= SYSTIMESTAMP - :3/24
                ORDER BY RECEIVED_AT
            """, (server2, metric, hours))
            data2 = [{'time': str(r[0]), 'value': float(r[1]) if str(r[1]).replace('.','').isdigit() else r[1]} for r in cur.fetchall()]

        cur.close()
        release_db_pool_connection(conn)

        return jsonify({
            'server1': server1,
            'server2': server2,
            'metric': metric,
            'data1': data1,
            'data2': data2
        })
    except Exception as e:
        logger.error(f"compare_metrics error: {e}")
        return jsonify({'error': str(e)}), 500


@rti_bp.route('/api/refresh_server_config', methods=['POST'])
@login_required
def refresh_rti_server_config_api():
    from refresh_rti_server_config import refresh_rti_server_config
    try:
        refresh_rti_server_config()
        return jsonify({"success": True, "updated": "all hosts"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

print("RTI v2.28 - Room-based SocketIO updates (subscribe_rti) + per-host filtering for efficient real-time streaming")
