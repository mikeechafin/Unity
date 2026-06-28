#!/usr/bin/env python3
# Version: 2026-04-21 v1.23
# Complete restored routes file - all routes included + syntax fixed

import os
import uuid
import threading
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime
from maa_libraries import logger, get_db_pool_connection, release_db_connection
from oedacli_runner import run_oedacli_background, run_config_refresh_background

oedacli_bp = Blueprint('oedacli', __name__)

@oedacli_bp.route('/')
@login_required
def oedacli_index():
    return render_template('oedacli/index.html',
                         username=current_user.id,
                         logo_base64=current_app.ORACLE_LOGO_BASE64 if hasattr(current_app, 'ORACLE_LOGO_BASE64') else '',
                         oracle_red=current_app.ORACLE_RED if hasattr(current_app, 'ORACLE_RED') else '#FF0000')

@oedacli_bp.route('/execute', methods=['POST'])
@login_required
def execute_oedacli_action():
    try:
        data = request.get_json()
        commands = data.get('commands', [])
        config_id = data.get('config_id')
        dry_run = data.get('dry_run', False)
        if not commands or not config_id:
            return jsonify({'success': False, 'error': 'Missing commands or config_id'}), 400
        task_id = f"oedacli_{uuid.uuid4().hex[:12]}"
        room = task_id
        current_app.socketio.start_background_task(
            run_oedacli_background,
            task_id=task_id,
            commands=commands,
            config_id=config_id,
            dry_run=dry_run,
            username=current_user.id,
            room=room,
            db_pool=current_app.config['DB_POOL'],
            socketio=current_app.socketio
        )
        return jsonify({'success': True, 'task_id': task_id})
    except Exception as e:
        logger.error(f"Error in execute_oedacli_action: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@oedacli_bp.route('/test_emit', methods=['POST'])
@login_required
def test_emit():
    try:
        data = request.get_json() or {}
        task_id = data.get('task_id') or f"global_test_{uuid.uuid4().hex[:12]}"
        test_line = f"FORCE TEST EMIT at {datetime.now().isoformat()}"
        current_app.socketio.emit('oedacli_output', {
            'status': 'RUNNING',
            'line': test_line,
            'room': task_id,
            'task_id': task_id
        }, room=task_id, namespace='/')
        logger.info(f"[TEST EMIT] Sent test event to room {task_id}")
        return jsonify({'success': True, 'task_id': task_id, 'message': test_line})
    except Exception as e:
        logger.error(f"Test emit failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@oedacli_bp.route('/refresh_configs', methods=['POST'])
@login_required
def refresh_configs():
    try:
        data = request.get_json() or {}
        hostname = data.get('hostname')
        mode = data.get('mode', 'all')
        task_id = f"refresh_{uuid.uuid4().hex[:12]}"
        room = task_id
        current_app.socketio.start_background_task(
            run_config_refresh_background,
            task_id=task_id,
            hostname=hostname,
            mode=mode,
            username=current_user.id,
            room=room,
            db_pool=current_app.config['DB_POOL'],
            socketio=current_app.socketio
        )
        return jsonify({'success': True, 'task_id': task_id})
    except Exception as e:
        logger.error(f"Error in refresh_configs: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@oedacli_bp.route('/api/configs', methods=['GET'])
@login_required
def api_configs():
    conn = None
    try:
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT CONFIG_ID, CONFIG_NAME, CREATED_DATE
            FROM MAAMD.OEDACLI_CONFIGS
            ORDER BY CREATED_DATE DESC
        """)
        rows = cursor.fetchall()
        configs = [{'id': r[0], 'name': r[1], 'created': r[2].isoformat() if r[2] else None} for r in rows]
        return jsonify({'configs': configs})
    except Exception as e:
        logger.error(f"Error querying configs: {e}")
        return jsonify({'configs': [], 'error': str(e)})
    finally:
        if conn:
            release_db_connection(conn, current_app.config['DB_POOL'])

@oedacli_bp.route('/api/hosts', methods=['GET'])
@login_required
def api_hosts():
    conn = None
    try:
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT SYSTEM_NAME
            FROM MAAMD.SYSTEM_ALLOCATIONS
            WHERE LOWER(SYSTEM_NAME) LIKE '%adm%'
              AND LOWER(SYSTEM_NAME) NOT LIKE '%celadm%'
            ORDER BY SYSTEM_NAME
        """)
        rows = cursor.fetchall()
        hosts = [r[0] for r in rows]
        return jsonify({'hosts': hosts})
    except Exception as e:
        logger.error(f"Error querying hosts: {e}")
        return jsonify({'hosts': []})
    finally:
        if conn:
            release_db_connection(conn, current_app.config['DB_POOL'])

@oedacli_bp.route('/ping')
def ping():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})

@oedacli_bp.route('/api/cluster_rack_sizes', methods=['GET'])
@login_required
def api_cluster_rack_sizes():
    conn = None
    try:
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        sql = """
            SELECT
                CASE
                    WHEN db_count = 2 AND storage_count = 3 THEN 'Quarter Rack'
                    WHEN db_count = 4 AND storage_count = 6 THEN 'Half Rack'
                    WHEN db_count = 8 AND storage_count = 12 THEN 'Full Rack'
                    ELSE 'Other'
                END AS rack_size,
                COUNT(*) AS cluster_count
            FROM (
                SELECT
                    c.CONFIG_ID,
                    (SELECT COUNT(*)
                     FROM JSON_TABLE(c.XML_CONTENT, '$.members[*]'
                          COLUMNS (type VARCHAR2(50) PATH '$.type'))
                     WHERE type = 'Database Server') AS db_count,
                    (SELECT COUNT(*)
                     FROM JSON_TABLE(c.XML_CONTENT, '$.members[*]'
                          COLUMNS (type VARCHAR2(50) PATH '$.type'))
                     WHERE type = 'Storage Server') AS storage_count
                FROM MAAMD.OEDACLI_CONFIGS c
            ) t
            GROUP BY
                CASE
                    WHEN db_count = 2 AND storage_count = 3 THEN 'Quarter Rack'
                    WHEN db_count = 4 AND storage_count = 6 THEN 'Half Rack'
                    WHEN db_count = 8 AND storage_count = 12 THEN 'Full Rack'
                    ELSE 'Other'
                END
            ORDER BY cluster_count DESC
        """
        cursor.execute(sql)
        rows = cursor.fetchall()
        labels = [row[0] for row in rows]
        data = [row[1] for row in rows]
        total = sum(data)
        return jsonify({'labels': labels, 'data': data, 'total_clusters': total, 'success': True})
    except Exception as e:
        logger.error(f"Error in api_cluster_rack_sizes: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if conn:
            release_db_connection(conn, current_app.config['DB_POOL'])

@oedacli_bp.route('/api/cluster_discovery_trend', methods=['GET'])
@login_required
def api_cluster_discovery_trend():
    conn = None
    try:
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        sql = """
            SELECT
                TO_CHAR(CREATED_DATE, 'YYYY-MM-DD') AS discovery_date,
                COUNT(*) AS clusters_added
            FROM MAAMD.OEDACLI_CONFIGS
            GROUP BY TO_CHAR(CREATED_DATE, 'YYYY-MM-DD')
            ORDER BY discovery_date ASC
        """
        cursor.execute(sql)
        rows = cursor.fetchall()
        dates = []
        counts = []
        cumulative = 0
        cumulative_counts = []
        for row in rows:
            dates.append(row[0])
            counts.append(row[1])
            cumulative += row[1]
            cumulative_counts.append(cumulative)
        return jsonify({'dates': dates, 'daily_counts': counts, 'cumulative_counts': cumulative_counts, 'success': True})
    except Exception as e:
        logger.error(f"Error in api_cluster_discovery_trend: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if conn:
            release_db_connection(conn, current_app.config['DB_POOL'])

@oedacli_bp.route('/api/server_types', methods=['GET'])
@login_required
def api_server_types():
    conn = None
    try:
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        sql = """
            SELECT
                SUM((SELECT COUNT(*) FROM JSON_TABLE(c.XML_CONTENT, '$.members[*]' COLUMNS (type VARCHAR2(50) PATH '$.type')) WHERE type = 'Database Server')) AS db_servers,
                SUM((SELECT COUNT(*) FROM JSON_TABLE(c.XML_CONTENT, '$.members[*]' COLUMNS (type VARCHAR2(50) PATH '$.type')) WHERE type = 'Storage Server')) AS storage_servers
            FROM MAAMD.OEDACLI_CONFIGS c
        """
        cursor.execute(sql)
        row = cursor.fetchone()
        return jsonify({'db_servers': row[0] or 0, 'storage_servers': row[1] or 0, 'success': True})
    except Exception as e:
        logger.error(f"Error in api_server_types: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if conn:
            release_db_connection(conn, current_app.config['DB_POOL'])

@oedacli_bp.route('/wizard')
@login_required
def oedacli_wizard():
    return render_template('oedacli/wizard.html',
                         username=current_user.id,
                         logo_base64=current_app.ORACLE_LOGO_BASE64 if hasattr(current_app, 'ORACLE_LOGO_BASE64') else '')

@oedacli_bp.route('/dashboard')
@login_required
def oedacli_dashboard():
    """OEDACLI Job History page - hardened version"""
    try:
        # Fetch jobs directly (more reliable than relying on client-side)
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT TASK_ID, COMMAND_FILE_CONTENT, STATUS, STARTED_DATE, COMPLETED_DATE
            FROM MAAMD.OEDACLI_JOBS
            ORDER BY STARTED_DATE DESC
            FETCH FIRST 50 ROWS ONLY
        """)
        
        rows = cursor.fetchall()
        jobs = []
        
        for row in rows:
            task_id = row[0]
            command = str(row[1])[:180] if row[1] else "—"
            status = row[2] or "UNKNOWN"
            started = row[3]
            completed = row[4]
            
            # Calculate duration
            duration = "—"
            if started and completed:
                try:
                    delta = completed - started
                    secs = int(delta.total_seconds())
                    duration = f"{secs}s" if secs < 60 else f"{secs // 60}m {secs % 60}s"
                except:
                    duration = "—"
            
            jobs.append({
                'id': task_id,
                'command': command,
                'status': status,
                'started_at': started.isoformat() if started else "—",
                'duration': duration
            })
        
        release_db_connection(conn, current_app.config['DB_POOL'])
        
        return render_template('oedacli/dashboard.html',
                             username=current_user.id,
                             jobs=jobs,
                             logo_base64=current_app.ORACLE_LOGO_BASE64 if hasattr(current_app, 'ORACLE_LOGO_BASE64') else '')
    
    except Exception as e:
        logger.error(f"Error loading OEDACLI dashboard: {str(e)}", exc_info=True)
        # Always return something so the page doesn't crash
        return render_template('oedacli/dashboard.html',
                             username=current_user.id,
                             jobs=[],
                             logo_base64=current_app.ORACLE_LOGO_BASE64 if hasattr(current_app, 'ORACLE_LOGO_BASE64') else '')

@oedacli_bp.route('/api/jobs', methods=['GET'])
@login_required
def api_oedacli_jobs():
    """Returns recent OEDACLI job executions for the dashboard."""
    conn = None
    try:
        conn = get_db_pool_connection(current_app.config['DB_POOL'])
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                JOB_ID,
                TASK_ID,
                STATUS,
                STARTED_DATE,
                COMPLETED_DATE,
                RETURN_CODE,
                DRY_RUN,
                COMMAND_FILE_CONTENT
            FROM MAAMD.OEDACLI_JOBS
            ORDER BY STARTED_DATE DESC
            FETCH FIRST 50 ROWS ONLY
        """)
        
        rows = cursor.fetchall()
        jobs = []
        
        for row in rows:
            job_id = row[0]
            task_id = row[1]
            status = row[2]
            started = row[3]
            completed = row[4]
            return_code = row[5]
            dry_run = bool(row[6])
            command_clob = row[7]
            
            # Handle CLOB safely
            command = ""
            if command_clob:
                try:
                    command = command_clob.read() if hasattr(command_clob, 'read') else str(command_clob)
                except:
                    command = str(command_clob)
            
            # Truncate long commands
            if len(command) > 200:
                command = command[:200] + "..."
            
            # Calculate duration
            duration = "—"
            if started and completed:
                try:
                    delta = completed - started
                    total_seconds = int(delta.total_seconds())
                    if total_seconds < 60:
                        duration = f"{total_seconds}s"
                    else:
                        minutes = total_seconds // 60
                        seconds = total_seconds % 60
                        duration = f"{minutes}m {seconds}s"
                except:
                    duration = "—"
            
            jobs.append({
                'id': task_id,                    # ← This matches your template: job.id
                'command': command or '—',
                'status': status or 'UNKNOWN',
                'started_at': started.isoformat() if started else '—',
                'duration': duration,
                'return_code': return_code,
                'dry_run': dry_run
            })
        
        return jsonify({'jobs': jobs})
        
    except Exception as e:
        logger.error(f"Error in api_oedacli_jobs: {str(e)}", exc_info=True)
        return jsonify({'jobs': [], 'error': str(e)}), 500
    finally:
        if conn:
            release_db_connection(conn, current_app.config['DB_POOL'])    
