#!/usr/bin/env python3
import oracledb
import hashlib
import traceback
import os
import psutil
import time
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify, current_app
from flask_login import login_required, current_user
from maa_libraries import logger, get_db_connection, get_db_pool_connection, release_db_connection, monitor_agent_status, delete_agent, shutdown_agent, startup_agent, refresh_agent_status, is_valid_fqdn, agent_status, status_lock, stop_monitoring
from maa_agent_helpers import compute_md5_hash, normalize_error_message, get_db_credentials, classify_error_type, compute_fingerprint
from datetime import datetime
from collections import namedtuple, defaultdict
import subprocess
from urllib.parse import unquote
import paramiko
from concurrent.futures import ThreadPoolExecutor
import re
import json
import threading

# Version: 2026-03-31 v1.3.3
# Changes: Fixed release_db_connection() missing 'pool' error by using direct conn.close() in parser_status (and all other direct get_db_connection calls). Kept exact scalar subquery for PARSED_DATE (matches your schema). All legacy routes preserved verbatim from your v1.2.12 copy. No changes to maa_libraries.py.

ERROR_COUNT_LIMIT = 50
agent_bp = Blueprint('agent', __name__, template_folder='templates/agent', static_folder='static/agent')

# === ULTRA-FAST PARSER STATUS CACHE (global, 60s TTL) ===
parser_stats_cache = {"data": None, "timestamp": 0}
CACHE_TTL = 60

@agent_bp.route('/parser_status')
@login_required
def parser_status():
    start_time = time.time()
    now = time.time()
    if parser_stats_cache["data"] and (now - parser_stats_cache["timestamp"] < CACHE_TTL):
        logs_tracked, unique_errors, last_parsed = parser_stats_cache["data"]
        logger.debug("parser_status: served from global 60s in-memory cache")
    else:
        logs_tracked = unique_errors = 0
        last_parsed = datetime.now()
        for attempt in range(6):
            try:
                conn = get_db_connection("maamd", os.environ.get('DB_PASSWORD'), current_app.config['DB_CONFIG']['dsn'])
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT /*+ RESULT_CACHE FIRST_ROWS(1) NO_PARALLEL MATERIALIZE */
                        NVL((SELECT num_rows FROM user_tables WHERE table_name = 'AGENT_LOG_INVENTORY'), 0) as logs_tracked,
                        (SELECT APPROX_COUNT_DISTINCT(error_hash) FROM maamd.agent_errors) as unique_errors,
                        TO_CHAR((SELECT MAX(parsed_date) FROM maamd.AGENT_LOG_INVENTORY), 'YYYY-MM-DD HH24:MI') as last_parsed_str
                    FROM dual
                """)
                row = cursor.fetchone()
                if row:
                    logs_tracked = int(row[0] or 0)
                    unique_errors = int(row[1] or 0)
                    last_parsed_str = row[2] or None
                    if last_parsed_str:
                        last_parsed = datetime.strptime(last_parsed_str, '%Y-%m-%d %H:%M')
                cursor.close()
                conn.close()  # direct connection - use close() instead of release_db_connection
                logger.info(f"parser_status query completed in {time.time()-start_time:.2f}s (logs={logs_tracked}, errors={unique_errors})")
                break
            except Exception as e:
                logger.warning(f"parser_status attempt {attempt+1} failed: {str(e)[:200]}")
                time.sleep(1.5 ** attempt)
        parser_stats_cache["data"] = (logs_tracked, unique_errors, last_parsed)
        parser_stats_cache["timestamp"] = now
    import config as app_config
    changes_summary = {'new_count': 0, 'regression_count': 0}
    codex_available = False
    try:
        if os.path.isfile(app_config.AGENT_ERROR_CHANGES_FILE):
            with open(app_config.AGENT_ERROR_CHANGES_FILE, 'r') as f:
                ch = json.load(f)
                changes_summary['new_count'] = ch.get('new_count', 0)
                changes_summary['regression_count'] = ch.get('regression_count', 0)
        from maa_codex_client import is_codex_available
        codex_available = is_codex_available()
    except Exception:
        pass
    return render_template('agent/parser_status.html',
                           logs_tracked=logs_tracked,
                           unique_errors=unique_errors,
                           last_parsed=last_parsed,
                           changes_summary=changes_summary,
                           codex_available=codex_available)

@agent_bp.route('/error_summary')
@login_required
def error_summary():
    return render_template('agent/error_summary.html')

@agent_bp.route('/error_summary_data')
@login_required
def error_summary_data():
    start_time = time.time()
    for attempt in range(6):
        try:
            username, password = get_db_credentials()
            conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
            cursor = conn.cursor()
            page = int(request.args.get('start', 0)) // 50
            per_page = int(request.args.get('length', 50))
            error_type = request.args.get('error_type', '').strip()
            search = request.args.get('search[value]', '').strip().lower()
            where = []
            params = []
            if error_type:
                where.append("error_type = :1")
                params.append(error_type)
            if search:
                where.append("(LOWER(NVL(normalized_message, error_message_trunc)) LIKE :2 OR error_hash LIKE :3)")
                params.extend([f"%{search}%", f"%{search}%"])
            where_clause = " AND ".join(where) if where else "1=1"
            query = f"""
                SELECT /*+ FIRST_ROWS(25) */
                    error_type, error_hash,
                    NVL(normalized_message, error_message_trunc) AS normalized_message,
                    SUM(occurrence_count) AS total_occurrences,
                    COUNT(DISTINCT hostname) AS host_count,
                    MAX(last_seen) AS last_seen
                FROM maamd.agent_errors
                WHERE {where_clause}
                GROUP BY error_type, error_hash, NVL(normalized_message, error_message_trunc)
                ORDER BY total_occurrences DESC
                OFFSET :4 ROWS FETCH NEXT 25 ROWS ONLY
            """
            cursor.execute(query, params + [page * per_page])
            rows = cursor.fetchall()
            data = []
            for row in rows:
                norm = row[2] or ''
                data.append({
                    "error_type": row[0] or 'OTHER',
                    "fingerprint": row[1],
                    "normalized": norm[:120] + "..." if len(norm) > 120 else norm,
                    "occurrences": row[3],
                    "hosts": row[4],
                    "last_seen": row[5].strftime("%Y-%m-%d %H:%M") if row[5] else "",
                    "detail_url": f"/agent/error_detail/{row[1]}"
                })
            cursor.close()
            conn.close()
            logger.info(f"error_summary_data query took {time.time()-start_time:.2f}s (returned {len(data)} rows)")
            return jsonify({"data": data})
        except oracledb.Error as e:
            logger.warning(f"maamd attempt {attempt+1} failed for error_summary_data: {e}")
            time.sleep(2 ** attempt)
            if attempt == 5:
                logger.error("All maamd attempts failed for error_summary_data")
                return jsonify({"data": []})

@agent_bp.route('/error_detail/<string:fingerprint>')
@login_required
def error_detail(fingerprint):
    start_time = time.time()
    for attempt in range(6):
        try:
            username, password = get_db_credentials()
            conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
            cursor = conn.cursor()
            cursor.execute("""
                SELECT /*+ FIRST_ROWS(25) */
                    hostname, agent_home, error_message, occurrence_count, first_seen, last_seen
                FROM maamd.agent_errors
                WHERE error_hash = :1
                ORDER BY occurrence_count DESC
                FETCH FIRST 25 ROWS ONLY
            """, [fingerprint])
            instances = cursor.fetchall()
            normalized = normalize_error_message(instances[0][2]) if instances else ""
            error_type = classify_error_type(instances[0][2]) if instances else ""
            cursor.close()
            conn.close()
            logger.info(f"error_detail query took {time.time()-start_time:.2f}s")
            return render_template('agent/error_details.html',
                                   fingerprint=fingerprint,
                                   normalized=normalized,
                                   error_type=error_type,
                                   instances=instances)
        except oracledb.Error as e:
            logger.warning(f"maamd attempt {attempt+1} failed for error_detail: {e}")
            time.sleep(2 ** attempt)
            if attempt == 5:
                logger.error("All maamd attempts failed for error_detail")
                return render_template('agent/error_details.html',
                                       fingerprint=fingerprint,
                                       normalized="Database temporarily unavailable",
                                       error_type="ERROR",
                                       instances=[])

@agent_bp.route('/run_parser_now', methods=['POST'])
@login_required
def run_parser_now():
    try:
        import config
        use_codex = request.form.get('use_codex', '1') == '1'
        cmd = ["python3", os.path.join(config.APP_ROOT, "parse_agent_logs.py"), "--debug"]
        if use_codex:
            cmd.append("--codex")
        else:
            cmd.append("--no-codex")
        subprocess.Popen(cmd)
        flash("✅ Full parser pipeline started (crawl + rollup + regression" +
              (" + Codex" if use_codex else "") + "). Check parse_agent_logs.log.", "success")
    except Exception as e:
        flash(f"Failed to start parser: {e}", "error")
    return redirect(url_for('agent.parser_status'))


@agent_bp.route('/ai_insights')
@login_required
def ai_insights():
    import config
    analysis = {}
    changes = {}
    codex_available = False
    try:
        from maa_codex_client import is_codex_available
        codex_available = is_codex_available()
    except Exception:
        pass
    if os.path.isfile(config.AGENT_ERROR_ANALYSIS_FILE):
        with open(config.AGENT_ERROR_ANALYSIS_FILE, 'r') as f:
            analysis = json.load(f)
    if os.path.isfile(config.AGENT_ERROR_CHANGES_FILE):
        with open(config.AGENT_ERROR_CHANGES_FILE, 'r') as f:
            changes = json.load(f)
    return render_template('agent/ai_insights.html',
                           analysis=analysis,
                           changes=changes,
                           codex_available=codex_available)


@agent_bp.route('/api/changes')
@login_required
def api_changes():
    import config
    if os.path.isfile(config.AGENT_ERROR_CHANGES_FILE):
        with open(config.AGENT_ERROR_CHANGES_FILE, 'r') as f:
            return jsonify(json.load(f))
    return jsonify({'new_errors': [], 'regressions': [], 'is_first_run': True})


@agent_bp.route('/run_codex_analysis', methods=['POST'])
@login_required
def run_codex_analysis_now():
    try:
        from maa_agent_log_parser.codex_analyzer import run_codex_analysis
        run_codex_analysis(force=True)
        flash("✅ Codex analysis complete.", "success")
    except Exception as e:
        flash(f"Codex analysis failed: {e}", "error")
    return redirect(url_for('agent.ai_insights'))

@agent_bp.route('/')
@login_required
def agent_index():
    return redirect(url_for('agent.report'))

@agent_bp.route('/status', methods=['GET'])
@login_required
def get_agent_status():
    with status_lock:
        status_copy = dict(agent_status)
    return jsonify(status_copy)

@agent_bp.route('/report', methods=['GET'])
@login_required
def report():
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('login'))
    summary_data = []
    total_unregistered = 0
    total_detected = 0
    details_data = []
    global_error_data = []
    filters = {
        'summary_hostname': '',
        'details_hostname': '',
        'pid': '',
        'port': '',
        'agent_home': '',
        'oms_url': '',
        'snmp_count': '',
        'configured_iloms': '',
        'agent_status': '',
        'install_date': '',
        'total_space': '',
        'cpu_usage': '',
        'memory_usage': '',
        'target_count': '',
        'agent_version': '',
        'oms_version': '',
        'heartbeat_status': '',
        'running_duration': '',
        'total_errors': '',
        'error_filter': '',
        'last_successful_upload': ''
    }
    try:
        logger.info("Starting /agent/report processing")
        logger.debug(f"Query parameters: {request.args}")
        process = psutil.Process()
        logger.debug(f"Memory usage before queries: RSS={process.memory_info().rss / 1024**2:.2f} MB")
        start_time = time.time()
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        query_start = time.time()
        cursor.execute("SELECT COUNT(*) FROM maamd.agent_home_info")
        agent_count = cursor.fetchone()[0]
        logger.info(f"Agent count: {agent_count} (query time={time.time()-query_start:.2f}s)")
        global_error_query = """
        SELECT
            NORMALIZED_ERROR_MESSAGE AS error_message,
            ERROR_TYPE,
            TOTAL_OCCURRENCES,
            AGENT_HOME_COUNT,
            AGENT_HOMES
        FROM MAAMD.AGENT_ERROR_GLOBAL
        ORDER BY TOTAL_OCCURRENCES DESC
        """
        logger.debug("Executing global error query")
        query_start = time.time()
        cursor.execute(global_error_query)
        raw_global_errors = cursor.fetchall()
        logger.info(f"Fetched {len(raw_global_errors)} global error rows (query time={time.time()-query_start:.2f}s)")
        global_error_data = []
        for row in raw_global_errors:
            logger.debug(f"Processing global error row: {row[:4]}, AGENT_HOMES type={type(row[4])}")
            agent_homes_str = row[4].read() if isinstance(row[4], oracledb.LOB) else row[4]
            agent_homes_list = agent_homes_str.split(',') if agent_homes_str else []
            global_error_data.append({
                'error_message': row[0],
                'error_type': row[1] or 'UNKNOWN',
                'total_occurrences': row[2],
                'agent_home_count': row[3],
                'agent_homes': agent_homes_list
            })
        logger.info(f"Processed global error data: {global_error_data[:5]} (total={len(global_error_data)})")
        summary_hostname_filter = request.args.get('summary_hostname', '').strip()
        summary_query = """
        WITH agent_counts AS (
            SELECT /*+ MATERIALIZE */
                ahi.hostname,
                SUM(CASE WHEN EXISTS (
                    SELECT 1
                    FROM maamd.ignore_strings_table ist
                    WHERE (ist.hostname = ahi.hostname OR ist.hostname = 'default')
                    AND UPPER(TRIM(ahi.agent_home)) LIKE '%' || UPPER(TRIM(ist.exclude_string)) || '%'
                ) THEN 1 ELSE 0 END) AS known_count,
                SUM(CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM maamd.ignore_strings_table ist
                    WHERE (ist.hostname = ahi.hostname OR ist.hostname = 'default')
                    AND UPPER(TRIM(ahi.agent_home)) LIKE '%' || UPPER(TRIM(ist.exclude_string)) || '%'
                ) THEN 1 ELSE 0 END) AS unregistered_count,
                COUNT(*) AS total_count
            FROM maamd.agent_home_info ahi
            GROUP BY ahi.hostname
        )
        SELECT
            ac.hostname,
            ac.unregistered_count,
            ac.known_count,
            ac.total_count,
            sa.ilom_name AS ilom_hostname
        FROM agent_counts ac
        LEFT JOIN maamd.guests g ON ac.hostname = g.hostname
        LEFT JOIN maamd.system_allocations sa
            ON sa.system_name = COALESCE(g.hypervisor, ac.hostname)
        WHERE ac.hostname NOT LIKE '%celadm%'
        """
        params = {}
        if summary_hostname_filter:
            summary_query += " AND ac.hostname LIKE :summary_hostname"
            params['summary_hostname'] = f"%{summary_hostname_filter.lower()}%"
        summary_query += " ORDER BY ac.hostname"
        query_start = time.time()
        cursor.execute(summary_query, params)
        raw_summary_data = cursor.fetchall()
        logger.info(f"Fetched {len(raw_summary_data)} summary rows (query time={time.time()-query_start:.2f}s)")
        summary_data = [(row[0], int(row[1]), int(row[2]), int(row[3]), row[4]) for row in raw_summary_data]
        if not summary_data:
            flash("No summary data found. The agent_home_info table might not match any ignore strings.", "info")
            total_unregistered = 0
            total_detected = 0
        else:
            total_unregistered = sum(row[1] for row in summary_data)
            total_detected = sum(row[3] for row in summary_data)
        logger.info(f"Total unregistered: {total_unregistered}, Total detected: {total_detected}")
        for key in filters:
            filters[key] = request.args.get(key, '').strip()
            if filters[key] and len(filters[key]) > 100:
                logger.warning(f"Invalid filter value for {key}: {filters[key]}")
                flash(f"Filter value for {key} is too long", "error")
                filters[key] = ''
        logger.debug(f"Processed filters: {filters}")
        details_query = """
        WITH base_info AS (
            SELECT
                ahi.hostname,
                ahi.pid,
                ahi.port,
                ahi.agent_home,
                ahi.oms_url,
                ahi.agent_status,
                ahi.install_date,
                ahi.total_space_mb,
                ahi.cpu_usage_percent,
                ahi.memory_usage_mb,
                ahi.target_count,
                ahi.agent_version,
                ahi.oms_version,
                ahi.heartbeat_status,
                ahi.running_duration_hours / 24 AS running_duration_days,
                ahi.last_successful_upload,
                COALESCE(es.total_errors, 0) AS total_errors
            FROM maamd.agent_home_info ahi
            LEFT JOIN maamd.guests g ON ahi.hostname = g.hostname
            LEFT JOIN (
                SELECT LOWER(TRIM(hostname)) AS hostname, LOWER(TRIM(agent_home)) AS agent_home, SUM(total_occurrences) AS total_errors
                FROM maamd.agent_error_summary
                GROUP BY LOWER(TRIM(hostname)), LOWER(TRIM(agent_home))
            ) es
                ON LOWER(TRIM(es.hostname)) = LOWER(TRIM(ahi.hostname))
               AND LOWER(TRIM(es.agent_home)) = LOWER(TRIM(ahi.agent_home))
            ),
            snmp_counts_base AS (
            SELECT
                sa.ilom_hostname,
                sa.destination_ip,
                sa.port,
                COUNT(*) AS snmp_count
            FROM maamd.snmp_subscriptions sa
            WHERE sa.status != 'disable'
            GROUP BY sa.ilom_hostname, sa.destination_ip, sa.port
            )
        SELECT
            bi.hostname,
            bi.pid,
            bi.port,
            bi.agent_home,
            bi.oms_url,
            bi.agent_status,
            bi.install_date,
            bi.total_space_mb,
            bi.cpu_usage_percent,
            bi.memory_usage_mb,
            bi.target_count,
            bi.agent_version,
            bi.oms_version,
            bi.heartbeat_status,
            bi.running_duration_days,
            bi.last_successful_upload,
            COALESCE(SUM(scb.snmp_count), 0) AS snmp_subscriptions_count,
            bi.total_errors
        FROM base_info bi
        LEFT JOIN snmp_counts_base scb
            ON scb.destination_ip = bi.hostname
           AND scb.port = bi.port
        WHERE 1=1
        """
        details_params = {}
        if filters['details_hostname']:
            details_query += " AND bi.hostname LIKE :details_hostname"
            details_params['details_hostname'] = f"%{filters['details_hostname'].lower()}%"
        if filters['pid']:
            details_query += " AND bi.pid = :pid"
            try:
                details_params['pid'] = int(filters['pid'])
            except ValueError:
                details_params['pid'] = -1
        if filters['port']:
            details_query += " AND bi.port = :port"
            try:
                details_params['port'] = int(filters['port'])
            except ValueError:
                details_params['port'] = -1
        if filters['agent_home']:
            details_query += " AND bi.agent_home LIKE :agent_home"
            details_params['agent_home'] = f"%{filters['agent_home'].lower()}%"
        if filters['oms_url']:
            details_query += " AND bi.oms_url LIKE :oms_url"
            details_params['oms_url'] = f"%{filters['oms_url'].lower()}%"
        if filters['snmp_count']:
            details_query += " AND COALESCE(SUM(scb.snmp_count), 0) = :snmp_count"
            try:
                details_params['snmp_count'] = int(filters['snmp_count'])
            except ValueError:
                details_params['snmp_count'] = -1
        if filters['agent_status']:
            details_query += " AND bi.agent_status LIKE :agent_status"
            details_params['agent_status'] = f"%{filters['agent_status'].lower()}%"
        if filters['install_date']:
            details_query += " AND TO_CHAR(bi.install_date, 'YYYY-MM-DD') LIKE :install_date"
            details_params['install_date'] = f"%{filters['install_date']}%"
        if filters['total_space']:
            details_query += " AND bi.total_space_mb = :total_space"
            try:
                details_params['total_space'] = float(filters['total_space'])
            except ValueError:
                details_params['total_space'] = -1
        if filters['cpu_usage']:
            details_query += " AND bi.cpu_usage_percent = :cpu_usage"
            try:
                details_params['cpu_usage'] = float(filters['cpu_usage'])
            except ValueError:
                details_params['cpu_usage'] = -1
        if filters['memory_usage']:
            details_query += " AND bi.memory_usage_mb = :memory_usage"
            try:
                details_params['memory_usage'] = float(filters['memory_usage'])
            except ValueError:
                details_params['memory_usage'] = -1
        if filters['target_count']:
            details_query += " AND bi.target_count = :target_count"
            try:
                details_params['target_count'] = int(filters['target_count'])
            except ValueError:
                details_params['target_count'] = -1
        if filters['agent_version']:
            details_query += " AND bi.agent_version LIKE :agent_version"
            details_params['agent_version'] = f"%{filters['agent_version'].lower()}%"
        if filters['oms_version']:
            details_query += " AND bi.oms_version LIKE :oms_version"
            details_params['oms_version'] = f"%{filters['oms_version'].lower()}%"
        if filters['heartbeat_status']:
            details_query += " AND bi.heartbeat_status LIKE :heartbeat_status"
            details_params['heartbeat_status'] = f"%{filters['heartbeat_status'].lower()}%"
        if filters['running_duration']:
            details_query += " AND bi.running_duration_days = :running_duration"
            try:
                details_params['running_duration'] = float(filters['running_duration'])
            except ValueError:
                details_params['running_duration'] = -1
        if filters['total_errors']:
            details_query += " AND bi.total_errors = :total_errors"
            try:
                details_params['total_errors'] = int(filters['total_errors'])
            except ValueError:
                details_params['total_errors'] = -1
        if filters['error_filter']:
            details_query += """
            AND EXISTS (
                SELECT 1
                FROM maamd.agent_error_summary aes
                WHERE aes.hostname = bi.hostname
                AND aes.agent_home = bi.agent_home
                AND :error_filter = aes.error_message
            )
            """
            details_params['error_filter'] = filters['error_filter']
        if filters['last_successful_upload']:
            details_query += " AND TO_CHAR(bi.last_successful_upload, 'YYYY-MM-DD') LIKE :last_successful_upload"
            details_params['last_successful_upload'] = f"%{filters['last_successful_upload']}%"
        details_query += """
            GROUP BY
            bi.hostname,
            bi.pid,
            bi.port,
            bi.agent_home,
            bi.oms_url,
            bi.agent_status,
            bi.install_date,
            bi.total_space_mb,
            bi.cpu_usage_percent,
            bi.memory_usage_mb,
            bi.target_count,
            bi.agent_version,
            bi.oms_version,
            bi.heartbeat_status,
            bi.running_duration_days,
            bi.last_successful_upload,
            bi.total_errors
            ORDER BY bi.hostname, bi.pid
        """
        logger.debug(f"Executing details query with params: {details_params}")
        query_start = time.time()
        cursor.execute(details_query, details_params)
        raw_details_data = cursor.fetchall()
        logger.info(f"Fetched {len(raw_details_data)} details rows (query time={time.time()-query_start:.2f}s)")
        if not raw_details_data:
            flash("No detailed agent data found. Check the database for related SNMP subscriptions or ILOM hosts.", "info")
            details_data = []
        else:
            ilom_query = """
            SELECT scb.destination_ip, scb.port, scb.ilom_hostname
            FROM maamd.snmp_subscriptions scb
            WHERE scb.status != 'disable'
            """
            query_start = time.time()
            cursor.execute(ilom_query)
            ilom_data = cursor.fetchall()
            logger.info(f"Fetched {len(ilom_data)} ILOM rows (query time={time.time()-query_start:.2f}s)")
            ilom_map = {}
            for dest_ip, port, ilom_hostname in ilom_data:
                key = (dest_ip.lower(), port)
                if key not in ilom_map:
                    ilom_map[key] = []
                ilom_map[key].append(ilom_hostname)
            configured_ilom_query = """
            SELECT aws.hostname, aws.pid, aws.port, ih.hostname AS configured_ilom
            FROM maamd.agent_home_info aws
            CROSS JOIN LATERAL (
                SELECT DISTINCT REGEXP_SUBSTR(
                    (SELECT LISTAGG(scb.ilom_hostname, ',') WITHIN GROUP (ORDER BY scb.ilom_hostname)
                     FROM maamd.snmp_subscriptions scb
                     WHERE scb.destination_ip = aws.hostname
                     AND scb.port = aws.port
                     AND scb.status != 'disable'),
                    '[^,]+', 1, LEVEL
                ) AS ilom_hostname
                FROM DUAL
                CONNECT BY LEVEL <= REGEXP_COUNT(
                    (SELECT LISTAGG(scb.ilom_hostname, ',') WITHIN GROUP (ORDER BY scb.ilom_hostname)
                     FROM maamd.snmp_subscriptions scb
                     WHERE scb.destination_ip = aws.hostname
                     AND scb.port = aws.port
                     AND scb.status != 'disable'),
                    ','
                ) + 1
            ) hids
            LEFT JOIN maamd.ilom_hosts ih
                ON ih.hostname = hids.ilom_hostname
            WHERE ih.hostname IS NOT NULL
            """
            query_start = time.time()
            cursor.execute(configured_ilom_query)
            configured_ilom_data = cursor.fetchall()
            logger.info(f"Fetched {len(configured_ilom_data)} configured ILOM rows (query time={time.time()-query_start:.2f}s)")
            configured_ilom_map = {}
            for hostname, pid, port, configured_ilom in configured_ilom_data:
                key = (hostname.lower(), pid, port)
                if key not in configured_ilom_map:
                    configured_ilom_map[key] = []
                configured_ilom_map[key].append(configured_ilom)
            details_data = []
            batch_size = 1000
            for batch_start in range(0, len(raw_details_data), batch_size):
                batch = raw_details_data[batch_start:batch_start + batch_size]
                for idx, row in enumerate(batch):
                    hostname, pid, port, agent_home, oms_url, agent_status, install_date, total_space_mb, \
                    cpu_usage_percent, memory_usage_mb, target_count, agent_version, oms_version, \
                    heartbeat_status, running_duration_days, last_successful_upload, snmp_count, total_errors = row
                    logger.debug(f"Raw row sample: hostname={hostname}, agent_home={agent_home}, total_errors={total_errors}, type={type(total_errors)}")
                    if not hostname or not isinstance(hostname, str):
                        logger.warning(f"Invalid hostname for row {idx}: {hostname}")
                        continue
                    if pid is None or not isinstance(pid, (int, str)) or str(pid).strip() == '':
                        logger.warning(f"Invalid pid for row {idx}: {pid}")
                        continue
                    if not agent_home or not isinstance(agent_home, str):
                        logger.warning(f"Invalid agent_home for row {idx}: {agent_home}")
                        continue
                    pid = int(pid) if pid is not None else 0
                    port = int(port) if port is not None else None
                    snmp_count = int(snmp_count or 0)
                    try:
                        cpu_usage_percent = float(cpu_usage_percent) if cpu_usage_percent is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting cpu_usage_percent for hostname {hostname}: value={cpu_usage_percent}, type={type(cpu_usage_percent)}, error={str(e)}")
                        cpu_usage_percent = 'N/A'
                    try:
                        memory_usage_mb = round(float(memory_usage_mb), 2) if memory_usage_mb is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting memory_usage_mb for hostname {hostname}: value={memory_usage_mb}, type={type(memory_usage_mb)}, error={str(e)}")
                        memory_usage_mb = 'N/A'
                    try:
                        target_count = int(target_count) if target_count is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting target_count for hostname {hostname}: value={target_count}, type={type(target_count)}, error={str(e)}")
                        target_count = 'N/A'
                    try:
                        running_duration_days = round(float(running_duration_days), 2) if running_duration_days is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting running_duration_days for hostname {hostname}: value={running_duration_days}, type={type(running_duration_days)}, error={str(e)}")
                        running_duration_days = 'N/A'
                    last_successful_upload_str = last_successful_upload.strftime("%Y-%m-%d %H:%M:%S") if last_successful_upload else 'N/A'
                    ilom_key = (hostname.lower(), port)
                    ilom_hostnames = ilom_map.get(ilom_key, [])
                    configured_key = (hostname.lower(), pid, port)
                    configured_iloms = configured_ilom_map.get(configured_key, [])
                    if not configured_iloms:
                        configured_iloms = ['None']
                    agent_id = f"{hostname}:{pid}:{agent_home}"
                    logger.debug(f"Created agent_id for row {idx}: {agent_id}")
                    row_tuple = (
                        hostname, pid, port, agent_home, oms_url or 'N/A', snmp_count, configured_iloms, agent_status or 'unknown',
                        install_date, total_space_mb or 'N/A', cpu_usage_percent, memory_usage_mb, target_count,
                        agent_version or 'N/A', oms_version or 'N/A', heartbeat_status or 'N/A', running_duration_days,
                        last_successful_upload_str, total_errors, agent_id
                    )
                    details_data.append(row_tuple)
                    logger.debug(f"Processed row - hostname: {hostname}, row: {row_tuple}")
                for row in details_data[batch_start:batch_start + batch_size]:
                    configured_iloms_len = sum(len(ilom) for ilom in row[6]) if row[6] else 0
                    logger.debug(f"Hostname {row[0]}: configured_iloms length={configured_iloms_len}")
            logger.info(f"Processed details data: {[(row[0], type(row[1]), row[1], type(row[2]), row[2], type(row[5]), row[5]) for row in details_data[:5]]}")
        cursor.close()
        conn.close()
        logger.info(f"Total processing time: {time.time()-start_time:.2f}s")
        logger.info(f"Rendering report.html with {len(global_error_data)} global errors")
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        return render_template(
            'agent/report.html',
            summary_data=summary_data,
            total_unregistered=total_unregistered,
            total_detected=total_detected,
            details_data=details_data,
            global_error_data=global_error_data,
            filters=filters,
            logo_base64=logo_base64,
            oracle_red=oracle_red,
            username=current_user.id
        )
    except oracledb.Error as e:
        logger.error(f"Database error: {e}", exc_info=True)
        error_str = str(e)
        error_code = "unknown" if "ORA-" not in error_str else error_str.split("ORA-")[1].split(":")[0]
        flash(f"Database error: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/", "error")
        return redirect(url_for('login'))
    except ValueError as e:
        logger.error(f"Data conversion error: {e}", exc_info=True)
        flash(f"Data conversion error: {str(e)}", "error")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
        flash(f"Unexpected error: {str(e)}", "error")
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        return render_template('error.html', error_message=str(e), oracle_red=oracle_red, logo_base64=logo_base64), 500

@agent_bp.route('/handle_agent_action', methods=['POST'])
@login_required
def handle_agent_action():
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('agent.report'))
    logger.debug(f"Handling POST to /agent/handle_agent_action, form data: {request.form}, headers: {request.headers}")
    action = request.form.get('action')
    selected_agents = request.form.getlist('selected_agents')
    if not selected_agents:
        logger.warning(f"No agents selected for action: {action or 'unknown action'}, form data: {request.form}")
        flash(f"No agents selected for {action or 'unknown action'}", "error")
        return redirect(url_for('agent.report'))
    valid_agents = []
    for agent in selected_agents:
        if agent.count(':') != 2:
            logger.warning(f"Invalid agent format: {agent}, expected 'hostname:pid:agent_home'")
            flash(f"Invalid agent selection: {agent}. Please ensure agents are correctly formatted.", "error")
            continue
        try:
            hostname, pid, agent_home = agent.split(':')
            if not hostname or not pid or not agent_home:
                logger.warning(f"Empty component in agent: {agent}")
                flash(f"Invalid agent selection: {agent}. Components cannot be empty.", "error")
                continue
            int(pid)
            valid_agents.append(agent)
        except ValueError:
            logger.warning(f"Invalid pid in agent: {agent}")
            flash(f"Invalid agent selection: {agent}. PID must be numeric.", "error")
            continue
    logger.debug(f"Valid selected agents: {valid_agents}")
    if not valid_agents:
        logger.warning(f"No valid agents selected for action: {action or 'unknown action'}, form data: {request.form}")
        flash(f"No valid agents selected for {action or 'unknown action'}", "error")
        return redirect(url_for('agent.report'))
    ssh_key_path = os.environ.get('SSH_KEY', '/home/maatest/.ssh/id_rsa')
    ssh_user = "oracle"
    user_id = current_user.id
    try:
        private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
    except Exception as e:
        logger.error(f"Failed to load SSH key: {str(e)}")
        flash(f"Failed to load SSH key: {str(e)}", "error")
        return redirect(url_for('agent.report'))
    if action == 'delete':
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        results = []
        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [
                    executor.submit(delete_agent, agent, conn, private_key, ssh_user, user_id)
                    for agent in valid_agents
                ]
                for future in futures:
                    try:
                        result = future.result(timeout=30)
                        results.append(result)
                    except TimeoutError:
                        results.append((False, "Operation timed out"))
                    except Exception as e:
                        results.append((False, str(e)))
            for success, message in results:
                if success:
                    flash(message, "success")
                else:
                    flash(f"Failed to delete agent: {message}", "error")
            conn.commit()
        except oracledb.Error as e:
            conn.rollback()
            logger.error(f"Database error during deletion: {e}")
            flash(f"Database error during deletion: {str(e)}", "error")
        finally:
            conn.close()
    elif action in ['shutdown', 'startup']:
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        results = []
        try:
            stop_monitoring.clear()
            with ThreadPoolExecutor(max_workers=50) as executor:
                action_func = shutdown_agent if action == 'shutdown' else startup_agent
                futures = [
                    executor.submit(action_func, agent, private_key, ssh_user, user_id)
                    for agent in valid_agents
                ]
                for future in futures:
                    try:
                        result = future.result(timeout=30)
                        results.append(result)
                    except TimeoutError:
                        results.append((False, "Operation timed out"))
                    except Exception as e:
                        results.append((False, str(e)))
            for success, message in results:
                if success:
                    flash(message, "success")
                else:
                    flash(f"{action.capitalize()} failed: {message}", "error")
            monitoring_thread = threading.Thread(
                target=monitor_agent_status,
                args=(valid_agents, ssh_key_path, ssh_user, user_id, action, username, password, current_app.config['DB_CONFIG']['dsn'])
            )
            monitoring_thread.start()
            conn.commit()
        except oracledb.Error as e:
            conn.rollback()
            logger.error(f"Database error during {action}: {e}")
            flash(f"Database error during {action}: {str(e)}", "error")
        finally:
            conn.close()
    elif action == 'refresh':
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        results = []
        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [
                    executor.submit(refresh_agent_status, agent, private_key, ssh_user, user_id, conn)
                    for agent in valid_agents
                ]
                for future in futures:
                    try:
                        result = future.result(timeout=30)
                        results.append(result)
                    except TimeoutError:
                        results.append((False, "Operation timed out"))
                    except Exception as e:
                        results.append((False, str(e)))
            for success, message in results:
                if success:
                    flash(message, "success")
                else:
                    flash(f"Status refresh failed: {message}", "error")
            conn.commit()
        except oracledb.Error as e:
            conn.rollback()
            logger.error(f"Database error during refresh: {e}")
            flash(f"Database error during refresh: {str(e)}", "error")
        finally:
            conn.close()
        flash("Status refresh completed for selected agents.", "success")
    else:
        logger.warning(f"Invalid action specified: {action}")
        flash("Invalid action specified", "error")
    return redirect(url_for('agent.report'))

@agent_bp.route('/host/<hostname>')
@login_required
def host_detail(hostname):
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('login'))
    summary_data = []
    total_unregistered = 0
    total_detected = 0
    details_data = []
    filters = {
        'summary_hostname': hostname,
        'details_hostname': hostname,
        'pid': '',
        'port': '',
        'agent_home': '',
        'oms_url': '',
        'snmp_count': '',
        'configured_iloms': '',
        'agent_status': '',
        'install_date': '',
        'total_space': '',
        'cpu_usage': '',
        'memory_usage': '',
        'target_count': '',
        'agent_version': '',
        'oms_version': '',
        'heartbeat_status': '',
        'running_duration': '',
        'last_successful_upload': ''
    }
    try:
        logger.info(f"Starting /agent/host/{hostname} processing")
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        summary_query = """
        WITH agent_counts AS (
            SELECT /*+ MATERIALIZE */
                ahi.hostname,
                SUM(CASE WHEN EXISTS (
                    SELECT 1
                    FROM maamd.ignore_strings_table ist
                    WHERE (ist.hostname = ahi.hostname OR ist.hostname = 'default')
                    AND UPPER(TRIM(ahi.agent_home)) LIKE '%' || UPPER(TRIM(ist.exclude_string)) || '%'
                ) THEN 1 ELSE 0 END) AS known_count,
                SUM(CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM maamd.ignore_strings_table ist
                    WHERE (ist.hostname = ahi.hostname OR ist.hostname = 'default')
                    AND UPPER(TRIM(ahi.agent_home)) LIKE '%' || UPPER(TRIM(ist.exclude_string)) || '%'
                ) THEN 1 ELSE 0 END) AS unregistered_count,
                COUNT(*) AS total_count
            FROM maamd.agent_home_info ahi
            GROUP BY ahi.hostname
        )
        SELECT
            ac.hostname,
            ac.unregistered_count,
            ac.known_count,
            ac.total_count,
            sa.ilom_name AS ilom_hostname
        FROM agent_counts ac
        LEFT JOIN maamd.guests g ON ac.hostname = g.hostname
        LEFT JOIN maamd.system_allocations sa
            ON sa.system_name = COALESCE(g.hypervisor, ac.hostname)
        WHERE ac.hostname NOT LIKE '%celadm%'
            AND ac.hostname = :hostname
        ORDER BY ac.hostname
        """
        cursor.execute(summary_query, {'hostname': hostname.lower()})
        raw_summary_data = cursor.fetchall()
        logger.info(f"Raw summary data for {hostname}: {[(row[0], type(row[1]), row[1], type(row[2]), row[2]) for row in raw_summary_data[:5]]}")
        summary_data = [(row[0], int(row[1]), int(row[2]), int(row[3]), row[4]) for row in raw_summary_data]
        if not summary_data:
            logger.info(f"No summary data found for hostname {hostname}")
            flash("No summary data found for this host.", "info")
            total_unregistered = 0
            total_detected = 0
        else:
            total_unregistered = sum(row[1] for row in summary_data)
            total_detected = sum(row[3] for row in summary_data)
        logger.info(f"Total unregistered: {total_unregistered}, Total detected: {total_detected}")
        details_query = """
        WITH base_info AS (
            SELECT
                ahi.hostname,
                ahi.pid,
                ahi.port,
                ahi.agent_home,
                ahi.oms_url,
                ahi.agent_status,
                ahi.install_date,
                ahi.total_space_mb,
                ahi.cpu_usage_percent,
                ahi.memory_usage_mb,
                ahi.target_count,
                ahi.agent_version,
                ahi.oms_version,
                ahi.heartbeat_status,
                ahi.running_duration_hours / 24 AS running_duration_days,
                ahi.last_successful_upload,
                COALESCE(es.total_errors, 0) AS total_errors
            FROM maamd.agent_home_info ahi
            LEFT JOIN maamd.guests g ON ahi.hostname = g.hostname
            LEFT JOIN (
                SELECT LOWER(TRIM(hostname)) AS hostname, LOWER(TRIM(agent_home)) AS agent_home, SUM(total_occurrences) AS total_errors
                FROM maamd.agent_error_summary
                GROUP BY LOWER(TRIM(hostname)), LOWER(TRIM(agent_home))
            ) es
                ON LOWER(TRIM(es.hostname)) = LOWER(TRIM(ahi.hostname))
               AND LOWER(TRIM(es.agent_home)) = LOWER(TRIM(ahi.agent_home))
            ),
            snmp_counts_base AS (
            SELECT
                sa.ilom_hostname,
                sa.destination_ip,
                sa.port,
                COUNT(*) AS snmp_count
            FROM maamd.snmp_subscriptions sa
            WHERE sa.status != 'disable'
            GROUP BY sa.ilom_hostname, sa.destination_ip, sa.port
            )
        SELECT
            bi.hostname,
            bi.pid,
            bi.port,
            bi.agent_home,
            bi.oms_url,
            bi.agent_status,
            bi.install_date,
            bi.total_space_mb,
            bi.cpu_usage_percent,
            bi.memory_usage_mb,
            bi.target_count,
            bi.agent_version,
            bi.oms_version,
            bi.heartbeat_status,
            bi.running_duration_days,
            bi.last_successful_upload,
            COALESCE(SUM(scb.snmp_count), 0) AS snmp_subscriptions_count,
            bi.total_errors
        FROM base_info bi
        LEFT JOIN snmp_counts_base scb
            ON scb.destination_ip = bi.hostname
           AND scb.port = bi.port
        WHERE bi.hostname = :hostname
        GROUP BY
            bi.hostname,
            bi.pid,
            bi.port,
            bi.agent_home,
            bi.oms_url,
            bi.agent_status,
            bi.install_date,
            bi.total_space_mb,
            bi.cpu_usage_percent,
            bi.memory_usage_mb,
            bi.target_count,
            bi.agent_version,
            bi.oms_version,
            bi.heartbeat_status,
            bi.running_duration_days,
            bi.last_successful_upload,
            bi.total_errors
        ORDER BY bi.hostname, bi.pid
        """
        cursor.execute(details_query, {'hostname': hostname.lower()})
        raw_details_data = cursor.fetchall()
        logger.info(f"Raw details data for {hostname} (first 5 rows): {[(row[0], type(row[1]), row[1], type(row[2]), row[2], type(row[5]), row[5]) for row in raw_details_data[:5]]}")
        if not raw_details_data:
            logger.info(f"No detailed agent data found for hostname {hostname}")
            flash("No detailed agent data found for this host.", "info")
            details_data = []
        else:
            ilom_query = """
            SELECT scb.destination_ip, scb.port, scb.ilom_hostname
            FROM maamd.snmp_subscriptions scb
            WHERE scb.status != 'disable'
            AND scb.destination_ip = :hostname
            """
            cursor.execute(ilom_query, {'hostname': hostname.lower()})
            ilom_data = cursor.fetchall()
            ilom_map = {}
            for dest_ip, port, ilom_hostname in ilom_data:
                key = (dest_ip.lower(), port)
                if key not in ilom_map:
                    ilom_map[key] = []
                ilom_map[key].append(ilom_hostname)
            configured_ilom_query = """
            SELECT aws.hostname, aws.pid, aws.port, ih.hostname AS configured_ilom
            FROM maamd.agent_home_info aws
            CROSS JOIN LATERAL (
                SELECT DISTINCT REGEXP_SUBSTR(
                    (SELECT LISTAGG(scb.ilom_hostname, ',') WITHIN GROUP (ORDER BY scb.ilom_hostname)
                     FROM maamd.snmp_subscriptions scb
                     WHERE scb.destination_ip = aws.hostname
                     AND scb.port = aws.port
                     AND scb.status != 'disable'),
                    '[^,]+', 1, LEVEL
                ) AS ilom_hostname
                FROM DUAL
                CONNECT BY LEVEL <= REGEXP_COUNT(
                    (SELECT LISTAGG(scb.ilom_hostname, ',') WITHIN GROUP (ORDER BY scb.ilom_hostname)
                     FROM maamd.snmp_subscriptions scb
                     WHERE scb.destination_ip = aws.hostname
                     AND scb.port = aws.port
                     AND scb.status != 'disable'),
                    ','
                ) + 1
            ) hids
            LEFT JOIN maamd.ilom_hosts ih
                ON ih.hostname = hids.ilom_hostname
            WHERE ih.hostname IS NOT NULL
            AND aws.hostname = :hostname
            """
            cursor.execute(configured_ilom_query, {'hostname': hostname.lower()})
            configured_ilom_data = cursor.fetchall()
            configured_ilom_map = {}
            for hostname, pid, port, configured_ilom in configured_ilom_data:
                key = (hostname.lower(), pid, port)
                if key not in configured_ilom_map:
                    configured_ilom_map[key] = []
                configured_ilom_map[key].append(configured_ilom)
            details_data = []
            batch_size = 1000
            for batch_start in range(0, len(raw_details_data), batch_size):
                batch = raw_details_data[batch_start:batch_start + batch_size]
                for idx, row in enumerate(batch):
                    hostname, pid, port, agent_home, oms_url, agent_status, install_date, total_space_mb, \
                    cpu_usage_percent, memory_usage_mb, target_count, agent_version, oms_version, \
                    heartbeat_status, running_duration_days, last_successful_upload, snmp_count, total_errors = row
                    logger.debug(f"Raw row sample: hostname={hostname}, agent_home={agent_home}, total_errors={total_errors}, type={type(total_errors)}")
                    if not hostname or not isinstance(hostname, str):
                        logger.warning(f"Invalid hostname for row {idx}: {hostname}")
                        continue
                    if pid is None or not isinstance(pid, (int, str)) or str(pid).strip() == '':
                        logger.warning(f"Invalid pid for row {idx}: {pid}")
                        continue
                    if not agent_home or not isinstance(agent_home, str):
                        logger.warning(f"Invalid agent_home for row {idx}: {agent_home}")
                        continue
                    pid = int(pid) if pid is not None else 0
                    port = int(port) if port is not None else None
                    snmp_count = int(snmp_count or 0)
                    try:
                        cpu_usage_percent = float(cpu_usage_percent) if cpu_usage_percent is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting cpu_usage_percent for hostname {hostname}: value={cpu_usage_percent}, type={type(cpu_usage_percent)}, error={str(e)}")
                        cpu_usage_percent = 'N/A'
                    try:
                        memory_usage_mb = round(float(memory_usage_mb), 2) if memory_usage_mb is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting memory_usage_mb for hostname {hostname}: value={memory_usage_mb}, type={type(memory_usage_mb)}, error={str(e)}")
                        memory_usage_mb = 'N/A'
                    try:
                        target_count = int(target_count) if target_count is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting target_count for hostname {hostname}: value={target_count}, type={type(target_count)}, error={str(e)}")
                        target_count = 'N/A'
                    try:
                        running_duration_days = round(float(running_duration_days), 2) if running_duration_days is not None else 'N/A'
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Error converting running_duration_days for hostname {hostname}: value={running_duration_days}, type={type(running_duration_days)}, error={str(e)}")
                        running_duration_days = 'N/A'
                    last_successful_upload_str = last_successful_upload.strftime("%Y-%m-%d %H:%M:%S") if last_successful_upload else 'N/A'
                    ilom_key = (hostname.lower(), port)
                    ilom_hostnames = ilom_map.get(ilom_key, [])
                    configured_key = (hostname.lower(), pid, port)
                    configured_iloms = configured_ilom_map.get(configured_key, [])
                    if not configured_iloms:
                        configured_iloms = ['None']
                    agent_id = f"{hostname}:{pid}:{agent_home}"
                    logger.debug(f"Created agent_id for row {idx}: {agent_id}")
                    row_tuple = (
                        hostname, pid, port, agent_home, oms_url or 'N/A', snmp_count, configured_iloms, agent_status or 'unknown',
                        install_date, total_space_mb or 'N/A', cpu_usage_percent, memory_usage_mb, target_count,
                        agent_version or 'N/A', oms_version or 'N/A', heartbeat_status or 'N/A', running_duration_days,
                        last_successful_upload_str, total_errors, agent_id
                    )
                    details_data.append(row_tuple)
                    logger.debug(f"Processed row - hostname: {hostname}, row: {row_tuple}")
                for row in details_data[batch_start:batch_start + batch_size]:
                    configured_iloms_len = sum(len(ilom) for ilom in row[6]) if row[6] else 0
                    logger.debug(f"Hostname {row[0]}: configured_iloms length={configured_iloms_len}")
            logger.info(f"Processed details data for {hostname} (first 5 rows): {[(row[0], type(row[1]), row[1], type(row[2]), row[2], type(row[5]), row[5]) for row in details_data[:5]]}")
        cursor.close()
        conn.close()
        if not summary_data and not details_data:
            logger.warning(f"No summary or details data found for hostname {hostname}")
            flash("Host not found or no agent data available.", "error")
            return redirect(url_for('agent.report'))
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        return render_template(
            'agent/report.html',
            summary_data=summary_data,
            total_unregistered=total_unregistered,
            total_detected=total_detected,
            details_data=details_data,
            filters=filters,
            logo_base64=logo_base64,
            oracle_red=oracle_red,
            username=current_user.id
        )
    except oracledb.Error as e:
        logger.error(f"Database error while fetching host details for {hostname}: {e}")
        error_str = str(e)
        error_code = None
        if "ORA-" in error_str:
            try:
                error_code = error_str.split("ORA-")[1].split(":")[0]
            except IndexError:
                error_code = "unknown"
        else:
            error_code = "unknown"
        flash(f"Database error while fetching host details: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/", 'error')
        return redirect(url_for('agent.report'))
    except Exception as e:
        logger.error(f"Unexpected error while fetching host details for {hostname}: {e}\n{traceback.format_exc()}")
        flash(f"Unexpected error: {str(e)}", "error")
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        return render_template('error.html', error_message=str(e), oracle_red=oracle_red, logo_base64=logo_base64), 500

@agent_bp.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('login'))
    try:
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM maamd.ignore_strings_table")
        ignore_count = cursor.fetchone()[0]
        if request.method == 'POST':
            action = request.form.get('action')
            hostname = request.form.get('hostname', '').strip()
            exclude_string = request.form.get('exclude_string', '').strip()
            if not is_valid_fqdn(hostname):
                flash("Hostname must be a valid FQDN or 'default'", "error")
            elif action == "add":
                cursor.execute("INSERT INTO maamd.ignore_strings_table (hostname, exclude_string, created_by, created_date) VALUES (:1, :2, :3, SYSDATE)", (hostname, exclude_string, username))
                conn.commit()
                flash("Entry added successfully", "success")
                cursor.close()
                conn.close()
                return redirect(url_for('agent.manage'))
            elif action == "delete":
                cursor.execute("SELECT created_by FROM maamd.ignore_strings_table WHERE hostname = :1 AND exclude_string = :2", (hostname, exclude_string))
                result = cursor.fetchone()
                if not result:
                    flash("Entry not found", "error")
                elif result[0].lower() != username.lower() and username != current_app.config['DB_CONFIG']['superuser']:
                    flash("You do not have permission to delete this entry", "error")
                else:
                    cursor.execute("DELETE FROM maamd.ignore_strings_table WHERE hostname = :1 AND exclude_string = :2", (hostname, exclude_string))
                    conn.commit()
                    flash("Entry deleted successfully", "success")
                cursor.close()
                conn.close()
                return redirect(url_for('agent.manage'))
        cursor.execute("SELECT hostname, exclude_string, created_by, created_date FROM maamd.ignore_strings_table ORDER BY hostname, exclude_string")
        entries = cursor.fetchall()
        if not entries:
            flash("No ignore strings found in the database.", "info")
        cursor.close()
        conn.close()
        return render_template('agent/manage.html', entries=entries, superuser=current_app.config['DB_CONFIG']['superuser'],
                               logo_base64=current_app.ORACLE_LOGO_BASE64, oracle_red=current_app.ORACLE_RED, username=current_user.id)
    except oracledb.Error as e:
        logger.error(f"Database error in manage: {e}")
        error_str = str(e)
        error_code = None
        if "ORA-" in error_str:
            try:
                error_code = error_str.split("ORA-")[1].split(":")[0]
            except IndexError:
                error_code = "unknown"
        else:
            error_code = "unknown"
        flash(f"Database error: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/", "error")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Unexpected error in manage: {e}\n{traceback.format_exc()}")
        flash(f"Unexpected error: {str(e)}", "error")
        return redirect(url_for('login'))

@agent_bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    hostname = request.args.get('hostname')
    exclude_string = request.args.get('exclude_string')
    if not hostname or not exclude_string:
        flash("Hostname and exclude string are required", "error")
        return redirect(url_for('agent.manage'))
    decoded_hostname = unquote(hostname).strip()
    decoded_exclude_string = unquote(exclude_string).strip()
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('login'))
    try:
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        query = "SELECT created_by FROM maamd.ignore_strings_table WHERE hostname = :1 AND exclude_string = :2"
        cursor.execute(query, (decoded_hostname, decoded_exclude_string))
        result = cursor.fetchone()
        if not result:
            flash("Entry not found", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('agent.manage'))
        created_by = result[0]
        if decoded_hostname.lower() == "default" and created_by != current_user.id and current_user.id != current_app.config['DB_CONFIG']['superuser']:
            flash("You do not have permission to edit default entries created by another user", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('agent.manage'))
        if request.method == 'POST':
            new_hostname = request.form.get('hostname', '').strip()
            new_exclude_string = request.form.get('exclude_string', '').strip()
            if not is_valid_fqdn(new_hostname):
                flash("Hostname must be a valid FQDN or 'default'", "error")
            else:
                cursor.execute("UPDATE maamd.ignore_strings_table SET hostname = :1, exclude_string = :2 WHERE hostname = :3 AND exclude_string = :4",
                               (new_hostname, new_exclude_string, decoded_hostname, decoded_exclude_string))
                conn.commit()
                flash("Entry updated successfully", "success")
                cursor.close()
                conn.close()
                return redirect(url_for('agent.manage'))
        cursor.close()
        conn.close()
        return render_template('agent/edit.html', hostname=decoded_hostname, exclude_string=decoded_exclude_string,
                               logo_base64=current_app.ORACLE_LOGO_BASE64, oracle_red=current_app.ORACLE_RED, username=current_user.id)
    except oracledb.Error as e:
        logger.error(f"Database error in edit: {e}")
        error_str = str(e)
        error_code = None
        if "ORA-" in error_str:
            try:
                error_code = error_str.split("ORA-")[1].split(":")[0]
            except IndexError:
                error_code = "unknown"
        else:
            error_code = "unknown"
        flash(f"Database error: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/", "error")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Unexpected error in edit: {e}\n{traceback.format_exc()}")
        flash(f"Unexpected error: {str(e)}", "error")
        return redirect(url_for('login'))

@agent_bp.route('/agent_home_detail', methods=['GET'])
@login_required
def agent_home_detail():
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('agent.report'))
    hostname = request.args.get('hostname', '').strip()
    port_str = request.args.get('port', '').strip()
    pid_str = request.args.get('pid', '').strip()
    agent_home_encoded = request.args.get('agent_home', '').strip()
    agent_home = unquote(agent_home_encoded)
    if not hostname or not agent_home:
        logger.info(f"Missing required parameters: hostname={hostname}, agent_home={agent_home}")
        flash("Hostname and agent_home are required.", "error")
        return redirect(url_for('agent.report'))
    try:
        port = int(port_str) if port_str else None
        pid = int(pid_str) if pid_str else None
    except ValueError:
        logger.warning(f"Invalid port or pid: port={port_str}, pid={pid_str}")
        flash("Invalid port or pid: both must be numeric.", "error")
        return redirect(url_for('agent.report'))
    logger.debug(f"Parameters: hostname={hostname}, port={port}, pid={pid}, agent_home={agent_home}")
    try:
        logger.info(f"Starting /agent/agent_home_detail processing for hostname={hostname}, port={port}, pid={pid}, agent_home={agent_home}")
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        if pid is None or port is None:
            lookup_query = """
            SELECT pid, port
            FROM maamd.agent_home_info
            WHERE LOWER(TRIM(hostname)) = LOWER(:hostname)
                AND LOWER(TRIM(agent_home)) = LOWER(:agent_home)
            """
            cursor.execute(lookup_query, {'hostname': hostname, 'agent_home': agent_home})
            lookup_row = cursor.fetchone()
            if lookup_row:
                pid = lookup_row[0]
                port = lookup_row[1]
                logger.info(f"Retrieved missing pid={pid}, port={port} for {hostname}:{agent_home}")
            else:
                logger.warning(f"Agent home not found for hostname={hostname}, agent_home={agent_home}")
                flash(f"Agent not found for hostname={hostname}, agent_home={agent_home}.", "error")
                cursor.close()
                conn.close()
                return redirect(url_for('agent.report'))
        agent_query = """
        SELECT
            hostname,
            pid,
            port,
            agent_home,
            oms_url,
            agent_status,
            install_date,
            total_space_mb,
            cpu_usage_percent,
            memory_usage_mb,
            target_count,
            agent_version,
            oms_version,
            heartbeat_status,
            running_duration_hours / 24 AS running_duration_days,
            last_successful_upload,
            last_attempted_upload
        FROM maamd.agent_home_info
        WHERE LOWER(TRIM(hostname)) = LOWER(TRIM(:hostname))
            AND port = :port
            AND pid = :pid
            AND LOWER(TRIM(agent_home)) = LOWER(TRIM(:agent_home))
        """
        logger.debug(f"Executing agent query with hostname={hostname}, port={port}, pid={pid}, agent_home={agent_home}")
        cursor.execute(agent_query, {'hostname': hostname, 'port': port, 'pid': pid, 'agent_home': agent_home})
        agent_data = cursor.fetchone()
        if not agent_data:
            logger.warning(f"Agent home not found for hostname={hostname}, port={port}, pid={pid}, agent_home={agent_home}")
            flash(f"Agent not found for hostname={hostname}, port={port}, pid={pid}, agent_home={agent_home}.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('agent.report'))
        logger.info(f"Agent data retrieved: {agent_data}")
        hostname, pid, port, agent_home, oms_url, agent_status, install_date, total_space_mb, \
        cpu_usage_percent, memory_usage_mb, target_count, agent_version, oms_version, \
        heartbeat_status, running_duration_days, last_successful_upload, last_attempted_upload = agent_data
        try:
            cpu_usage_percent = float(cpu_usage_percent) if cpu_usage_percent is not None else 'N/A'
        except (ValueError, TypeError) as e:
            logger.debug(f"Error converting cpu_usage_percent for hostname {hostname}: value={cpu_usage_percent}, type={type(cpu_usage_percent)}, error={str(e)}")
            cpu_usage_percent = 'N/A'
        try:
            memory_usage_mb = round(float(memory_usage_mb), 2) if memory_usage_mb is not None else 'N/A'
        except (ValueError, TypeError) as e:
            logger.debug(f"Error converting memory_usage_mb for hostname {hostname}: value={memory_usage_mb}, type={type(memory_usage_mb)}, error={str(e)}")
            memory_usage_mb = 'N/A'
        try:
            target_count = int(target_count) if target_count is not None else 'N/A'
        except (ValueError, TypeError) as e:
            logger.debug(f"Error converting target_count for hostname {hostname}: value={target_count}, type={type(target_count)}, error={str(e)}")
            target_count = 'N/A'
        try:
            running_duration_days = round(float(running_duration_days), 2) if running_duration_days is not None else 'N/A'
        except (ValueError, TypeError) as e:
            logger.debug(f"Error converting running_duration_days for hostname {hostname}: value={running_duration_days}, type={type(running_duration_days)}, error={str(e)}")
            running_duration_days = 'N/A'
        last_successful_upload_str = last_successful_upload.strftime("%Y-%m-%d %H:%M:%S") if last_successful_upload else 'N/A'
        last_attempted_upload_str = last_attempted_upload.strftime("%Y-%m-%d %H:%M:%S") if last_attempted_upload else 'N/A'
        agent_details = {
            'hostname': hostname,
            'pid': int(pid) if pid is not None else 0,
            'port': int(port) if port is not None else None,
            'agent_home': agent_home,
            'oms_url': oms_url or 'N/A',
            'agent_status': agent_status or 'unknown',
            'install_date': install_date or 'N/A',
            'total_space_mb': total_space_mb or 'N/A',
            'cpu_usage_percent': cpu_usage_percent,
            'memory_usage_mb': memory_usage_mb,
            'target_count': target_count,
            'agent_version': agent_version or 'N/A',
            'oms_version': oms_version or 'N/A',
            'heartbeat_status': heartbeat_status or 'N/A',
            'running_duration_days': running_duration_days,
            'last_successful_upload': last_successful_upload_str,
            'last_attempted_upload': last_attempted_upload_str
        }
        logger.info(f"Agent details prepared for rendering: {agent_details}")
        errors_query = """
        SELECT error_message, latest_timestamp AS error_time, error_hash, total_occurrences AS occurrence_count
        FROM maamd.agent_error_summary
        WHERE LOWER(TRIM(hostname)) = LOWER(TRIM(:hostname))
            AND LOWER(TRIM(agent_home)) = LOWER(TRIM(:agent_home))
        ORDER BY total_occurrences DESC
        """
        if ERROR_COUNT_LIMIT > 0:
            errors_query += f" FETCH FIRST {ERROR_COUNT_LIMIT} ROWS ONLY"
        logger.debug(f"Executing errors query with hostname={hostname}, agent_home={agent_home}, limit={ERROR_COUNT_LIMIT if ERROR_COUNT_LIMIT > 0 else 'all'}")
        cursor.execute(errors_query, {'hostname': hostname, 'agent_home': agent_home})
        log_errors = cursor.fetchall()
        logger.debug(f"Log errors retrieved: {log_errors}")
        if not log_errors:
            logger.warning(f"No errors found in maamd.agent_error_summary for hostname={hostname}, agent_home={agent_home}")
        total_errors_query = """
        SELECT COUNT(*) AS unique_errors
        FROM maamd.agent_error_summary
        WHERE LOWER(TRIM(hostname)) = LOWER(TRIM(:hostname))
            AND LOWER(TRIM(agent_home)) = LOWER(TRIM(:agent_home))
        """
        cursor.execute(total_errors_query, {'hostname': hostname, 'agent_home': agent_home})
        total_unique_errors = cursor.fetchone()[0]
        logger.info(f"Total unique errors for hostname={hostname}, agent_home={agent_home}: {total_unique_errors}")
        log_errors_data = []
        for error_message, error_time, error_hash, occurrence_count in log_errors:
            error_time_str = error_time.strftime("%Y-%m-%dT%H:%M:%S") if error_time else "N/A"
            log_errors_data.append({
                'error_message': error_message,
                'error_time': error_time_str,
                'error_hash': error_hash,
                'occurrence_count': occurrence_count,
                'oms_url': oms_url or "N/A",
                'sample_error': error_message
            })
        logger.debug(f"Processed log errors data: {log_errors_data}")
        cursor.close()
        conn.close()
        logger.debug(f"Passing {len(log_errors_data)} errors to agent_home_detail.html for rendering (out of {total_unique_errors} unique errors)")
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        logger.info(f"Rendering agent_home_detail.html with log_errors_data: {log_errors_data}")
        return render_template(
            'agent/agent_home_detail.html',
            title="Agent Home Detail",
            agent_details=agent_details,
            log_errors=log_errors_data,
            logo_base64=logo_base64,
            oracle_red=oracle_red,
            username=current_user.id,
            pid=pid,
            timestamp=datetime.now().strftime('%Y%m%d%H%M%S')
        )
    except oracledb.Error as e:
        logger.error(f"Database error while fetching agent home details: {e}")
        error_str = str(e)
        error_code = None
        if "ORA-" in error_str:
            try:
                error_code = error_str.split("ORA-")[1].split(":")[0]
            except IndexError:
                error_code = "unknown"
        else:
            error_code = "unknown"
        flash(f"Database error while fetching agent home details: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/", "error")
        return redirect(url_for('agent.report'))
    except Exception as e:
        logger.error(f"Unexpected error in /agent/agent_home_detail: {e}\n{traceback.format_exc()}")
        flash(f"Unexpected error: {str(e)}", "error")
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        return render_template('error.html', error_message=str(e), oracle_red=oracle_red, logo_base64=logo_base64), 500

@agent_bp.route('/errors/<hostname>', methods=['GET'])
@login_required
def view_all_errors(hostname):
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        flash(str(e), "error")
        return redirect(url_for('agent.report'))
    agent_home = request.args.get('agent_home', '').strip()
    error_message = request.args.get('error_message', '').strip()
    error_message_hash = request.args.get('error_message_hash', '').strip()
    pid = request.args.get('pid', '').strip()
    if not agent_home or not error_message or not error_message_hash or not pid:
        logger.info(f"Missing parameters for /agent/errors/{hostname}: agent_home={agent_home}, error_message={error_message}, error_message_hash={error_message_hash}, pid={pid}")
        flash("Missing parameters for viewing errors.", "error")
        return redirect(url_for('agent.report'))
    try:
        logger.info(f"Starting /agent/errors/{hostname} processing for error_message={error_message}")
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        errors_query = """
        SELECT error_message, latest_timestamp AS error_time, total_occurrences AS occurrence_count
        FROM maamd.agent_error_summary
        WHERE LOWER(TRIM(hostname)) = LOWER(TRIM(:hostname))
            AND LOWER(TRIM(agent_home)) = LOWER(TRIM(:agent_home))
            AND error_hash = :error_message_hash
        ORDER BY occurrence_count DESC
        """
        logger.debug(f"Executing errors query with hostname={hostname}, agent_home={agent_home}, error_message_hash={error_message_hash}")
        cursor.execute(errors_query, {'hostname': hostname, 'agent_home': agent_home, 'error_message_hash': error_message_hash})
        all_errors = cursor.fetchall()
        logger.debug(f"All errors retrieved: {all_errors}")
        error_details = [
            {
                'error_message': row[0],
                'error_time': row[1].strftime("%Y-%m-%dT%H:%M:%S") if row[1] else "N/A",
                'occurrence_count': row[2],
                'oms_url': "N/A"
            }
            for row in all_errors
        ]
        cursor.close()
        conn.close()
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        logger.info(f"Rendering error_details.html with error_details: {error_details}")
        return render_template(
            'agent/error_details.html',
            title=f"Error Details for {hostname}",
            hostname=hostname,
            agent_home=agent_home,
            error_message=error_message,
            error_details=error_details,
            logo_base64=logo_base64,
            oracle_red=oracle_red,
            username=current_user.id,
            pid=pid,
            timestamp=datetime.now().strftime('%Y%m%d%H%M%S')
        )
    except oracledb.Error as e:
        logger.error(f"Database error while fetching error details: {e}")
        error_str = str(e)
        error_code = "unknown" if "ORA-" not in error_str else error_str.split("ORA-")[1].split(":")[0]
        flash(f"Database error while fetching error details: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/", "error")
        return redirect(url_for('agent.report'))
    except Exception as e:
        logger.error(f"Unexpected error in /agent/errors: {e}\n{traceback.format_exc()}")
        flash(f"Unexpected error: {str(e)}", "error")
        oracle_red = getattr(current_app, 'ORACLE_RED', '#FF0000')
        logo_base64 = getattr(current_app, 'ORACLE_LOGO_BASE64', '')
        return render_template('error.html', error_message=str(e), oracle_red=oracle_red, logo_base64=logo_base64), 500

@agent_bp.route('/error_summary', methods=['GET'])
@login_required
def error_summary_legacy():
    return redirect(url_for('agent.error_summary'))

@agent_bp.route('/error_summary_data', methods=['GET'])
@login_required
def error_summary_data_legacy():
    return redirect(url_for('agent.error_summary_data'))

@agent_bp.route('/ilom_detail', methods=['GET'])
@login_required
def ilom_detail():
    try:
        username, password = get_db_credentials()
    except ValueError as e:
        logger.info(f"Failed to retrieve DB credentials for user {current_user.id}")
        return jsonify({'error': 'Failed to retrieve DB credentials'}), 401
    ilom_hostname = request.args.get('ilom_hostname', '').strip()
    if not ilom_hostname:
        logger.warning("Missing ilom_hostname parameter")
        return jsonify({'error': 'ILOM hostname is required'}), 400
    try:
        logger.info(f"Starting /agent/ilom_detail for ilom_hostname={ilom_hostname}")
        conn = get_db_connection(username, password, current_app.config['DB_CONFIG']['dsn'])
        cursor = conn.cursor()
        ilom_query = """
        SELECT hostname, ilom_ip
        FROM maamd.ilom_hosts
        WHERE LOWER(TRIM(hostname)) = LOWER(TRIM(:ilom_hostname))
        """
        logger.debug(f"Executing ILOM query with ilom_hostname={ilom_hostname}")
        cursor.execute(ilom_query, {'ilom_hostname': ilom_hostname})
        ilom_data = cursor.fetchone()
        cursor.close()
        conn.close()
        if not ilom_data:
            logger.warning(f"No ILOM data found for hostname={ilom_hostname}")
            return jsonify({'error': f"ILOM not found for hostname={ilom_hostname}"}), 404
        ilom_details = {
            'ilom_hostname': ilom_data[0],
            'ilom_ip': ilom_data[1] or 'N/A'
        }
        logger.info(f"ILOM details retrieved: {ilom_details}")
        return jsonify(ilom_details)
    except oracledb.Error as e:
        logger.error(f"Database error in ilom_detail: {e}")
        error_str = str(e)
        error_code = "unknown" if "ORA-" not in error_str else error_str.split("ORA-")[1].split(":")[0]
        return jsonify({'error': f"Database error: {error_str}\nHelp: https://docs.oracle.com/error-help/db/ora-{error_code}/"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in ilom_detail: {e}\n{traceback.format_exc()}")
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500
