# Filename: job_routes.py
# Version: 2026-06-02 v1.0.84
# Changes: Normalize empty or "none" script_parameters to NULL in add_job() and edit_job() so no parameters are stored/passed as the literal string "none".
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session, send_file, Response, jsonify
from flask_login import login_required, current_user
from apscheduler.triggers.cron import CronTrigger
from apscheduler.schedulers.base import SchedulerNotRunningError
import oracledb
from datetime import datetime, timedelta
import time
import os
import traceback
from maa_unified_app import run_script
from maa_scheduler import safe_restart_scheduler, get_scheduler
from maa_libraries import logger
from environment_setup_functions import execute_function
job_bp = Blueprint('jobs', __name__, template_folder='templates')
def detect_dependency_cycle(job_id, parent_job_id, conn):
    if not parent_job_id:
        return False
    cursor = conn.cursor()
    try:
        visited = set()
        current_id = parent_job_id
        while current_id:
            if current_id == job_id or (job_id is None and current_id in visited):
                logger.error("Circular dependency detected involving job_id %s", job_id or 'new')
                return True
            if current_id in visited:
                break
            visited.add(current_id)
            cursor.execute("SELECT PARENT_JOB_ID FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID = :1", (current_id,))
            result = cursor.fetchone()
            current_id = result[0] if result else None
        return False
    finally:
        cursor.close()
def set_job_lock(job_id, script_name, conn):
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM MAAMD.JOB_LOCKS WHERE JOB_ID = :1", (job_id,))
        cursor.execute(
            "INSERT INTO MAAMD.JOB_LOCKS (JOB_ID, SCRIPT_NAME, START_TIME, IS_RUNNING) VALUES (:1, :2, SYSTIMESTAMP, 'Y')",
            (job_id, script_name)
        )
        conn.commit()
        logger.debug("Lock set for job %d (%s)", job_id, script_name)
    finally:
        cursor.close()
def clear_job_lock(job_id, conn):
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM MAAMD.JOB_LOCKS WHERE JOB_ID = :1", (job_id,))
        conn.commit()
        logger.debug("Lock cleared for job %d", job_id)
    finally:
        cursor.close()
def is_job_running(job_id, conn):
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT IS_RUNNING FROM MAAMD.JOB_LOCKS WHERE JOB_ID = :1 AND IS_RUNNING = 'Y'",
            (job_id,)
        )
        result = cursor.fetchone()
        is_running = result is not None
        logger.debug("Job %d lock status: %s", job_id, 'Running' if is_running else 'Not running')
        return is_running
    except oracledb.Error as e:
        logger.error("Error checking job lock for job_id %d: %s", job_id, str(e))
        return False
    finally:
        cursor.close()
@job_bp.route('/scheduled_jobs')
@login_required
def scheduled_jobs():
    logger.info("Starting scheduled_jobs route for user %s", current_user.id)
    start_time = time.time()
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                logger.debug("Acquiring database connection, attempt %d", attempt + 1)
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash("Database connection failed. Please try again later.", "error")
                    return render_template(
                        'jobs/scheduled_jobs.html',
                        jobs=[],
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=datetime.now().strftime('%Y%m%d%H%M%S'),
                        scheduler_running=False,
                        overdue_count=0
                    ), 500
        cursor = conn.cursor()
        # === CLEANUP STUCK LOCKS (fixes "always shows Running" after restart) ===
        cursor.execute("DELETE FROM MAAMD.JOB_LOCKS WHERE IS_RUNNING = 'Y'")
        conn.commit()
        logger.debug("Cleared any stale JOB_LOCKS rows on page load")
        logger.debug("Executing jobs query")
        query_start = time.time()
        cursor.execute(
            """
            SELECT
                sj.JOB_ID,
                sj.SCRIPT_NAME,
                sj.DISPLAY_NAME,
                sj.SCRIPT_PATH,
                sj.SCRIPT_PARAMETERS,
                sj.LOG_FILE,
                sj.SCHEDULE_INTERVAL_MINUTES,
                sj.CRON_SCHEDULE,
                sj.PARENT_JOB_ID,
                jh.RUN_TIME AS LAST_RUN,
                jh.STATUS AS LAST_STATUS,
                jh.EXIT_CODE,
                p.SCRIPT_NAME AS PARENT_NAME,
                (SELECT COUNT(*)
                 FROM MAAMD.JOB_LOCKS jl
                 WHERE jl.JOB_ID = sj.JOB_ID AND jl.IS_RUNNING = 'Y') AS IS_RUNNING
            FROM MAAMD.SCHEDULED_JOBS sj
            LEFT JOIN (
                SELECT JOB_ID, RUN_TIME, STATUS, EXIT_CODE
                FROM MAAMD.JOB_HISTORY
                WHERE (JOB_ID, RUN_TIME) IN (
                    SELECT JOB_ID, MAX(RUN_TIME)
                    FROM MAAMD.JOB_HISTORY
                    GROUP BY JOB_ID
                )
            ) jh ON sj.JOB_ID = jh.JOB_ID
            LEFT JOIN MAAMD.SCHEDULED_JOBS p ON sj.PARENT_JOB_ID = p.JOB_ID
            WHERE ROWNUM <= 100
            """
        )
        jobs = cursor.fetchall()
        query_duration = time.time() - query_start
        logger.info("Fetched %d scheduled jobs in %.2f seconds", len(jobs), query_duration)
        job_list = []
        overdue_count = 0
        for row in jobs:
            try:
                job_id, script_name, display_name, script_path, script_parameters, log_file, interval, cron_schedule, parent_job_id, last_run, last_status, exit_code, parent_name, is_running = row
                if job_id is None:
                    logger.warning("Skipping job with NULL job_id: script_name=%s", script_name)
                    continue
                logger.debug("Processing job_id=%d, script_name=%s, display_name=%s",
                             job_id, script_name, display_name)
                job = {
                    'job_id': job_id,
                    'script_name': script_name or 'Unknown',
                    'display_name': display_name or script_name,
                    'script_path': script_path or 'N/A',
                    'script_parameters': script_parameters or '',
                    'log_file': log_file or 'N/A',
                    'schedule_interval': interval,
                    'cron_schedule': cron_schedule,
                    'parent_job_id': parent_job_id,
                    'last_run': last_run.strftime('%Y-%m-%d %H:%M:%S') if last_run else None,
                    'parent_name': parent_name if parent_name else f'Job ID {parent_job_id}' if parent_job_id else None,
                    'is_running': is_running > 0 if is_running is not None else False,
                    'last_status': last_status,
                    'exit_code': exit_code,
                    'script_path_invalid': False
                }
                if not script_path.startswith('PLSQL:') and not script_path.startswith('FUNCTION:'):
                    script_base_path = script_path.split()[0] if script_parameters else script_path
                    if not os.path.exists(script_base_path):
                        job['script_path_invalid'] = True
                        logger.warning("Invalid script path %s for job %d (%s)", script_base_path, job_id, script_name)
                if job['is_running']:
                    job['status'] = 'Running'
                elif job['last_status'] == 'Failed' or (job['exit_code'] is not None and job['exit_code'] != 0):
                    job['status'] = 'Last Run Failed'
                else:
                    job['status'] = 'Not Running'
                if job['parent_job_id']:
                    job['next_run'] = 'After ' + (job['parent_name'] or f'Job ID {parent_job_id}')
                elif job['cron_schedule']:
                    try:
                        trigger = CronTrigger.from_crontab(job['cron_schedule'], timezone='UTC')
                        next_run = trigger.get_next_fire_time(None, datetime.now()).strftime('%Y-%m-%d %H:%M:%S')
                        job['next_run'] = next_run
                    except ValueError:
                        job['next_run'] = 'Invalid Cron'
                elif job['last_run'] and job['schedule_interval']:
                    last_run_dt = datetime.strptime(job['last_run'], '%Y-%m-%d %H:%M:%S')
                    next_run = last_run_dt + timedelta(minutes=job['schedule_interval'])
                    job['next_run'] = next_run.strftime('%Y-%m-%d %H:%M:%S')
                    time_since_last_run = (datetime.now() - last_run_dt).total_seconds() / 60
                    max_expected_interval = job['schedule_interval'] + 5
                    if time_since_last_run > max_expected_interval:
                        logger.warning("Job %s is overdue: last_run=%s, interval=%dm, time_since=%.2fm",
                                       job['script_name'], job['last_run'], job['schedule_interval'], time_since_last_run)
                        overdue_count += 1
                else:
                    job['next_run'] = None
                job_list.append(job)
                logger.debug("Added job to job_list: %s", job)
            except Exception as e:
                logger.error("Error processing job row %s: %s", row, str(e), exc_info=True)
                continue
        # === ALPHABETICAL SORT BY DISPLAY NAME ===
        job_list = sorted(job_list, key=lambda x: x['display_name'].lower())
        logger.info("Processed %d jobs (overdue: %d) for display in %.2f seconds", len(job_list), overdue_count, time.time() - start_time)
        scheduler_running = get_scheduler().running
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        logger.debug("Rendering scheduled_jobs.html with %d jobs", len(job_list))
        response = render_template(
            'jobs/scheduled_jobs.html',
            jobs=job_list,
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=timestamp,
            scheduler_running=scheduler_running,
            overdue_count=overdue_count
        )
        logger.info("Completed scheduled_jobs route in %.2f seconds", time.time() - start_time)
        return response
    except oracledb.Error as e:
        error_str = str(e)
        logger.error("Database error in scheduled_jobs: %s", error_str, exc_info=True)
        flash(f"Database error: {error_str}", "error")
        return render_template(
            'jobs/scheduled_jobs.html',
            jobs=[],
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=datetime.now().strftime('%Y%m%d%H%M%S'),
            scheduler_running=False,
            overdue_count=0
        ), 500
    except Exception as e:
        logger.error("Unexpected error in scheduled_jobs: %s", str(e), exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        return render_template(
            'jobs/scheduled_jobs.html',
            jobs=[],
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=datetime.now().strftime('%Y%m%d%H%M%S'),
            scheduler_running=False,
            overdue_count=0
        ), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
        logger.debug("Released database resources for scheduled_jobs")
@job_bp.route('/stream_job_output/<int:job_id>')
@login_required
def stream_job_output(job_id):
    conn = None
    cursor = None
    log_file = None
    try:
        conn = current_app.config['DB_POOL'].acquire()
        cursor = conn.cursor()
        cursor.execute("SELECT LOG_FILE FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID = :1", (job_id,))
        result = cursor.fetchone()
        if result and result[0]:
            log_file = result[0]
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
    def event_stream():
        logger.info("SSE STARTED for job_id=%s, log_file=%s", job_id, log_file)
        if not log_file:
            logger.error("No log_file for job_id=%s", job_id)
            yield "data: [ERROR] Log file not found for this job\n\n"
            return
        if not os.path.exists(log_file):
            logger.warning("Log file does not exist yet for job_id=%s", job_id)
            yield "data: [INFO] Waiting for log file to be created...\n\n"
            time.sleep(1)
            return
        yield f"data: [Live Output Started - Job ID {job_id}]\n\n"
        with open(log_file, 'r') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    yield f"data: {line.strip()}\n\n"
                else:
                    time.sleep(0.3)
    return Response(event_stream(), mimetype="text/event-stream")
@job_bp.route('/run_job/<int:job_id>', methods=['POST'])
@login_required
def run_job(job_id):
    logger.info("Triggering job %d via POST, user=%s", job_id, current_user.id)
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT SCRIPT_NAME, SCRIPT_PATH, SCRIPT_PARAMETERS, LOG_FILE FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID = :1",
            (job_id,)
        )
        result = cursor.fetchone()
        if not result:
            flash("Job not found", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
        script_name, script_path, script_parameters, log_file = result
        logger.debug("Validating job %d: script_name=%s, script_path=%s, log_file=%s",
                     job_id, script_name, script_path, log_file)
        if is_job_running(job_id, conn):
            flash(f"Job '{script_name}' is already running", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
        if script_path and script_path.startswith('FUNCTION:'):
            func_name = script_path[9:].strip()
            logger.info("Detected special function job: %s (job_id=%d)", func_name, job_id)
            import config
            safe_log_dir = config.OUTPUT_DIR
            os.makedirs(safe_log_dir, exist_ok=True)
            log_file = os.path.join(safe_log_dir, "maa_falcon_all.log")
            with open(log_file, 'w') as f:
                f.write(f"=== {script_name} started at {datetime.now()} ===\n")
                f.write(f"Function: {func_name}\n")
                f.write("="*80 + "\n\n")
            logger.info("Created log file for FUNCTION job: %s", log_file)
            cursor.execute(
                "UPDATE MAAMD.SCHEDULED_JOBS SET LOG_FILE = :1 WHERE JOB_ID = :2",
                (log_file, job_id)
            )
            conn.commit()
            logger.info("Updated DB LOG_FILE for job %d to forced path", job_id)
            set_job_lock(job_id, script_name, conn)
            task_id = f"manual_function_{job_id}_{datetime.now().timestamp()}"
            try:
                result_output = execute_function(
                    component_name='global',
                    func_name=func_name,
                    params=script_parameters,
                    pool=current_app.config['DB_POOL'],
                    app=current_app._get_current_object(),
                    socketio=getattr(current_app, 'socketio', None),
                    sid=None,
                    task_id=task_id
                )
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write("\n" + "="*80 + "\n")
                        f.write(str(result_output) + "\n")
                        f.write("="*80 + "\n")
                cursor.execute(
                    "INSERT INTO MAAMD.JOB_HISTORY (JOB_ID, RUN_TIME, STATUS, EXIT_CODE, TRIGGERED_BY) VALUES (:1, CURRENT_TIMESTAMP, 'Completed', 0, :2)",
                    (job_id, current_user.id)
                )
                conn.commit()
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'status': 'success',
                        'message': f"Function '{func_name}' triggered successfully",
                        'job_id': job_id
                    })
                flash(f"Function '{func_name}' triggered successfully", "success")
                return redirect(url_for('jobs.scheduled_jobs'))
            except Exception as e:
                logger.error("Failed to execute function %s: %s", func_name, str(e), exc_info=True)
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write(f"\nERROR: {str(e)}\n")
                cursor.execute(
                    "INSERT INTO MAAMD.JOB_HISTORY (JOB_ID, RUN_TIME, STATUS, EXIT_CODE, TRIGGERED_BY, ERROR_MESSAGE) VALUES (:1, CURRENT_TIMESTAMP, 'Failed', 1, :2, :3)",
                    (job_id, current_user.id, str(e)[:4000])
                )
                conn.commit()
                flash(f"Failed to trigger function: {str(e)}", "error")
                return redirect(url_for('jobs.scheduled_jobs'))
            finally:
                clear_job_lock(job_id, conn)
        if not script_path.startswith('PLSQL:'):
            script_base_path = script_path.split()[0] if script_parameters else script_path
            if not os.path.exists(script_base_path):
                flash(f"Invalid script path '{script_base_path}' for job '{script_name}'. Please edit the job.", "error")
                logger.error("Script path %s for job %d (%s) does not exist", script_base_path, job_id, script_name)
                return redirect(url_for('jobs.scheduled_jobs'))
            if not os.access(script_base_path, os.X_OK):
                flash(f"Script '{script_base_path}' is not executable for job '{script_name}'. Please check permissions.", "error")
                logger.error("Script %s for job %d (%s) is not executable", script_base_path, job_id, script_name)
                return redirect(url_for('jobs.scheduled_jobs'))
        if not get_scheduler().running:
            logger.warning("Scheduler is not running, attempting to start")
            try:
                safe_restart_scheduler()
                logger.info("Scheduler started successfully for job %d", job_id)
            except Exception as e:
                logger.error("Failed to start scheduler for job %d: %s", job_id, str(e), exc_info=True)
                flash(f"Failed to start scheduler: {str(e)}", "error")
                return redirect(url_for('jobs.scheduled_jobs'))
        job_id_str = f"manual_{job_id}_{datetime.now().timestamp()}"
        try:
            get_scheduler().add_job(
                func=run_script,
                args=[script_name, job_id],
                trigger='date',
                run_date=datetime.now(),
                id=job_id_str,
                name=script_name,
                replace_existing=True
            )
            logger.info("User %s manually triggered job %d (%s) with job_id %s",
                        current_user.id, job_id, script_name, job_id_str)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'message': f"Job '{script_name}' triggered successfully",
                    'job_id': job_id
                })
            flash(f"Job '{script_name}' triggered successfully", "success")
            return redirect(url_for('jobs.scheduled_jobs'))
        except SchedulerNotRunningError as e:
            logger.error("Scheduler not running when adding job %d (%s): %s", job_id, script_name, str(e))
            flash("Scheduler is not running, job not triggered", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
        except Exception as e:
            logger.error("Failed to schedule manual job %d (%s): %s", job_id, script_name, str(e), exc_info=True)
            flash(f"Failed to trigger job: {str(e)}", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
    except oracledb.Error as e:
        logger.error("Database error in run_job: %s\n%s", str(e), traceback.format_exc())
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    except Exception as e:
        logger.error("Unexpected error in run_job: %s\n%s", str(e), traceback.format_exc())
        flash(f"Unexpected error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
        logger.debug("Released database resources for run_job")
@job_bp.route('/view_log/<script_name>')
@login_required
def view_log(script_name):
    logger.info("Accessing view_log for script %s, user=%s", script_name, current_user.id)
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute("SELECT LOG_FILE FROM MAAMD.SCHEDULED_JOBS WHERE SCRIPT_NAME = :1", (script_name,))
        result = cursor.fetchone()
        if not result:
            logger.warning("No job found with script name %s", script_name)
            flash(f"No job found with script name {script_name}", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
        log_file = result[0]
        log_content = "Log file not found or empty."
        if log_file and os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                logger.info("Successfully read log file %s for script %s", log_file, script_name)
            except Exception as e:
                logger.error("Error reading log file %s: %s", log_file, str(e))
                flash(f"Error reading log file: {str(e)}", "error")
                log_content = "Unable to read log file."
        else:
            logger.warning("Log file %s does not exist for script %s", log_file, script_name)
            flash(f"Log file {log_file} does not exist.", "error")
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return render_template(
            'jobs/view_log.html',
            script_name=script_name,
            log_content=log_content,
            log_file=log_file,
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=timestamp
        )
    except oracledb.Error as e:
        logger.error("Database error in view_log: %s", str(e))
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
@job_bp.route('/download_log/<script_name>')
@login_required
def download_log(script_name):
    logger.info("Accessing download_log for script %s, user=%s", script_name, current_user.id)
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute("SELECT LOG_FILE FROM MAAMD.SCHEDULED_JOBS WHERE SCRIPT_NAME = :1", (script_name,))
        result = cursor.fetchone()
        if not result:
            logger.warning("No job found with script name %s", script_name)
            flash(f"No job found with script name {script_name}", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
        log_file = result[0]
        if not log_file or not os.path.exists(log_file):
            logger.warning("Log file %s does not exist for script %s", log_file, script_name)
            flash(f"Log file {log_file} does not exist.", "error")
            return redirect(url_for('jobs.scheduled_jobs'))
        logger.info("Serving log file %s for script %s", log_file, script_name)
        return send_file(
            log_file,
            as_attachment=False,
            mimetype='text/plain',
            download_name=os.path.basename(log_file)
        )
    except oracledb.Error as e:
        logger.error("Database error in download_log: %s", str(e))
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    except Exception as e:
        logger.error("Unexpected error in download_log: %s", str(e), exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
@job_bp.route('/restart_scheduler', methods=['POST'])
@login_required
def restart_scheduler():
    logger.info("=== RESTART SCHEDULER initiated by user %s ===", current_user.id)
    try:
        success = safe_restart_scheduler()
        if success:
            flash("Scheduler restarted successfully (clean restart - spaces fixed)", "success")
            logger.info("=== RESTART SCHEDULER completed successfully ===")
        else:
            flash("Scheduler restart failed - check logs", "error")
    except Exception as e:
        logger.error("Error restarting scheduler: %s", str(e), exc_info=True)
        flash(f"Error restarting scheduler: {str(e)}", "error")
    return redirect(url_for('jobs.scheduled_jobs'))
@job_bp.route('/run_all_scripts', methods=['POST'])
@login_required
def run_all_scripts():
    logger.info("Triggering all root scripts, user=%s, scheduler_running=%s", current_user.id, get_scheduler().running)
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute("SELECT JOB_ID, SCRIPT_NAME, SCRIPT_PATH, SCRIPT_PARAMETERS FROM MAAMD.SCHEDULED_JOBS WHERE PARENT_JOB_ID IS NULL")
        jobs = cursor.fetchall()
        if not get_scheduler().running:
            logger.warning("Scheduler is not running, attempting to start")
            try:
                safe_restart_scheduler()
                logger.info("Scheduler started successfully for run_all_scripts")
            except Exception as e:
                logger.error("Failed to start scheduler for run_all_scripts: %s\n%s", str(e), traceback.format_exc())
                flash(f"Failed to start scheduler: {str(e)}", "error")
                return redirect(url_for('jobs.scheduled_jobs'))
        triggered_jobs = 0
        for job_id, script_name, script_path, script_parameters in jobs:
            if is_job_running(job_id, conn):
                logger.warning("Job %d (%s) is already running, skipping", job_id, script_name)
                continue
            if not script_path.startswith('PLSQL:') and not script_path.startswith('FUNCTION:'):
                script_base_path = script_path.split()[0] if script_parameters else script_path
                if not os.path.exists(script_base_path):
                    logger.error("Script path %s for job %d (%s) does not exist, skipping", script_base_path, job_id, script_name)
                    continue
                if not os.access(script_base_path, os.X_OK):
                    logger.error("Script %s for job %d (%s) is not executable, skipping", script_base_path, job_id, script_name)
                    continue
            try:
                job_id_str = f"manual_{job_id}_{datetime.now().timestamp()}"
                get_scheduler().add_job(
                    func=run_script,
                    args=[script_name, job_id],
                    trigger='date',
                    run_date=datetime.now(),
                    id=job_id_str,
                    name=script_name,
                    replace_existing=True
                )
                logger.info("Scheduled root script %s (job_id: %d, manual_id: %s)", script_name, job_id, job_id_str)
                triggered_jobs += 1
            except Exception as e:
                logger.error("Failed to schedule job %d (%s): %s\n%s", job_id, script_name, str(e), traceback.format_exc())
        flash(f"Triggered {triggered_jobs} root scripts successfully", "success")
    except oracledb.Error as e:
        logger.error("Database error in run_all_scripts: %s\n%s", str(e), traceback.format_exc())
        flash(f"Database error: {str(e)}", "error")
    except Exception as e:
        logger.error("Error running all scripts: %s\n%s", str(e), traceback.format_exc())
        flash(f"Error running all scripts: {str(e)}", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
    return redirect(url_for('jobs.scheduled_jobs'))
@job_bp.route('/add_job', methods=['GET', 'POST'])
@login_required
def add_job():
    logger.info("Accessing add_job, method=%s, user=%s", request.method, current_user.id)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute("SELECT JOB_ID, SCRIPT_NAME FROM MAAMD.SCHEDULED_JOBS ORDER BY SCRIPT_NAME")
        available_jobs = cursor.fetchall()
        logger.debug("Fetched %d available jobs for add_job", len(available_jobs))
        if request.method == 'POST':
            script_name = request.form['script_name'].strip()
            display_name = request.form.get('display_name', script_name).strip()
            script_path = request.form['script_path'].strip()
            raw_params = request.form.get('script_parameters', '').strip()
            script_parameters = None if (not raw_params or raw_params.lower() == 'none') else raw_params
            log_file = request.form['log_file'].strip()
            job_type = request.form.get('job_type')
            schedule_interval = request.form.get('schedule_interval', '')
            cron_schedule = request.form.get('cron_schedule', '')
            parent_job_id = request.form.get('parent_job_id', '')
            if script_path.startswith('FUNCTION:'):
                pass
            elif not script_path.startswith('PLSQL:'):
                if not os.path.isfile(script_path):
                    flash(f"Invalid script path: '{script_path}' does not exist.", "error")
                    logger.error("Invalid script path %s provided for job %s", script_path, script_name)
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                if not os.access(script_path, os.X_OK):
                    flash(f"Script '{script_path}' is not executable. Please check permissions.", "error")
                    logger.error("Script %s for job %s is not executable", script_path, script_name)
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
            # === RELAXED DUPLICATE CHECK using NAMED binds (fixes DPY-4009) ===
            cursor.execute(
                """
                SELECT COUNT(*) FROM MAAMD.SCHEDULED_JOBS 
                WHERE SCRIPT_NAME = :script_name 
                AND (SCRIPT_PARAMETERS = :params OR (SCRIPT_PARAMETERS IS NULL AND :params IS NULL))
                """,
                {'script_name': script_name, 'params': script_parameters or None}
            )
            if cursor.fetchone()[0] > 0:
                flash(f"A job with script name '{script_name}' and these exact parameters already exists. Use a different Internal Script Name or change the parameters.", "error")
                return render_template(
                    'jobs/add_job.html',
                    username=current_user.id,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    timestamp=timestamp,
                    available_jobs=available_jobs
                )
            if job_type not in ['interval', 'cron', 'dependent']:
                flash("Invalid job type selected.", "error")
                return render_template(
                    'jobs/add_job.html',
                    username=current_user.id,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    timestamp=timestamp,
                    available_jobs=available_jobs
                )
            if job_type == 'interval':
                if not schedule_interval:
                    flash("Schedule Interval is required for interval-based jobs.", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                try:
                    schedule_interval = int(schedule_interval)
                    if schedule_interval <= 0:
                        raise ValueError("Schedule Interval must be a positive integer.")
                except ValueError as e:
                    flash(f"Invalid Schedule Interval: {e}", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                cron_schedule = None
                parent_job_id = None
            elif job_type == 'cron':
                if not cron_schedule:
                    flash("Cron Schedule is required for cron-scheduled jobs.", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                try:
                    CronTrigger.from_crontab(cron_schedule, timezone='UTC')
                except ValueError as e:
                    flash(f"Invalid Cron Schedule: {e}", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                schedule_interval = None
                parent_job_id = None
            elif job_type == 'dependent':
                if not parent_job_id:
                    flash("A parent job must be selected for dependent jobs.", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                try:
                    parent_job_id = int(parent_job_id)
                except ValueError:
                    flash("Invalid parent job selected.", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                if detect_dependency_cycle(None, parent_job_id, conn):
                    flash("Invalid dependency: Circular dependency detected.", "error")
                    return render_template(
                        'jobs/add_job.html',
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp,
                        available_jobs=available_jobs
                    )
                schedule_interval = None
                cron_schedule = None
            try:
                cursor.execute(
                    """
                    INSERT INTO MAAMD.SCHEDULED_JOBS (
                        SCRIPT_NAME, DISPLAY_NAME, SCRIPT_PATH, SCRIPT_PARAMETERS, LOG_FILE, SCHEDULE_INTERVAL_MINUTES,
                        CRON_SCHEDULE, PARENT_JOB_ID, CREATED_BY, CREATED_DATE, LAST_UPDATED_BY, LAST_UPDATED_DATE
                    )
                    VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, SYSDATE, :10, SYSDATE)
                    """,
                    (script_name, display_name, script_path, script_parameters or None, log_file, schedule_interval, cron_schedule or None,
                     parent_job_id, current_user.id, current_user.id)
                )
                conn.commit()
                flash("Job added successfully", "success")
                logger.info("User %s added job '%s' (display: '%s')", current_user.id, script_name, display_name)
                return redirect(url_for('jobs.scheduled_jobs'))
            except oracledb.Error as e:
                error_str = str(e)
                logger.error("Failed to add job '%s': %s\n%s", script_name, error_str, traceback.format_exc())
                if "ORA-00001" in error_str:
                    flash(f"A job with script name '{script_name}' and these exact parameters already exists. Use a different Internal Script Name or change the parameters.", "error")
                else:
                    flash(f"Database error: {error_str}", "error")
                return render_template(
                    'jobs/add_job.html',
                    username=current_user.id,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    timestamp=timestamp,
                    available_jobs=available_jobs
                )
        return render_template(
            'jobs/add_job.html',
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=timestamp,
            available_jobs=available_jobs
        )
    except oracledb.Error as e:
        logger.error("Database error in add_job: %s\n%s", str(e), traceback.format_exc())
        flash(f"Database error: {str(e)}", "error")
        return render_template(
            'jobs/add_job.html',
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=timestamp,
            available_jobs=available_jobs
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
@job_bp.route('/edit_job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    logger.info("Accessing edit_job for job %d, method=%s, user=%s", job_id, request.method, current_user.id)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT JOB_ID, SCRIPT_NAME, DISPLAY_NAME, SCRIPT_PATH, SCRIPT_PARAMETERS, LOG_FILE, SCHEDULE_INTERVAL_MINUTES,
                   CRON_SCHEDULE, PARENT_JOB_ID
            FROM MAAMD.SCHEDULED_JOBS
            WHERE JOB_ID = :1
        """, (job_id,))
        job = cursor.fetchone()
        if not job:
            flash("Job not found", "error")
            logger.warning("Job ID %d not found", job_id)
            return redirect(url_for('jobs.scheduled_jobs'))
        job_id, script_name, display_name, script_path, script_parameters, log_file, schedule_interval, cron_schedule, parent_job_id = job
        cursor.execute("SELECT JOB_ID, SCRIPT_NAME FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID != :1 ORDER BY SCRIPT_NAME", (job_id,))
        available_jobs = cursor.fetchall()
        logger.debug("Fetched %d available jobs for edit_job %d", len(available_jobs), job_id)
        if request.method == 'POST':
            new_script_name = request.form['script_name'].strip()
            new_display_name = request.form.get('display_name', new_script_name).strip()
            new_script_path = request.form['script_path'].strip()
            raw_params = request.form.get('script_parameters', '').strip()
            new_script_parameters = None if (not raw_params or raw_params.lower() == 'none') else raw_params
            new_log_file = request.form['log_file'].strip()
            job_type = request.form.get('job_type')
            new_schedule_interval = request.form.get('schedule_interval', '')
            new_cron_schedule = request.form.get('cron_schedule', '')
            new_parent_job_id = request.form.get('parent_job_id', '')
            if new_script_path.startswith('FUNCTION:'):
                pass
            elif not new_script_path.startswith('PLSQL:'):
                if not os.path.isfile(new_script_path):
                    flash(f"Invalid script path: '{new_script_path}' does not exist.", "error")
                    logger.error("Invalid script path %s provided for job %d (%s)", new_script_path, job_id, new_script_name)
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                if not os.access(new_script_path, os.X_OK):
                    flash(f"Script '{new_script_path}' is not executable. Please check permissions.", "error")
                    logger.error("Script %s for job %d (%s) is not executable", new_script_path, job_id, new_script_name)
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
            if new_script_name != script_name:
                cursor.execute("SELECT COUNT(*) FROM MAAMD.SCHEDULED_JOBS WHERE SCRIPT_NAME = :1 AND JOB_ID != :2",
                              (new_script_name, job_id))
                if cursor.fetchone()[0] > 0:
                    flash(f"Job with script name '{new_script_name}' already exists.", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
            # === RELAXED DUPLICATE CHECK using NAMED binds (fixes DPY-4009) ===
            cursor.execute(
                """
                SELECT COUNT(*) FROM MAAMD.SCHEDULED_JOBS 
                WHERE SCRIPT_NAME = :script_name 
                AND (SCRIPT_PARAMETERS = :params OR (SCRIPT_PARAMETERS IS NULL AND :params IS NULL))
                AND JOB_ID != :job_id
                """,
                {'script_name': new_script_name, 'params': new_script_parameters or None, 'job_id': job_id}
            )
            if cursor.fetchone()[0] > 0:
                flash(f"A job with script name '{new_script_name}' and these exact parameters already exists. Use a different Internal Script Name or change the parameters.", "error")
                return render_template(
                    'jobs/edit_job.html',
                    job={
                        'job_id': job_id,
                        'script_name': script_name,
                        'display_name': display_name,
                        'script_path': script_path,
                        'script_parameters': script_parameters,
                        'log_file': log_file,
                        'schedule_interval': schedule_interval,
                        'cron_schedule': cron_schedule,
                        'parent_job_id': parent_job_id
                    },
                    job_type='interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval',
                    available_jobs=available_jobs,
                    username=current_user.id,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    timestamp=timestamp
                )
            if job_type not in ['interval', 'cron', 'dependent']:
                flash("Invalid job type selected.", "error")
                return render_template(
                    'jobs/edit_job.html',
                    job={
                        'job_id': job_id,
                        'script_name': script_name,
                        'display_name': display_name,
                        'script_path': script_path,
                        'script_parameters': script_parameters,
                        'log_file': log_file,
                        'schedule_interval': schedule_interval,
                        'cron_schedule': cron_schedule,
                        'parent_job_id': parent_job_id
                    },
                    job_type='interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval',
                    available_jobs=available_jobs,
                    username=current_user.id,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    timestamp=timestamp
                )
            if job_type == 'interval':
                if not new_schedule_interval:
                    flash("Schedule Interval is required for interval-based jobs.", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='interval',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                try:
                    new_schedule_interval = int(new_schedule_interval)
                    if new_schedule_interval <= 0:
                        raise ValueError("Schedule Interval must be a positive integer.")
                except ValueError as e:
                    flash(f"Invalid Schedule Interval: {e}", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='interval',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                new_cron_schedule = None
                new_parent_job_id = None
            elif job_type == 'cron':
                if not new_cron_schedule:
                    flash("Cron Schedule is required for cron-scheduled jobs.", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='cron',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                try:
                    CronTrigger.from_crontab(new_cron_schedule, timezone='UTC')
                except ValueError as e:
                    flash(f"Invalid Cron Schedule: {e}", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='cron',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                new_schedule_interval = None
                new_parent_job_id = None
            elif job_type == 'dependent':
                if not new_parent_job_id:
                    flash("A parent job must be selected for dependent jobs.", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='dependent',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                try:
                    new_parent_job_id = int(new_parent_job_id)
                except ValueError:
                    flash("Invalid parent job selected.", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='dependent',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                if detect_dependency_cycle(job_id, new_parent_job_id, conn):
                    flash("Invalid dependency: Circular dependency detected.", "error")
                    return render_template(
                        'jobs/edit_job.html',
                        job={
                            'job_id': job_id,
                            'script_name': script_name,
                            'display_name': display_name,
                            'script_path': script_path,
                            'script_parameters': script_parameters,
                            'log_file': log_file,
                            'schedule_interval': schedule_interval,
                            'cron_schedule': cron_schedule,
                            'parent_job_id': parent_job_id
                        },
                        job_type='dependent',
                        available_jobs=available_jobs,
                        username=current_user.id,
                        logo_base64=current_app.ORACLE_LOGO_BASE64,
                        oracle_red=current_app.ORACLE_RED,
                        timestamp=timestamp
                    )
                new_schedule_interval = None
                new_cron_schedule = None
            try:
                cursor.execute(
                    """
                    UPDATE MAAMD.SCHEDULED_JOBS
                    SET SCRIPT_NAME = :1, DISPLAY_NAME = :2, SCRIPT_PATH = :3, SCRIPT_PARAMETERS = :4, LOG_FILE = :5,
                        SCHEDULE_INTERVAL_MINUTES = :6, CRON_SCHEDULE = :7,
                        PARENT_JOB_ID = :8, LAST_UPDATED_BY = :9, LAST_UPDATED_DATE = SYSDATE
                    WHERE JOB_ID = :10
                    """,
                    (new_script_name, new_display_name, new_script_path, new_script_parameters or None, new_log_file,
                     new_schedule_interval, new_cron_schedule, new_parent_job_id, current_user.id, job_id)
                )
                conn.commit()
                flash("Job updated successfully", "success")
                logger.info("User %s updated job %d: script_name='%s', display_name='%s'",
                            current_user.id, job_id, new_script_name, new_display_name)
                return redirect(url_for('jobs.scheduled_jobs'))
            except oracledb.Error as e:
                error_str = str(e)
                logger.error("Failed to update job %d: %s\n%s", job_id, error_str, traceback.format_exc())
                if "ORA-00001" in error_str:
                    flash(f"A job with script name '{new_script_name}' and these exact parameters already exists. Use a different Internal Script Name or change the parameters.", "error")
                else:
                    flash(f"Database error: {error_str}", "error")
                return render_template(
                    'jobs/edit_job.html',
                    job={
                        'job_id': job_id,
                        'script_name': script_name,
                        'display_name': display_name,
                        'script_path': script_path,
                        'script_parameters': script_parameters,
                        'log_file': log_file,
                        'schedule_interval': schedule_interval,
                        'cron_schedule': cron_schedule,
                        'parent_job_id': parent_job_id
                    },
                    job_type='interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval',
                    available_jobs=available_jobs,
                    username=current_user.id,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    timestamp=timestamp
                )
        job_type = 'interval' if schedule_interval else 'cron' if cron_schedule else 'dependent' if parent_job_id else 'interval'
        return render_template(
            'jobs/edit_job.html',
            job={
                'job_id': job_id,
                'script_name': script_name,
                'display_name': display_name,
                'script_path': script_path,
                'script_parameters': script_parameters,
                'log_file': log_file,
                'schedule_interval': schedule_interval,
                'cron_schedule': cron_schedule,
                'parent_job_id': parent_job_id
            },
            job_type=job_type,
            available_jobs=available_jobs,
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            timestamp=timestamp
        )
    except oracledb.Error as e:
        logger.error("Database error in edit_job: %s\n%s", str(e), traceback.format_exc())
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
@job_bp.route('/delete_job/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    logger.info("Deleting job %d, user=%s", job_id, current_user.id)
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database error: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        cursor.execute("SELECT SCRIPT_NAME FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID = :1", (job_id,))
        result = cursor.fetchone()
        if not result:
            flash("Job not found", "error")
            logger.warning("Job ID %d not found", job_id)
            return redirect(url_for('jobs.scheduled_jobs'))
        script_name = result[0]
        cursor.execute("SELECT COUNT(*) FROM MAAMD.SCHEDULED_JOBS WHERE PARENT_JOB_ID = :1", (job_id,))
        if cursor.fetchone()[0] > 0:
            flash(f"Cannot delete job '{script_name}' as it has dependent jobs.", "error")
            logger.warning("Job %d (%s) has dependent jobs", job_id, script_name)
            return redirect(url_for('jobs.scheduled_jobs'))
        cursor.execute("DELETE FROM MAAMD.JOB_HISTORY WHERE JOB_ID = :1", (job_id,))
        cursor.execute("DELETE FROM MAAMD.JOB_LOCKS WHERE JOB_ID = :1", (job_id,))
        cursor.execute("DELETE FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID = :1", (job_id,))
        conn.commit()
        try:
            get_scheduler().remove_job(f"{script_name}_{job_id}")
            logger.debug("Removed job %s from scheduler", script_name)
        except Exception as e:
            logger.warning("Failed to remove job %s from scheduler: %s", script_name, str(e))
        flash(f"Job '{script_name}' deleted successfully", "success")
        logger.info("User %s deleted job %d (%s)", current_user.id, job_id, script_name)
        return redirect(url_for('jobs.scheduled_jobs'))
    except oracledb.Error as e:
        logger.error("Database error in delete_job: %s\n%s", str(e), traceback.format_exc())
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    except Exception as e:
        logger.error("Unexpected error in delete_job: %s\n%s", str(e), traceback.format_exc())
        flash(f"Unexpected error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
        logger.debug("Released database resources for delete_job")
@job_bp.route('/job_history', methods=['GET'])
@login_required
def job_history():
    logger.info("Accessing job_history, user=%s", current_user.id)
    conn = None
    cursor = None
    try:
        for attempt in range(3):
            try:
                conn = current_app.config['DB_POOL'].acquire()
                break
            except oracledb.Error as e:
                logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                time.sleep(1)
                if attempt == 2:
                    logger.error("Failed to acquire connection after 3 attempts: %s", str(e))
                    flash(f"Database connection failed: {str(e)}", "error")
                    return redirect(url_for('jobs.scheduled_jobs'))
        cursor = conn.cursor()
        query = """
            SELECT jh.JOB_ID, sj.SCRIPT_NAME, jh.HISTORY_ID, jh.RUN_TIME, jh.STATUS, jh.EXIT_CODE,
                   jh.ERROR_MESSAGE, jh.TRIGGERED_BY
            FROM MAAMD.JOB_HISTORY jh
            JOIN MAAMD.SCHEDULED_JOBS sj ON jh.JOB_ID = sj.JOB_ID
            WHERE 1=1
        """
        params = {}
        job_id = request.args.get('job_id')
        if job_id:
            try:
                job_id = int(job_id)
                query += " AND jh.JOB_ID = :job_id"
                params['job_id'] = job_id
            except ValueError:
                logger.warning("Invalid job_id: %s", job_id)
                flash("Invalid job ID", "error")
                return redirect(url_for('jobs.scheduled_jobs'))
        for param, key in [('sj.SCRIPT_NAME', 'script_name'), ('jh.STATUS', 'status'), ('jh.TRIGGERED_BY', 'triggered_by')]:
            value = request.args.get(key, '').strip()
            if value:
                query += f" AND LOWER({param}) LIKE LOWER(:{key})"
                params[key] = f"%{value}%"
        query += " ORDER BY jh.RUN_TIME DESC"
        cursor.execute(query, params)
        history_records = cursor.fetchall()
        logger.debug("Fetched %d job history records", len(history_records))
        history_data = [
            {
                'job_id': job_id,
                'script_name': script_name,
                'history_id': history_id,
                'run_time': run_time.strftime('%Y-%m-%d %H:%M:%S') if run_time else None,
                'status': status,
                'exit_code': exit_code,
                'error_message': error_message,
                'triggered_by': triggered_by
            }
            for job_id, script_name, history_id, run_time, status, exit_code, error_message, triggered_by in history_records
        ]
        filters = {
            'script_name': request.args.get('script_name', ''),
            'status': request.args.get('status', ''),
            'triggered_by': request.args.get('triggered_by', ''),
            'job_id': job_id or ''
        }
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        if not history_data:
            flash("No job history entries found.", "info")
        return render_template(
            'jobs/job_history.html',
            history_records=history_data,
            username=current_user.id,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            filters=filters,
            timestamp=timestamp
        )
    except oracledb.Error as e:
        logger.error("Database error in job_history: %s\n%s", str(e), traceback.format_exc())
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    except Exception as e:
        logger.error("Unexpected error in job_history: %s\n%s", str(e), traceback.format_exc())
        flash(f"Unexpected error: {str(e)}", "error")
        return redirect(url_for('jobs.scheduled_jobs'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            current_app.config['DB_POOL'].release(conn)
        logger.debug("Released database resources for job_history")
