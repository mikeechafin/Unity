#!/usr/bin/env python3
# Version: 2026-03-29 v1.0.83
# Changes: Removed new imports from maa_libraries (fixes ImportError). Hardened cleanup_stale_jobs and schedule_jobs with inline credential fallback (original pattern) + extra retry/sleep for DPY-4005 pool race condition. All legacy logic, locking, triggers, and maa_agent_log_parser_daily cron preserved verbatim.
import logging
import sys
import time
import uuid
import traceback
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_PAUSED, SchedulerAlreadyRunningError
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.events import EVENT_JOB_ADDED, EVENT_JOB_EXECUTED, EVENT_JOB_ERROR, EVENT_JOB_MISSED
from sqlalchemy import MetaData
import atexit
import os
import psutil
import fcntl
import subprocess
import oracledb
import config
from flask import current_app, has_request_context
from flask_login import current_user
logger = logging.getLogger('MAA_Unified')
scheduler = None
scheduler_instance_id = str(uuid.uuid4())
logger.info("Scheduler module loaded with instance ID: %s", scheduler_instance_id)
def init_scheduler():
    global scheduler
    if scheduler is not None:
        return scheduler
    try:
        from maa_unified_app import app as flask_app
        with flask_app.app_context():
            dsn = flask_app.config['DB_CONFIG']['dsn']
            jobstores = {
                'default': SQLAlchemyJobStore(
                    url=f"oracle+oracledb://maamd:{os.environ.get('DB_PASSWORD')}@{dsn}",
                    tablename='apscheduler_jobs',
                    metadata=MetaData(schema='MAAMD'),
                    tableschema='MAAMD',
                    pickle_protocol=4
                )
            }
            executors = {'default': ThreadPoolExecutor(12)}
            job_defaults = {'coalesce': True, 'max_instances': 1, 'misfire_grace_time': 86400}
            scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, timezone='UTC')
            logger.debug("Scheduler object initialized successfully")
            return scheduler
    except Exception as e:
        logger.error("Failed to init_scheduler: %s\n%s", str(e), traceback.format_exc())
        raise
def get_scheduler():
    """Safe accessor that guarantees scheduler is initialized."""
    global scheduler
    if scheduler is None:
        scheduler = init_scheduler()
    return scheduler
def is_job_running(job_id, conn):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT IS_RUNNING FROM MAAMD.JOB_LOCKS WHERE JOB_ID = :1 AND IS_RUNNING = 'Y'", (job_id,))
        result = cursor.fetchone()
        is_running = result is not None
        logger.debug("Job %d lock status: %s", job_id, 'Running' if is_running else 'Not running')
        return is_running
    except oracledb.Error as e:
        logger.error("Error checking job lock for job_id %d: %s\n%s", job_id, str(e), traceback.format_exc())
        return False
    finally:
        cursor.close()
def acquire_job_lock(job_id, script_name, conn, max_attempts=15, delay=5):
    cursor = None
    try:
        for attempt in range(max_attempts):
            cursor = conn.cursor()
            try:
                conn.begin()
                cursor.execute("""
                    DELETE FROM MAAMD.JOB_LOCKS
                    WHERE JOB_ID = :1
                    AND (IS_RUNNING = 'Y' OR START_TIME < SYSTIMESTAMP - INTERVAL '1' MINUTE)
                """, (job_id,))
                if cursor.rowcount > 0:
                    logger.info("Cleaned up %d stale locks for job_id %d", cursor.rowcount, job_id)
                conn.commit()
                cursor.execute("""
                    INSERT INTO MAAMD.JOB_LOCKS (JOB_ID, SCRIPT_NAME, START_TIME, IS_RUNNING)
                    VALUES (:1, :2, SYSTIMESTAMP, 'Y')
                """, (job_id, script_name))
                conn.commit()
                logger.info("Acquired lock for job_id %d, script %s", job_id, script_name)
                return True
            except oracledb.Error as e:
                error_str = str(e)
                conn.rollback()
                if "ORA-00001" in error_str:
                    logger.warning("Lock conflict for job_id %d on attempt %d: %s", job_id, attempt + 1, error_str)
                    time.sleep(delay * (attempt + 1))
                else:
                    logger.error("Failed to acquire lock for job_id %d: %s\n%s", job_id, error_str, traceback.format_exc())
                    return False
            finally:
                if cursor:
                    cursor.close()
        logger.error("Failed to acquire lock for job_id %d after %d attempts", job_id, max_attempts)
        return False
    except Exception as e:
        logger.error("Unexpected error in acquire_job_lock for job_id %d: %s\n%s", job_id, str(e), traceback.format_exc())
        return False
def release_job_lock(job_id, conn):
    if conn is None:
        logger.error("Cannot release lock - conn is None")
        return
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE MAAMD.JOB_LOCKS SET IS_RUNNING = 'N' WHERE JOB_ID = :1", (job_id,))
        conn.commit()
        logger.debug("Released lock for job_id %d", job_id)
    except oracledb.Error as e:
        logger.error("Failed to release lock for job_id %d: %s\n%s", job_id, str(e), traceback.format_exc())
    finally:
        cursor.close()
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
def run_script(script_name, job_id=None):
    from maa_unified_app import app as flask_app
    with flask_app.app_context():
        logger.info("Attempting to run script: %s (job_id: %s) with scheduler instance %s", script_name, job_id, scheduler_instance_id)
        if job_id is None:
            logger.error("Invalid job_id: None for script %s. Skipping execution.", script_name)
            return
        conn = None
        cursor = None
        history_id = None
        try:
            for attempt in range(6):
                try:
                    conn = flask_app.config['DB_POOL'].acquire()
                    break
                except oracledb.Error as e:
                    logger.warning("Failed to acquire connection on attempt %d: %s", attempt + 1, str(e))
                    time.sleep(2 ** attempt)
                    if attempt == 5:
                        logger.error("Failed to acquire connection after 6 attempts: %s\n%s", str(e), traceback.format_exc())
                        return
            cursor = conn.cursor()
            cursor.execute(
                "SELECT JOB_ID, SCRIPT_PATH, SCRIPT_PARAMETERS, LOG_FILE FROM MAAMD.SCHEDULED_JOBS WHERE JOB_ID = :1 AND SCRIPT_NAME = :2",
                (job_id, script_name)
            )
            result = cursor.fetchone()
            if not result:
                logger.error("Script %s (job_id: %d) not found in MAAMD.SCHEDULED_JOBS", script_name, job_id)
                return
            _, script_path, script_parameters, log_file = result
            logger.debug("Script details: job_id=%d, script_name=%s, script_path=%s, script_parameters=%s, log_file=%s",
                         job_id, script_name, script_path, script_parameters or 'None', log_file or 'None')
            if not script_path.startswith('PLSQL:'):
                script_base_path = script_path.split()[0] if script_parameters else script_path
                if not os.path.exists(script_base_path):
                    logger.error("Script path %s for job %d (%s) does not exist", script_base_path, job_id, script_name)
                    return
                if not os.access(script_base_path, os.X_OK):
                    logger.error("Script %s for job %d (%s) is not executable", script_base_path, job_id, script_name)
                    return
            if is_job_running(job_id, conn):
                logger.warning("Script %s (job_id: %d) is already running, skipping", script_name, job_id)
                return
            if not acquire_job_lock(job_id, script_name, conn):
                logger.error("Failed to acquire lock for %s (job_id: %d)", script_name, job_id)
                return
            try:
                triggered_by = 'Scheduler'
                if has_request_context() and current_user and hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                    triggered_by = current_user.id
                history_id_var = cursor.var(oracledb.NUMBER)
                cursor.execute(
                    """
                    INSERT INTO MAAMD.JOB_HISTORY (JOB_ID, RUN_TIME, STATUS, TRIGGERED_BY)
                    VALUES (:1, SYSTIMESTAMP, :2, :3)
                    RETURNING HISTORY_ID INTO :4
                    """,
                    (job_id, 'Running', triggered_by, history_id_var)
                )
                history_id = history_id_var.getvalue()[0]
                conn.commit()
                logger.info("Inserted JOB_HISTORY entry for job_id %d, history_id %s, status Running", job_id, history_id)
            except oracledb.Error as e:
                error_str = str(e)
                if "ORA-02290" in error_str:
                    logger.warning("Failed to insert JOB_HISTORY for job_id %d due to ORA-02290, continuing execution: %s", job_id, error_str)
                else:
                    logger.error("Failed to insert JOB_HISTORY for job_id %d: %s\n%s", job_id, error_str, traceback.format_exc())
                    return
            try:
                if script_path.startswith('PLSQL:'):
                    plsql_block = script_path[len('PLSQL:'):]
                    logger.info("Executing PL/SQL block for %s: %s", script_name, plsql_block)
                    cursor.execute(plsql_block)
                    conn.commit()
                    logger.info("PL/SQL block for %s executed successfully", script_name)
                    status = 'Completed'
                    exit_code = 0
                    error_message = None
                else:
                    import subprocess
                    command = [sys.executable, script_path]
                    if script_parameters:
                        command.extend(script_parameters.split())
                    logger.debug("Executing command: %s, cwd=%s, env=%s", command, os.getcwd(), os.environ)
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        cwd=config.APP_ROOT
                    )
                    start_time = datetime.now(timezone.utc)
                    stdout, stderr = process.communicate(timeout=3600)
                    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                    if duration > 7200:
                        logger.warning("Script %s took %.2f seconds to complete", script_name, duration)
                    exit_code = process.returncode
                    status = 'Completed' if exit_code == 0 else 'Failed'
                    error_message = stderr if stderr else None
                    if stdout:
                        logger.info("Script %s stdout: %s", script_name, stdout)
                    if stderr:
                        logger.error("Script %s stderr: %s", script_name, stderr)
                    if exit_code != 0:
                        logger.error("Script %s failed with return code %d", script_name, exit_code)
                    else:
                        logger.info("Script %s completed successfully in %.2f seconds", script_name, duration)
                if history_id:
                    try:
                        cursor.execute(
                            """
                            UPDATE MAAMD.JOB_HISTORY
                            SET STATUS = :1, EXIT_CODE = :2, ERROR_MESSAGE = :3
                            WHERE HISTORY_ID = :4
                            """,
                            (status, exit_code, error_message, history_id)
                        )
                        conn.commit()
                        logger.info("Updated JOB_HISTORY for job_id %d, history_id %s, status %s", job_id, history_id, status)
                    except oracledb.Error as e:
                        logger.error("Failed to update JOB_HISTORY for job_id %d, history_id %s: %s\n%s", job_id, history_id, str(e), traceback.format_exc())
                if exit_code == 0:
                    trigger_dependent_jobs(job_id, conn)
            except oracledb.Error as e:
                logger.error("Database error running script %s: %s\n%s", script_name, str(e), traceback.format_exc())
                if history_id:
                    try:
                        cursor.execute(
                            """
                            UPDATE MAAMD.JOB_HISTORY
                            SET STATUS = 'Failed', ERROR_MESSAGE = :1
                            WHERE HISTORY_ID = :2
                            """,
                            (str(e), history_id)
                        )
                        conn.commit()
                    except oracledb.Error as e2:
                        logger.error("Failed to update JOB_HISTORY: %s\n%s", str(e2), traceback.format_exc())
            except subprocess.SubprocessError as e:
                logger.error("Subprocess error running script %s: %s\n%s", script_name, str(e), traceback.format_exc())
                if history_id:
                    try:
                        cursor.execute(
                            """
                            UPDATE MAAMD.JOB_HISTORY
                            SET STATUS = 'Failed', ERROR_MESSAGE = :1
                            WHERE HISTORY_ID = :2
                            """,
                            (str(e), history_id)
                        )
                        conn.commit()
                    except oracledb.Error as e2:
                        logger.error("Failed to update JOB_HISTORY: %s\n%s", str(e2), traceback.format_exc())
            except Exception as e:
                logger.error("Unexpected error running script %s: %s\n%s", script_name, str(e), traceback.format_exc())
                if history_id:
                    try:
                        cursor.execute(
                            """
                            UPDATE MAAMD.JOB_HISTORY
                            SET STATUS = 'Failed', ERROR_MESSAGE = :1
                            WHERE HISTORY_ID = :2
                            """,
                            (str(e), history_id)
                        )
                        conn.commit()
                    except oracledb.Error as e2:
                        logger.error("Failed to update JOB_HISTORY: %s\n%s", str(e2), traceback.format_exc())
        finally:
            if job_id:
                release_job_lock(job_id, conn)
            if cursor:
                cursor.close()
            if conn:
                flask_app.config['DB_POOL'].release(conn)
            logger.debug("Released database resources for job_id %d", job_id)
def trigger_dependent_jobs(parent_job_id, conn):
    if not parent_job_id:
        return
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT JOB_ID, SCRIPT_NAME FROM MAAMD.SCHEDULED_JOBS WHERE PARENT_JOB_ID = :1",
            (parent_job_id,)
        )
        dependent_jobs = cursor.fetchall()
        for job in dependent_jobs:
            dep_job_id, dep_script_name = job
            logger.info("Triggering dependent job %s (job_id: %d) after parent job_id %d", dep_script_name, dep_job_id, parent_job_id)
            get_scheduler().add_job(
                func=run_script,
                args=[dep_script_name, dep_job_id],
                trigger=DateTrigger(run_date=datetime.now(timezone.utc)),
                id=f"dependent_{dep_job_id}_{datetime.now(timezone.utc).timestamp()}",
                name=dep_script_name,
                replace_existing=False
            )
            logger.debug("Scheduled dependent job %s (job_id: %d)", dep_script_name, dep_job_id)
    except oracledb.Error as e:
        logger.error("Error triggering dependent jobs for parent_job_id %d: %s\n%s", parent_job_id, str(e), traceback.format_exc())
    finally:
        cursor.close()
def cleanup_stale_jobs():
    from maa_unified_app import app as flask_app
    with flask_app.app_context():
        logger.info("Cleaning up stale job statuses")
        time.sleep(15)  # extra delay for pool readiness
        conn = None
        cursor = None
        for attempt in range(6):
            try:
                if not flask_app.config.get('DB_POOL'):
                    logger.warning("No database pool available, skipping cleanup")
                    return
                conn = flask_app.config['DB_POOL'].acquire()
                cursor = conn.cursor()
                stale_time = (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()
                cursor.execute("DELETE FROM MAAMD.JOB_HISTORY WHERE RUN_TIME < :1", (datetime.fromtimestamp(stale_time, tz=timezone.utc),))
                logger.info("Deleted %d stale JOB_HISTORY entries", cursor.rowcount)
                cursor.execute("DELETE FROM MAAMD.apscheduler_jobs WHERE next_run_time < :1", (stale_time,))
                logger.info("Deleted %d stale apscheduler_jobs entries", cursor.rowcount)
                cursor.execute(
                    "DELETE FROM MAAMD.JOB_LOCKS WHERE START_TIME < :1 AND IS_RUNNING = 'Y'",
                    (datetime.fromtimestamp(stale_time - 3600, tz=timezone.utc),)
                )
                logger.info("Deleted %d stale JOB_LOCKS entries", cursor.rowcount)
                conn.commit()
                break
            except oracledb.Error as e:
                logger.warning("Pool timeout in cleanup_stale_jobs (attempt %d) — falling back to standalone", attempt + 1)
                if conn:
                    conn.rollback()
                time.sleep(2 ** attempt)
                if attempt == 5:
                    # Standalone fallback (original pattern - no new imports)
                    try:
                        username = 'maamd'
                        password = os.environ.get('DB_PASSWORD')
                        if not password:
                            logger.error("Environment variable DB_PASSWORD is not set")
                            raise ValueError("Environment variable DB_PASSWORD is not set")
                        dsn = flask_app.config['DB_CONFIG']['dsn']
                        conn = oracledb.connect(user=username, password=password, dsn=dsn)
                        cursor = conn.cursor()
                        stale_time = (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()
                        cursor.execute("DELETE FROM MAAMD.JOB_HISTORY WHERE RUN_TIME < :1", (datetime.fromtimestamp(stale_time, tz=timezone.utc),))
                        logger.info("Deleted %d stale JOB_HISTORY entries (standalone)", cursor.rowcount)
                        cursor.execute("DELETE FROM MAAMD.apscheduler_jobs WHERE next_run_time < :1", (stale_time,))
                        logger.info("Deleted %d stale apscheduler_jobs entries (standalone)", cursor.rowcount)
                        cursor.execute(
                            "DELETE FROM MAAMD.JOB_LOCKS WHERE START_TIME < :1 AND IS_RUNNING = 'Y'",
                            (datetime.fromtimestamp(stale_time - 3600, tz=timezone.utc),)
                        )
                        logger.info("Deleted %d stale JOB_LOCKS entries (standalone)", cursor.rowcount)
                        conn.commit()
                        break
                    except Exception as fallback_e:
                        logger.error("Both pool and standalone failed in cleanup: %s", str(fallback_e))
                        logger.error("Failed to cleanup stale jobs after 6 attempts")
            except Exception as e:
                logger.error("Unexpected error in cleanup_stale_jobs: %s\n%s", str(e), traceback.format_exc())
                break
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    try:
                        flask_app.config['DB_POOL'].release(conn)
                    except:
                        if conn:
                            conn.close()
def schedule_jobs():
    from maa_unified_app import app as flask_app
    with flask_app.app_context():
        logger.debug("Starting job scheduling process")
        get_scheduler().remove_all_jobs()
        cleanup_stale_jobs()
        conn = None
        cursor = None
        for attempt in range(6):
            try:
                conn = flask_app.config['DB_POOL'].acquire()
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT JOB_ID, SCRIPT_NAME, SCRIPT_PATH, SCRIPT_PARAMETERS, LOG_FILE, SCHEDULE_INTERVAL_MINUTES, CRON_SCHEDULE, PARENT_JOB_ID
                    FROM MAAMD.SCHEDULED_JOBS
                """)
                jobs = cursor.fetchall()
                logger.info("Fetched %d jobs from MAAMD.SCHEDULED_JOBS", len(jobs))
                for job in jobs:
                    job_id, script_name, script_path, script_parameters, log_file, interval, cron_schedule, parent_job_id = job
                    logger.debug("Processing job %s (job_id: %d)", script_name, job_id)
                    if detect_dependency_cycle(job_id, parent_job_id, conn):
                        logger.error("Skipping job %s (job_id: %d) due to circular dependency", script_name, job_id)
                        continue
                    if parent_job_id:
                        logger.info("Job %s (job_id: %d) will run after parent job_id %d", script_name, job_id, parent_job_id)
                        continue
                    job_args = [script_name, job_id]
                    if cron_schedule:
                        try:
                            get_scheduler().add_job(
                                func=run_script,
                                args=job_args,
                                trigger=CronTrigger.from_crontab(cron_schedule, timezone='UTC'),
                                id=str(job_id),
                                name=script_name,
                                replace_existing=True
                            )
                            logger.info("Scheduled job %s (job_id: %d) with cron: %s", script_name, job_id, cron_schedule)
                        except ValueError as e:
                            logger.error("Invalid cron schedule for job %s (job_id: %d): %s\n%s", script_name, job_id, str(e), traceback.format_exc())
                    elif interval:
                        get_scheduler().add_job(
                            func=run_script,
                            args=job_args,
                            trigger='interval',
                            minutes=interval,
                            id=str(job_id),
                            name=script_name,
                            replace_existing=True
                        )
                        logger.info("Scheduled job %s (job_id: %d) every %d minutes", script_name, job_id, interval)
                    else:
                        logger.warning("Job %s (job_id: %d) has no schedule or dependency defined", script_name, job_id)
                break
            except oracledb.Error as e:
                logger.warning("Pool timeout in schedule_jobs (attempt %d) — falling back to standalone", attempt + 1)
                time.sleep(2 ** attempt)
                if attempt == 5:
                    # Standalone fallback (original pattern - no new imports)
                    try:
                        username = 'maamd'
                        password = os.environ.get('DB_PASSWORD')
                        if not password:
                            logger.error("Environment variable DB_PASSWORD is not set")
                            raise ValueError("Environment variable DB_PASSWORD is not set")
                        dsn = flask_app.config['DB_CONFIG']['dsn']
                        conn = oracledb.connect(user=username, password=password, dsn=dsn)
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT JOB_ID, SCRIPT_NAME, SCRIPT_PATH, SCRIPT_PARAMETERS, LOG_FILE, SCHEDULE_INTERVAL_MINUTES, CRON_SCHEDULE, PARENT_JOB_ID
                            FROM MAAMD.SCHEDULED_JOBS
                        """)
                        jobs = cursor.fetchall()
                        logger.info("Fetched %d jobs from MAAMD.SCHEDULED_JOBS (standalone)", len(jobs))
                        for job in jobs:
                            job_id, script_name, script_path, script_parameters, log_file, interval, cron_schedule, parent_job_id = job
                            logger.debug("Processing job %s (job_id: %d)", script_name, job_id)
                            if detect_dependency_cycle(job_id, parent_job_id, conn):
                                logger.error("Skipping job %s (job_id: %d) due to circular dependency", script_name, job_id)
                                continue
                            if parent_job_id:
                                logger.info("Job %s (job_id: %d) will run after parent job_id %d", script_name, job_id, parent_job_id)
                                continue
                            job_args = [script_name, job_id]
                            if cron_schedule:
                                try:
                                    get_scheduler().add_job(
                                        func=run_script,
                                        args=job_args,
                                        trigger=CronTrigger.from_crontab(cron_schedule, timezone='UTC'),
                                        id=str(job_id),
                                        name=script_name,
                                        replace_existing=True
                                    )
                                    logger.info("Scheduled job %s (job_id: %d) with cron: %s", script_name, job_id, cron_schedule)
                                except ValueError as e:
                                    logger.error("Invalid cron schedule for job %s (job_id: %d): %s\n%s", script_name, job_id, str(e), traceback.format_exc())
                            elif interval:
                                get_scheduler().add_job(
                                    func=run_script,
                                    args=job_args,
                                    trigger='interval',
                                    minutes=interval,
                                    id=str(job_id),
                                    name=script_name,
                                    replace_existing=True
                                )
                                logger.info("Scheduled job %s (job_id: %d) every %d minutes", script_name, job_id, interval)
                            else:
                                logger.warning("Job %s (job_id: %d) has no schedule or dependency defined", script_name, job_id)
                        break
                    except Exception as fallback_e:
                        logger.error("Both pool and standalone failed in schedule_jobs: %s", str(fallback_e))
                        logger.error("Failed to schedule jobs after 6 attempts")
            except Exception as e:
                logger.error("Unexpected error in schedule_jobs: %s\n%s", str(e), traceback.format_exc())
                break
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    try:
                        flask_app.config['DB_POOL'].release(conn)
                    except:
                        if conn:
                            conn.close()
        logger.debug("Completed job scheduling process")
        # === MAA AGENT LOG PARSER DAILY JOB (added 2026-03-29) ===
        try:
            from maa_agent_log_parser.core import run_full_pipeline
            get_scheduler().add_job(
                func=run_full_pipeline,
                kwargs={'use_codex': True},
                trigger='cron',
                hour=2,
                minute=0,
                id='maa_agent_log_parser_daily',
                name='Agent Log Parser - Daily crawl + rollup + Codex analysis',
                replace_existing=True
            )
            logger.info("Scheduled maa_agent_log_parser_daily at 02:00 UTC (crawl + rollup + Codex)")
        except ImportError as e:
            logger.warning(f"maa_agent_log_parser not yet importable (install in PYTHONPATH): {e}")
        except Exception as e:
            logger.error(f"Failed to schedule agent log parser: {e}")
def job_added(event):
    job = get_scheduler().get_job(event.job_id)
    logger.info("Job added: id=%s, name=%s, trigger=%s",
                event.job_id, job.name if job else 'Unknown', str(job.trigger) if job else 'Unknown')
def job_executed(event):
    job = get_scheduler().get_job(event.job_id)
    duration = (datetime.now(timezone.utc) - event.scheduled_run_time).total_seconds()
    logger.info("Job executed: id=%s, name=%s, duration=%.2fs",
                event.job_id, job.name if job else 'Unknown', duration)
def job_error(event):
    job = get_scheduler().get_job(event.job_id)
    logger.error("Job error: id=%s, name=%s, exception=%s\n%s",
                 event.job_id, job.name if job else 'Unknown', str(event.exception), traceback.format_exc())
def job_missed(event):
    job = get_scheduler().get_job(event.job_id)
    delay = (datetime.now(timezone.utc) - event.scheduled_run_time).total_seconds()
    logger.warning("Job missed: id=%s, name=%s, scheduled_time=%s, delay=%.2fs",
                   event.job_id, job.name if job else 'Unknown', event.scheduled_run_time, delay)
def safe_restart_scheduler():
    """Safe restart that works even if scheduler is None or not running."""
    global scheduler
    from maa_unified_app import app as flask_app
    with flask_app.app_context():
        try:
            if scheduler is None:
                scheduler = init_scheduler()
            schedule_jobs()
            if not scheduler.running:
                scheduler.start()
                logger.info("APScheduler started successfully via safe_restart")
            elif scheduler.state == STATE_PAUSED:
                scheduler.resume()
                logger.info("Scheduler was paused — resumed via safe_restart")
            logger.info("Scheduler status after safe restart: running=%s, state=%s", scheduler.running, scheduler.state)
            return True
        except SchedulerAlreadyRunningError:
            logger.info("APScheduler was already running — no action needed")
            return True
        except Exception as e:
            logger.error("Error in safe_restart_scheduler: %s\n%s", str(e), traceback.format_exc())
            return False
def start_scheduler():
    global scheduler
    try:
        scheduler = init_scheduler()
        schedule_jobs()
        if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or 'WERKZEUG_RUN_MAIN' not in os.environ:
            try:
                scheduler.start()
                logger.info("APScheduler started successfully")
            except SchedulerAlreadyRunningError:
                logger.info("APScheduler was already running — no action needed")
            if scheduler.state == STATE_PAUSED:
                scheduler.resume()
                logger.info("Scheduler was paused — resumed automatically")
            logger.info("APScheduler status: running=%s, state=%s", scheduler.running, scheduler.state)
        else:
            logger.info("Skipping scheduler start in Flask reloader parent process")
    except Exception as e:
        logger.error("Unexpected error during scheduler auto-start: %s\n%s", str(e), traceback.format_exc())
atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler and scheduler.running else None)
