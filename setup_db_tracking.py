# Filename: setup_db_tracking.py
# Version: 2026-03-24 v1.0.0
# Changes: New file - extracted DB tracking helpers. Contains start_script_run and end_script_run.
import uuid
import oracledb
from maa_libraries import logger, get_db_pool_connection, release_db_connection

def start_script_run(script_name, pool=None):
    run_id = str(uuid.uuid4())
    conn = None
    cursor = None
    try:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO MAAMD.SCRIPT_RUN_STATUS
            (RUN_ID, SCRIPT_NAME, STATUS, START_TIME, MESSAGE)
            VALUES (:1, :2, 'RUNNING', CURRENT_TIMESTAMP, :3)
        """, (run_id, script_name, f"{script_name} started..."))
        conn.commit()
        logger.info(f"Started run {run_id} – {script_name}")
        return run_id
    except oracledb.Error as e:
        logger.error(f"Error starting script run for {script_name}: {e}", exc_info=True)
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn, pool)

def end_script_run(run_id, success=True, message=None, pool=None):
    if not run_id:
        return
    conn = None
    cursor = None
    try:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        status = 'SUCCESS' if success else 'FAILED'
        msg = message or ('Completed' if success else 'Failed')
        cursor.execute("""
            UPDATE MAAMD.SCRIPT_RUN_STATUS
            SET STATUS = :1, MESSAGE = :2, END_TIME = CURRENT_TIMESTAMP
            WHERE RUN_ID = :3
        """, (status, msg, run_id))
        conn.commit()
        logger.info(f"Ended run {run_id} with status {status}")
    except oracledb.Error as e:
        logger.error(f"Error ending script run {run_id}: {e}", exc_info=True)
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn, pool)
