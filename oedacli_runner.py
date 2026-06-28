#!/usr/bin/env python3
# Version: 2026-04-21 v1.36
# Changes: Switched to -c flag + multiple -e commands for better reliability with LIST commands.

import os
import subprocess
import traceback
from datetime import datetime
from typing import List, Optional, Dict, Any
from maa_libraries import logger, get_db_pool_connection, release_db_connection

OEDA_BASE_DIR = "/home/maatest/mchafin/MAA_APPS_NEW/OEDA"
OEDACLI_BINARY = os.path.join(OEDA_BASE_DIR, "oedacli")
GENERATOR_SCRIPT = "/home/maatest/mchafin/MAA_APPS_NEW/generate_oedacli_configs.py"
WORKDIR = os.path.join(OEDA_BASE_DIR, "WorkDir")


def generate_oedacli_command_file(commands: List[str], config_xml_path: str, dry_run: bool = False) -> str:
    """Generate temporary command file (kept for compatibility)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    cmd_filename = f"oedacli_job_{timestamp}.cmd"
    os.makedirs(WORKDIR, exist_ok=True)
    cmd_path = os.path.join(WORKDIR, cmd_filename)

    with open(cmd_path, 'w', encoding='utf-8') as f:
        f.write(f"LOAD FILE {config_xml_path}\n")
        if dry_run:
            f.write("SET DRYRUN ON\n")
        for cmd in commands:
            f.write(cmd.strip() + "\n")
        f.write("EXIT\n")

    logger.info(f"Generated OEDACLI command file: {cmd_path}")
    return cmd_path


def safe_emit_progress(socketio, room: str, data: Dict[str, Any]):
    """Safe SocketIO emit."""
    try:
        if socketio and room:
            socketio.emit('oedacli_output', data, room=room, namespace='/')
    except Exception as e:
        print(f"[SAFE_EMIT FAILED] {str(e)}")


def run_oedacli_background(task_id: str, commands: List[str], config_id: int,
                           dry_run: bool, username: str, room: str,
                           db_pool, socketio):
    """Background task - uses -c flag (more reliable for LIST commands)."""
    terminal_output = []
    return_code = 1
    start_time = datetime.now()

    try:
        safe_emit_progress(socketio, room, {
            'status': 'RUNNING',
            'line': f"Starting task {task_id} (config_id={config_id})"
        })

        # Get pre-generated XML from database
        conn = get_db_pool_connection(db_pool)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT PROPER_OEDA_XML
            FROM MAAMD.OEDACLI_CONFIGS
            WHERE CONFIG_ID = :1
        """, (config_id,))
        row = cursor.fetchone()
        cursor.close()
        release_db_connection(conn, db_pool)

        if not row or not row[0]:
            raise Exception(f"Config {config_id} has no PROPER_OEDA_XML")

        proper_xml = row[0].read() if hasattr(row[0], 'read') else str(row[0])

        os.makedirs(WORKDIR, exist_ok=True)
        config_xml_path = os.path.join(WORKDIR, f"official_es_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.xml")
        with open(config_xml_path, 'w', encoding='utf-8') as f:
            f.write(proper_xml)

        safe_emit_progress(socketio, room, {
            'status': 'RUNNING',
            'line': f"Using pre-generated config: {config_xml_path}"
        })

        # Build command using -c flag + multiple -e
        cmd = [OEDACLI_BINARY, "-c", config_xml_path]
        if dry_run:
            cmd.extend(["-e", "SET DRYRUN ON"])

        for c in commands:
            cmd.extend(["-e", c.strip()])

        safe_emit_progress(socketio, room, {
            'status': 'RUNNING',
            'line': f"Executing: {' '.join(cmd)}"
        })

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            line = line.rstrip('\n')
            if line:
                terminal_output.append(line)
                safe_emit_progress(socketio, room, {
                    'status': 'RUNNING',
                    'line': line
                })

        process.stdout.close()
        return_code = process.wait()

        final_status = 'SUCCESS' if return_code == 0 else 'FAILED'
        safe_emit_progress(socketio, room, {
            'status': final_status,
            'message': f"OEDACLI execution completed with return code {return_code}",
            'return_code': return_code,
            'full_output': '\n'.join(terminal_output),
            'duration': str(datetime.now() - start_time)
        })

        # Save job record
        conn = get_db_pool_connection(db_pool)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO MAAMD.OEDACLI_JOBS
            (TASK_ID, COMMAND_FILE_CONTENT, TERMINAL_OUTPUT, STATUS, DRY_RUN, RETURN_CODE, STARTED_BY, STARTED_DATE, COMPLETED_DATE)
            VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9)
        """, (
            task_id,
            '\n'.join(commands),
            '\n'.join(terminal_output),
            final_status,
            1 if dry_run else 0,
            return_code,
            username,
            start_time,
            datetime.now()
        ))
        conn.commit()
        cursor.close()
        release_db_connection(conn, db_pool)

    except Exception as e:
        logger.error(f"[OEDACLI Runner] Critical error in task {task_id}: {str(e)}", exc_info=True)
        safe_emit_progress(socketio, room, {
            'status': 'FAILED',
            'message': f'Execution failed: {str(e)}',
            'error': traceback.format_exc()
        })


def run_config_refresh_background(task_id: str, hostname: Optional[str], mode: str,
                                  username: str, room: str, db_pool, socketio):
    """Background task to refresh OEDACLI configs."""
    try:
        safe_emit_progress(socketio, room, {
            'status': 'RUNNING',
            'line': f"Starting config refresh (mode={mode}, hostname={hostname or 'ALL'})"
        })

        cmd = ["python3", GENERATOR_SCRIPT]
        if mode == "single" and hostname:
            cmd.extend(["--host", hostname])
        else:
            cmd.append("--all")
        cmd.append("--debug")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            line = line.rstrip('\n')
            if line:
                safe_emit_progress(socketio, room, {
                    'status': 'RUNNING',
                    'line': line
                })

        process.stdout.close()
        return_code = process.wait()

        final_status = 'SUCCESS' if return_code == 0 else 'FAILED'
        safe_emit_progress(socketio, room, {
            'status': final_status,
            'message': f"Config refresh completed with return code {return_code}",
            'return_code': return_code
        })

    except Exception as e:
        logger.error(f"[Config Refresh] Critical error in task {task_id}: {str(e)}", exc_info=True)
        safe_emit_progress(socketio, room, {
            'status': 'FAILED',
            'message': f'Refresh failed: {str(e)}',
            'error': traceback.format_exc()
        })


def execute_oedacli_sync(commands: List[str], dry_run: bool = False) -> Dict[str, Any]:
    """Synchronous version for debugging (not used in production)."""
    raise NotImplementedError("Use run_oedacli_background for production use")
