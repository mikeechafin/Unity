# Filename: setup_execution.py
# Version: 2026-05-26 v1.88
# Changes: Removed 'imageinfo' from CellCLI detection so it runs as shell command (fixes DBM-01504 / CELL-01504 syntax errors).

DEBUG = False
import os
import subprocess
import tempfile
import time
import uuid
import oracledb
import paramiko
import pexpect
import shutil
from functools import partial
from maa_libraries import logger, get_db_pool_connection, release_db_connection, get_credential_silent
from shared_state import execution_logs, log_lock
from flask import current_app
from environment_setup_registry import execute_function as registry_execute
from setup_scl_loader import scl_functions
from ade_kerberos_helper import run_ade_command, get_ade_password
from shutdown_kvm_and_services import shutdown_kvm_guests_and_services
from start_kvm_guests_and_services import start_kvm_guests_and_services

def safe_emit_progress(task_id, message, status='running', hostname=None, sid=None):
    prefix = f"[{hostname}] " if hostname else "[global] "
    full_msg = prefix + message
    try:
        if current_app and hasattr(current_app, 'socketio'):
            current_app.socketio.emit('message', {
                'task_id': task_id,
                'line': full_msg,
                'status': status
            }, room=sid, namespace='/')
    except Exception as e:
        logger.error(f"safe_emit_progress failed: {e}")

def run_cellcli_via_ilom_console(ilom_host, cellcli_command, pool, task_id=None, sid=None, socketio=None):
    safe_emit_progress(task_id, f"Connecting to ILOM {ilom_host}...", hostname=ilom_host, sid=sid)
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        ilom_pass = get_credential_silent(cursor, 'ILOM', 'default', 'root')
        if not ilom_pass:
            raise Exception("ILOM root password not found for 'default'")
        cell_name = ilom_host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        cell_pass = get_credential_silent(cursor, 'PHYSICAL_HOST', cell_name, 'root') or get_credential_silent(cursor, 'Storage Server', cell_name, 'root') or get_credential_silent(cursor, 'PHYSICAL_HOST', 'default', 'root') or get_credential_silent(cursor, 'Storage Server', 'default', 'root')
        if not cell_pass:
            raise Exception(f"Cell root password not found for {cell_name}")
    except Exception as e:
        err = f"Failed to fetch credentials: {str(e)}"
        logger.error(err, exc_info=True)
        safe_emit_progress(task_id, err, status='error', hostname=ilom_host, sid=sid)
        return err
    finally:
        cursor.close()
        release_db_connection(conn, pool)

    output = ""
    client = None
    channel = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ilom_host, username='root', password=ilom_pass, look_for_keys=True, timeout=30)
        safe_emit_progress(task_id, "Connected to ILOM", hostname=ilom_host, sid=sid)
        channel = client.invoke_shell()
        time.sleep(2)
        if channel.recv_ready():
            recv = channel.recv(4096).decode('utf-8', errors='ignore')
            output += recv
            safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        safe_emit_progress(task_id, "Starting console...", hostname=ilom_host, sid=sid)
        channel.send('start /SP/console\n')
        time.sleep(2)
        buff = ''
        while 'Are you sure' not in buff:
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                buff += recv
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
            time.sleep(0.5)
        channel.send('y\n')
        time.sleep(10)
        safe_emit_progress(task_id, "Waking console and collecting output...", hostname=ilom_host, sid=sid)
        collected = ''
        for _ in range(15):
            channel.send('\n')
            time.sleep(2)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                collected += recv
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        collected_lower = collected.lower()
        if 'cellcli>' in collected_lower:
            safe_emit_progress(task_id, "Detected CellCLI session - exiting to shell...", hostname=ilom_host, sid=sid)
            channel.send('exit\n')
            time.sleep(5)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
            collected_lower += recv.lower()
        if 'login:' in collected_lower:
            safe_emit_progress(task_id, "Login prompt detected - logging in as root...", hostname=ilom_host, sid=sid)
            channel.send('root\n')
            time.sleep(3)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
            safe_emit_progress(task_id, "Sending cell root password...", hostname=ilom_host, sid=sid)
            channel.send(f"{cell_pass}\n")
            time.sleep(10)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        safe_emit_progress(task_id, "Final wake-up to shell prompt...", hostname=ilom_host, sid=sid)
        for _ in range(5):
            channel.send('\n')
            time.sleep(2)
            if channel.recv_ready():
                recv = channel.recv(4096).decode('utf-8', errors='ignore')
                output += recv
                safe_emit_progress(task_id, recv.strip(), hostname=ilom_host, sid=sid)
        safe_emit_progress(task_id, "Running cellcli command...", hostname=ilom_host, sid=sid)
        full_cmd = f"cellcli -e \"{cellcli_command}\"\n"
        channel.send(full_cmd)
        time.sleep(12)
        buff = ''
        while channel.recv_ready():
            recv = channel.recv(4096).decode('utf-8', errors='ignore')
            buff += recv
            time.sleep(0.5)
        output += buff
        lines = output.splitlines()
        for line in lines:
            if line.strip():
                safe_emit_progress(task_id, line, hostname=ilom_host, sid=sid)
        if "successfully altered" in output.lower():
            safe_emit_progress(task_id, "Command completed successfully", status='success', hostname=ilom_host, sid=sid)
        else:
            safe_emit_progress(task_id, "Command executed (check output for result)", status='success', hostname=ilom_host, sid=sid)
        return output
    except Exception as e:
        err = f"Failed to run cellcli via ILOM: {str(e)}"
        logger.error(err, exc_info=True)
        safe_emit_progress(task_id, err, status='error', hostname=ilom_host, sid=sid)
        return err
    finally:
        if channel:
            channel.send('\x1b(')
            time.sleep(1)
            channel.send('exit\n')
            time.sleep(1)
        if client:
            client.close()

def execute_function(component_name, func_name, params, pool=None, app=None, socketio=None, sid=None, task_id=None, components=None):
    if components is None:
        components = [component_name] if component_name and component_name != 'global' else []
    for ctype, funcs in scl_functions.items():
        for name, cmd, desc in funcs:
            if name == func_name:
                socketio.emit('message', {'task_id': task_id, 'line': f"[{component_name}] Executing {'ILOM' if func_name.endswith('.ilom') else 'SCL'}: {func_name}", 'status': 'running'}, room=sid)
                group_path = None
                script_path = None
                try:
                    if func_name in ['enable_ssh_login.ilom', 'disable_ssh_login.ilom']:
                        ilom_host = component_name
                        if not ilom_host.endswith('-ilom') and '-ilom.' not in ilom_host:
                            if '.us.oracle.com' in ilom_host:
                                ilom_host = ilom_host.replace('.us.oracle.com', '-ilom.us.oracle.com')
                            else:
                                ilom_host = ilom_host + '-ilom'
                        cellcli_cmd = cmd.strip()
                        result = run_cellcli_via_ilom_console(ilom_host, cellcli_cmd, pool=pool, task_id=task_id, sid=sid, socketio=socketio)
                        with app.app_context():
                            with log_lock:
                                execution_logs[task_id]['status'] = 'success'
                            socketio.emit('message', {'task_id': task_id, 'line': f"[{component_name}] {func_name}: SUCCESS", 'status': 'success'}, room=sid)
                        return result

                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.list') as g:
                        g.write(component_name + '\n')
                        group_path = g.name

                    raw_cmd = cmd.strip()
                    content_lower = raw_cmd.lower()
                    cellcli_starters = ('list ', 'alter ', 'create ', 'drop ', 'set ', 'show ', 'describe ', 'cellcli')
                    is_cellcli = any(content_lower.startswith(kw) for kw in cellcli_starters) or ' cell ' in content_lower

                    # Always create temp script and use -x for reliability
                    script_suffix = '.scl' if is_cellcli else '.sh'
                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=script_suffix) as s:
                        if not is_cellcli:
                            s.write("#!/bin/bash\n")
                        s.write(raw_cmd + "\n")
                        script_path = s.name
                    os.chmod(script_path, 0o755)

                    if func_name.endswith('.ilom'):
                        conn = get_db_pool_connection(pool)
                        cursor = conn.cursor()
                        try:
                            username = 'root'
                            password = get_credential_silent(cursor, 'ILOM', component_name, username) or get_credential_silent(cursor, 'ILOM', 'default', username)
                            child = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no {username}@{component_name}')
                            child.timeout = 30
                            i = child.expect([pexpect.TIMEOUT, 'password:', pexpect.EOF, '-> '])
                            if i == 1:
                                child.sendline(password)
                                child.expect('-> ', timeout=30)
                            elif i == 3:
                                pass
                            else:
                                raise Exception("Connection failed or timed out")
                            lines = []
                            for line_cmd in cmd.splitlines():
                                if line_cmd.strip():
                                    child.sendline(line_cmd)
                                    child.expect('-> ', timeout=30)
                                    output = child.before.decode('utf-8', errors='ignore').strip()
                                    cleaned = '\n'.join(l for l in output.splitlines() if l.strip() and not l.strip().startswith(line_cmd.strip()))
                                    if cleaned.strip():
                                        lines.append(cleaned)
                            full_output = "\n".join(lines)
                            with app.app_context():
                                with log_lock:
                                    execution_logs[task_id]['lines'].extend([f"[{component_name}] {line}" for line in lines if line.strip()])
                                    execution_logs[task_id]['status'] = 'success'
                                if socketio and sid:
                                    for line in lines:
                                        if line.strip():
                                            socketio.emit('message', {'task_id': task_id, 'line': f"[{component_name}] {line}", 'status': 'running'}, room=sid)
                                    socketio.emit('message', {'task_id': task_id, 'line': f"[{component_name}] {func_name}: SUCCESS", 'status': 'success'}, room=sid)
                            return full_output
                        finally:
                            if 'child' in locals():
                                child.sendline('exit')
                                child.close(force=True)
                            cursor.close()
                            release_db_connection(conn, pool)
                    else:
                        if ctype in ('Database Server', 'Guest') or any(k in component_name.lower() for k in ['db', 'adm', 'compute']):
                            dcli_bin = "/usr/bin/dcli_compute"
                        else:
                            dcli_bin = "/usr/bin/dcli"

                        # Always use -x when we created a temp script (fixes temp .sh errors)
                        dcli_cmd = [dcli_bin, "-l", "root", "-g", group_path, "-x", script_path]

                        if DEBUG:
                            logger.info(f"DEBUG [execute_function] Full dcli command: {' '.join(dcli_cmd)}")
                            safe_emit_progress(task_id, f"DEBUG: Executing: {' '.join(dcli_cmd)}", hostname=component_name, sid=sid)

                        process = subprocess.Popen(
                            dcli_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1,
                            universal_newlines=True
                        )
                        output_lines = []
                        for line in iter(process.stdout.readline, ''):
                            line = line.rstrip()
                            if line:
                                output_lines.append(line)
                                socketio.emit('message', {'task_id': task_id, 'line': f"[{component_name}] {line}", 'status': 'running'}, room=sid)
                        process.wait()
                        rc = process.returncode
                        full_output = '\n'.join(output_lines) if output_lines else "Command completed (no output)"
                        if rc != 0:
                            full_output = f"ERROR (dcli exit code {rc}): {full_output}"
                        elif any(kw in full_output.lower() for kw in ['error', 'failed', 'no such file', 'invalid command', 'permission denied']):
                            full_output = f"ERROR: {full_output}"
                        return full_output
                except Exception as e:
                    return f"ERROR executing {func_name}: {str(e)}"
                finally:
                    for p in [group_path, script_path]:
                        if p and os.path.exists(p):
                            try:
                                os.unlink(p)
                            except Exception:
                                pass
    return registry_execute(component_name, func_name, params, pool=pool, app=app, socketio=socketio, sid=sid, task_id=task_id, components=components)

def run_script_background(task_id, component_name, func_name, params, app_obj, sid, components=None):
    with app_obj.app_context():
        try:
            if DEBUG:
                current_app.socketio.emit('message', {'task_id': task_id, 'line': f"DEBUG [run_script_background] received params type={type(params)} value={repr(params)} id={id(params)}", 'status': 'running'}, room=sid)
                logger.info(f"DEBUG [run_script_background] received params type={type(params)} value={repr(params)} id={id(params)}")
            if components is None:
                components = [component_name] if component_name and component_name != 'global' else []
            with log_lock:
                if task_id not in execution_logs:
                    execution_logs[task_id] = {
                        'status': 'running',
                        'lines': [f"[{component_name}] Starting {func_name}..."],
                        'start_time': time.time()
                    }
            current_app.socketio.emit('message', {
                'task_id': task_id,
                'line': execution_logs[task_id]['lines'][-1],
                'status': 'running'
            }, room=sid)
            result = execute_function(
                component_name, func_name, params,
                pool=current_app.config.get('DB_POOL'),
                app=app_obj,
                socketio=current_app.socketio,
                sid=sid,
                task_id=task_id,
                components=components
            )
            new_lines = result.splitlines() if isinstance(result, str) else []
            with log_lock:
                if task_id in execution_logs:
                    for line in new_lines:
                        if line.strip() and line not in execution_logs[task_id]['lines']:
                            execution_logs[task_id]['lines'].append(line)
                    for line in new_lines:
                        current_app.socketio.emit('message', {
                            'task_id': task_id,
                            'line': f"[{component_name}] {line}",
                            'status': 'running'
                        }, room=sid)
            final_status = 'error' if isinstance(result, str) and 'ERROR' in result.upper() else 'success'
            with log_lock:
                if task_id in execution_logs:
                    execution_logs[task_id]['status'] = final_status
            current_app.socketio.emit('message', {
                'task_id': task_id,
                'line': f"[{component_name}] {'Completed with error' if final_status == 'error' else 'Completed successfully'}",
                'status': final_status
            }, room=sid)
        except Exception as e:
            error_line = f"[{component_name}] ERROR: {str(e)}"
            logger.error(f"Error in run_script_background {task_id}: {e}", exc_info=True)
            with log_lock:
                if task_id not in execution_logs:
                    execution_logs[task_id] = {'status': 'error', 'lines': [], 'start_time': time.time()}
                execution_logs[task_id]['lines'].append(error_line)
                execution_logs[task_id]['status'] = 'error'
            current_app.socketio.emit('message', {
                'task_id': task_id,
                'line': error_line,
                'status': 'error'
            }, room=sid)
            current_app.socketio.emit('message', {'task_id': task_id, 'line': f"[{component_name}] Completed with error", 'status': 'error'}, room=sid)

def run_custom_command_background(task_id, components, cmd, app_obj, sid):
    with app_obj.app_context():
        socketio = current_app.socketio
        success_count = 0
        for host in components:
            try:
                socketio.emit('message', {'task_id': task_id, 'line': f'[{host}] Connecting and running: {cmd}', 'status': 'running'}, room=sid)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, username='root', timeout=30, allow_agent=True, look_for_keys=True)
                stdin, stdout, stderr = client.exec_command(cmd, timeout=300)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                ec = stdout.channel.recv_exit_status()
                client.close()
                line = f"[{host}] {output or error or 'Command completed (no output)'}"
                with log_lock:
                    if task_id in execution_logs:
                        execution_logs[task_id]['lines'].append(line)
                socketio.emit('message', {'task_id': task_id, 'line': line, 'status': 'running' if ec == 0 else 'error'}, room=sid)
                if ec == 0:
                    success_count += 1
            except Exception as e:
                line = f"[{host}] ERROR: {str(e)}"
                with log_lock:
                    if task_id in execution_logs:
                        execution_logs[task_id]['lines'].append(line)
                socketio.emit('message', {'task_id': task_id, 'line': line, 'status': 'error'}, room=sid)
        with log_lock:
            if task_id in execution_logs:
                execution_logs[task_id]['status'] = 'success' if success_count == len(components) else 'error'
        socketio.emit('message', {'task_id': task_id, 'line': f'Custom command completed on {success_count}/{len(components)} hosts', 'status': 'success' if success_count == len(components) else 'error'}, room=sid)
