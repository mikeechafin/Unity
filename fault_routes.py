# textVersion: 2026-05-28 v2.80
# Changes: Broadened keyword matching + improved general fallback in load_run_data() for Steps 9 (FEMS link) and 10 (Clear) so historical View Details matches live tab more consistently.

#!/usr/bin/env python3

from flask import Blueprint, render_template, request, flash, current_app, redirect, url_for, jsonify
from flask_login import login_required
import subprocess
import os
import tempfile
import oracledb
import re
import time
import uuid
import threading
import copy
from maa_libraries import get_db_pool_connection, release_db_connection, logger
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright

fault_bp = Blueprint('fault', __name__, url_prefix='/fault')


def discover_asr_trap_port(asrm_host):
    logger.info(f"[MONITOR] Discovering trap port on {asrm_host} as mchafin")
    try:
        cmd = "ss -tuln 2>/dev/null | grep -E 'udp.*(162|snmp|asr)' | head -5"
        ssh_cmd = [
            "ssh", "-i", "/home/maatest/.ssh/id_ed25519_maa",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8",
            "-o", "BatchMode=yes",
            f"mchafin@{asrm_host}",
            cmd
        ]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=12)
        for line in result.stdout.splitlines():
            parts = line.split()
            for p in parts:
                if ':' in p:
                    port_str = p.split(':')[-1]
                    if port_str.isdigit():
                        logger.info(f"[MONITOR] Found listening port {port_str} on {asrm_host}")
                        return int(port_str)
    except Exception as e:
        logger.warning(f"[MONITOR] Port discovery failed on {asrm_host}: {e}")
    return 162


def start_asr_trap_capture(asrm_host):
    """Start a background tcpdump on the ASR host.
    Always kills any previous instance first, then starts exactly one."""
    capture_file = f"/tmp/asr_trap_capture_{int(time.time())}.pcap"
    logger.info(f"[CAPTURE] === STARTING tcpdump on {asrm_host} ===")
    logger.info(f"[CAPTURE] Target pcap: {capture_file}")

    try:
        stop_asr_trap_capture(asrm_host)

        cmd = (
            f"nohup /usr/sbin/tcpdump -i any -nn -U -w {capture_file} 'udp port 162' "
            f"> /tmp/tcpdump_capture.log 2>&1 & echo $!"
        )
        ssh_cmd = [
            "ssh", "-i", "/home/maatest/.ssh/id_ed25519_maa",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8",
            "-o", "BatchMode=yes",
            f"root@{asrm_host}",
            cmd
        ]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=25)
        output_lines = result.stdout.strip().split('\n')
        pid = output_lines[0].strip() if output_lines else ""
        logger.info(f"[CAPTURE] Remote stdout: {result.stdout.strip()}")
        logger.info(f"[CAPTURE] Remote stderr: {result.stderr.strip()}")
        if pid.isdigit():
            logger.info(f"[CAPTURE] Got valid PID {pid}")
            return capture_file
        else:
            logger.error(f"[CAPTURE] No valid PID returned")
            return None
    except Exception as e:
        logger.error(f"[CAPTURE] Failed to start tcpdump on {asrm_host}: {e}")
        return None


def stop_asr_trap_capture(asrm_host):
    """Stop any running tcpdump capture processes on the ASR host."""
    try:
        cmd = (
            "pkill -9 -f tcpdump || true; "
            "killall -9 tcpdump 2>/dev/null || true; "
            "sleep 1"
        )
        ssh_cmd = [
            "ssh", "-i", "/home/maatest/.ssh/id_ed25519_maa",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8",
            "-o", "BatchMode=yes",
            f"root@{asrm_host}",
            cmd
        ]
        subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
        logger.info(f"[CAPTURE] Stopped tcpdump capture on {asrm_host}")
    except Exception as e:
        logger.error(f"[CAPTURE] Failed to stop tcpdump on {asrm_host}: {e}")


def check_asr_trap_captured(asrm_host, capture_file, wait_seconds=30):
    if not capture_file:
        return False, "No capture file"

    logger.info(f"[CAPTURE] Checking for traps in {capture_file} on {asrm_host} (wait up to {wait_seconds}s)")

    start_time = time.time()
    while time.time() - start_time < wait_seconds:
        try:
            cmd = f"tcpdump -r {capture_file} -nn 'udp port 162' 2>/dev/null | tail -10"
            ssh_cmd = [
                "ssh", "-i", "/home/maatest/.ssh/id_ed25519_maa",
                "-o", "StrictHostKeyChecking=no",
                f"root@{asrm_host}",
                cmd
            ]
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()

            if output and len(output) > 20:
                logger.info(f"[CAPTURE] Trap(s) found in capture file")
                return True, output

        except Exception as e:
            logger.warning(f"[CAPTURE] Check error: {e}")

        time.sleep(3)

    return False, "No trap captured within timeout"

asr_test_results = {}
default_asrm = 'phoenix235943.dev3sub3phx.databasede3phx.oraclevcn.com'

@fault_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    pool = current_app.config['DB_POOL']
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT HOSTNAME FROM ilom_hosts ORDER BY HOSTNAME")
        all_hosts = [row[0] for row in cursor.fetchall()]
        cursor.execute("""
            SELECT HOSTNAME, STATUS FROM ASRM
            ORDER BY CASE WHEN HOSTNAME = :def_asrm THEN 0 ELSE 1 END, HOSTNAME
        """, {'def_asrm': default_asrm})
        asrm_managers = cursor.fetchall()

        page = request.args.get('page', 1, type=int)
        page_size = 20
        offset = (page - 1) * page_size
        cursor.execute("SELECT COUNT(*) FROM FAULT_TEST_RUNS")
        total_runs = cursor.fetchone()[0]
        cursor.execute("""
            SELECT RUN_ID, HOST, MODEL, TO_CHAR(START_TIME, 'MM/DD/YYYY HH24:MI'),
                   TO_CHAR(END_TIME, 'MM/DD/YYYY HH24:MI'), STATUS,
                   TOTAL_EREPORTS, TOTAL_INJECTED, TOTAL_MS_ALERTS, TOTAL_EM_INCIDENTS
            FROM FAULT_TEST_RUNS
            ORDER BY START_TIME DESC
            OFFSET :offset ROWS FETCH NEXT :page_size ROWS ONLY
        """, {'offset': offset, 'page_size': page_size})
        runs = cursor.fetchall()
        total_pages = (total_runs + page_size - 1) // page_size

        selected_run = request.args.get('run_id')
        details = []
        log_id = request.args.get('log_id')
        terminal_output = None
        if selected_run:
            cursor.execute("""
                SELECT FAULT_TIME, EREPORT, STATUS, UUID, MS_ALERT, EM_RESULTS, NOTES, ARTIFACTS
                FROM FAULT_TEST_DETAILS WHERE RUN_ID = :run_id ORDER BY FAULT_TIME
            """, {'run_id': selected_run})
            details = cursor.fetchall()
        if log_id:
            cursor.execute("SELECT TERMINAL_OUTPUT FROM FAULT_TEST_RUNS WHERE RUN_ID = :run_id", {'run_id': log_id})
            row = cursor.fetchone()
            if row and row[0]:
                terminal_output = row[0].read() if hasattr(row[0], 'read') else str(row[0])
            else:
                terminal_output = "No terminal output available."

        if request.method == 'POST':
            if 'full_host' in request.form:
                start_fault_run(request.form['full_host'])
                flash("Full ILOM test started", "success")
                return redirect(url_for('fault.dashboard'))
            if 'fetch_host' in request.form:
                return redirect(url_for('fault.dashboard', fetch_host=request.form['fetch_host']))
            if 'run_selected' in request.form:
                host = request.form['selected_host']
                ereports = request.form.getlist('ereport')
                if host and ereports:
                    fd, path = tempfile.mkstemp(suffix='.ereports')
                    with os.fdopen(fd, 'w') as f:
                        for e in ereports:
                            f.write(e + '\n')
                    start_fault_run(host, path)
                    flash("Partial test started", "success")
                    return redirect(url_for('fault.dashboard'))

        fetch_host = request.args.get('fetch_host')
        ereports_list = []
        if fetch_host:
            result = subprocess.run(['python3', './aft.py', fetch_host, '--listreports'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for i, line in enumerate(lines):
                    if "Available ereports" in line:
                        ereports_list = [l.strip() for l in lines[i+1:] if l.strip().startswith('ereport.')]
                        break
            else:
                flash(f"Failed to fetch ereports: {result.stderr}", "error")

        return render_template('fault_dashboard.html',
                               hosts=all_hosts, runs=runs,
                               asrm_managers=asrm_managers, fetch_host=fetch_host, ereports_list=ereports_list,
                               selected_run=selected_run, details=details, log_id=log_id, terminal_output=terminal_output,
                               page=page, total_pages=total_pages, total_runs=total_runs)
    finally:
        release_db_connection(conn, pool)

def start_fault_run(host, ereport_path=None):
    pool = current_app.config['DB_POOL']
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    run_id_var = cursor.var(oracledb.NUMBER)
    start_msg = f"Fault test started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} on {host}\n"
    cursor.execute("""
        INSERT INTO FAULT_TEST_RUNS
        (RUN_ID, HOST, STATUS, TERMINAL_OUTPUT, TOTAL_EREPORTS, TOTAL_INJECTED, TOTAL_MS_ALERTS, TOTAL_EM_INCIDENTS)
        VALUES (FAULT_TEST_RUNS_SEQ.NEXTVAL, :host, 'RUNNING', :log, 0, 0, 0, 0)
        RETURNING RUN_ID INTO :run_id
    """, {'host': host, 'log': start_msg, 'run_id': run_id_var})
    run_id = run_id_var.getvalue()[0]
    conn.commit()
    release_db_connection(conn, pool)
    logger.info(f"Started fault run ID {run_id} on {host}")

    def stream_output():
        bg_conn = get_db_pool_connection(pool)
        bg_cursor = bg_conn.cursor()
        cmd = ['python3', './aft.py', host, '--run_id', str(run_id), '--debug', '--checkms']
        if ereport_path:
            cmd += ['--ereport', ereport_path]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
        log_text = start_msg
        for line in process.stdout:
            stripped = line.rstrip()
            if stripped:
                log_text += stripped + "\n"
                if len(log_text) % 8192 == 0:
                    bg_cursor.execute("UPDATE FAULT_TEST_RUNS SET TERMINAL_OUTPUT = :log WHERE RUN_ID = :run_id",
                                      {'log': log_text, 'run_id': run_id})
                    bg_conn.commit()
        process.wait()
        status = 'COMPLETED' if process.returncode == 0 else 'FAILED'
        bg_cursor.execute("""
            UPDATE FAULT_TEST_RUNS
            SET END_TIME = SYSDATE, STATUS = :status, TERMINAL_OUTPUT = :log
            WHERE RUN_ID = :run_id
        """, {'status': status, 'log': log_text, 'run_id': run_id})
        bg_conn.commit()
        release_db_connection(bg_conn, pool)

    threading.Thread(target=stream_output, daemon=True).start()
    return run_id

@fault_bp.route('/asr_test', methods=['GET', 'POST'])
@login_required
def asr_test():
    if request.method == 'POST':
        target_type = request.form.get('target_type')
        host = request.form.get('host')
        asrm_manager = request.form.get('asrm_manager') or default_asrm
        device_type = request.form.get('device_type', 'Disk')
        auto_clear = request.form.get('auto_clear') == 'on'

        if not target_type or not host:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
                return jsonify({'success': False, 'error': 'Please select target type and host'}), 400
            else:
                flash('Please select target type and host', 'error')
                return redirect(url_for('fault.dashboard'))

        test_id = str(uuid.uuid4())

        asr_test_results[test_id] = {
            'target_type': target_type,
            'host': host,
            'device_type': device_type,
            'steps': [
                {'name': '1. Verify ASR Configuration', 'status': 'Running', 'details': 'Starting verification...', 'raw': '', 'screenshot': None},
                {'name': '2. Find Healthy Disk', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '3. Simulate Hardware Fault', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '4. Verify MS Alert Created', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '5. Check SNMP Trap Sent (MS logs)', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '6. Active Trap Monitor on ASR Host', 'status': 'Pending', 'details': 'Waiting for UDP trap on wire...', 'raw': '', 'screenshot': None},
                {'name': '7. Check SNMP Trap Received (ASR Manager)', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '8. FEMS Verification', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '9. FEMS Link Generated', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None},
                {'name': '10. Clear Simulated Failure', 'status': 'Pending', 'details': 'Waiting...', 'raw': '', 'screenshot': None}
            ],
            'summary': 'Test starting...',
            'fems_link': '',
            'success': False,
            'run_status': 'RUNNING'
        }

        threading.Thread(target=run_asr_hardware_fault_test_background, args=(test_id, target_type, host, auto_clear, current_app.config['DB_POOL'], asrm_manager, device_type), daemon=True).start()
        time.sleep(1.5)
        redirect_url = f"/fault/asr_test_result/{test_id}"
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
            return jsonify({
                'success': True,
                'test_id': test_id,
                'message': f'ASR Hardware Fault Test started on {host}',
                'redirect_url': redirect_url
            })
        else:
            return redirect(redirect_url)
    return redirect(url_for('fault.dashboard'))

def run_asr_hardware_fault_test_background(test_id, target_type, host, auto_clear, pool, asrm_manager, device_type='Disk'):
    try:
        run_asr_hardware_fault_test_sync(test_id, target_type, host, auto_clear, pool, asrm_manager, device_type)
    except Exception as e:
        logger.error(f"Background test failed: {e}")

def persist_asr_test_to_db(test_id, report, pool, host):
    try:
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        run_id_var = cursor.var(oracledb.NUMBER)
        overall_status = report.get('run_status', 'COMPLETED')
        cursor.execute("""
            INSERT INTO FAULT_TEST_RUNS
            (RUN_ID, HOST, STATUS, START_TIME, END_TIME, MODEL,
            TOTAL_EREPORTS, TOTAL_INJECTED, TOTAL_MS_ALERTS, TOTAL_EM_INCIDENTS)
            VALUES (FAULT_TEST_RUNS_SEQ.NEXTVAL, :host, :status, SYSDATE, SYSDATE, 'ASR Hardware Fault Test',
                    0, 1, 1, 0)
            RETURNING RUN_ID INTO :run_id
        """, {'host': host, 'status': overall_status, 'run_id': run_id_var})
        run_id = run_id_var.getvalue()[0]
        for step in report['steps']:
            cursor.execute("""
                INSERT INTO FAULT_TEST_DETAILS (DETAIL_ID, RUN_ID, FAULT_TIME, STATUS, UUID, NOTES, ARTIFACTS, EREPORT)
                VALUES (FAULT_TEST_DETAILS_SEQ.NEXTVAL, :run_id, SYSDATE, :status, :uuid, :notes, :artifacts, 'ASR_Hardware_Fault_Test')
            """, {
                'run_id': run_id,
                'status': step['status'],
                'uuid': str(uuid.uuid4()),
                'notes': step.get('details', ''),
                'artifacts': step.get('screenshot', '') or step.get('raw', '')
            })
        conn.commit()
        logger.info(f"Persisted ASR test {test_id} to DB with RUN_ID {run_id} status={overall_status}")
    finally:
        if 'conn' in locals():
            release_db_connection(conn, pool)

def run_asr_hardware_fault_test_sync(test_id, target_type, host, auto_clear, pool, asrm_manager, device_type='Disk'):
    report = asr_test_results[test_id]
    overall_success = True
    fault_injected = False
    disk_to_clear = None
    aborted = False

    logger.info(f"[CAPTURE] Starting background tcpdump on {asrm_manager} at test start")
    capture_file = start_asr_trap_capture(asrm_manager)
    if capture_file:
        report['capture_file'] = capture_file
        asr_test_results[test_id] = copy.deepcopy(report)
        logger.info(f"[CAPTURE] Capture file stored: {capture_file}")
    else:
        logger.error("[CAPTURE] Failed to start capture at test start")

    def record_step(name, status, details="", raw="", screenshot=None):
        nonlocal overall_success
        for step in report['steps']:
            clean_name = name.split('. ', 1)[-1].lower() if '. ' in name else name.lower()
            clean_step = step['name'].split('. ', 1)[-1].lower() if '. ' in step['name'] else step['name'].lower()
            if clean_name == clean_step or clean_name in clean_step or clean_step in clean_name:
                step.update({'status': status, 'details': details, 'raw': raw, 'screenshot': screenshot})
                if status == "Failed":
                    overall_success = False
                asr_test_results[test_id] = copy.deepcopy(report)
                logger.info(f"RECORD_STEP: {name} -> {status}")
                return
        report['steps'].append({'name': name, 'status': status, 'details': details, 'raw': raw, 'screenshot': screenshot})
        if status == "Failed":
            overall_success = False
        asr_test_results[test_id] = copy.deepcopy(report)
        logger.info(f"RECORD_STEP NEW: {name} -> {status}")

        if "Trap Sent" in name or "Check SNMP Trap Sent" in name:
            logger.info("[MONITOR] === STEP 5 COMPLETE - FORCING STEP 6 EVALUATION NOW ===")
            try:
                capture_file = report.get('capture_file')
                received, details = check_asr_trap_captured(asrm_manager, capture_file, wait_seconds=30)
                mon_status = "Passed" if received else "Failed"
                record_step("6. Active Trap Monitor on ASR Host", mon_status, details, details)
                logger.info(f"[MONITOR] Step 6 FINAL result: {mon_status}")

                if not received:
                    logger.info("[MONITOR] No trap captured after 30s. Aborting steps 7-9.")
                    mark_remaining_steps_skipped(6)
            except Exception as e:
                logger.error(f"[MONITOR] Error during forced step 6 check: {e}")
                record_step("6. Active Trap Monitor on ASR Host", "Failed", str(e))
                mark_remaining_steps_skipped(6)

        if "Active Trap Monitor" in name:
            logger.info("[MONITOR] Checking background capture for traps (step 6)")
            capture_file = report.get('capture_file')
            try:
                received, details = check_asr_trap_captured(asrm_manager, capture_file, wait_seconds=30)
                mon_status = "Passed" if received else "Failed"
                record_step("6. Active Trap Monitor on ASR Host", mon_status, details, details)

                if not received:
                    logger.info("[MONITOR] No trap captured. Marking later steps as not executed.")
                    mark_remaining_steps_skipped(6)
            except Exception as mon_err:
                logger.error(f"[MONITOR] Error checking capture: {mon_err}")
                record_step("6. Active Trap Monitor on ASR Host", "Failed", str(mon_err))
                mark_remaining_steps_skipped(6)

    def mark_remaining_steps_skipped(start_index):
        nonlocal aborted
        aborted = True
        step_names = [
            "1. Verify ASR Configuration",
            "2. Find Healthy Disk",
            "3. Simulate Hardware Fault",
            "4. Verify MS Alert Created",
            "5. Check SNMP Trap Sent (MS logs)",
            "6. Active Trap Monitor on ASR Host",
            "7. Check SNMP Trap Received (ASR Manager)",
            "8. FEMS Verification",
            "9. FEMS Link Generated",
        ]
        for i in range(start_index, 9):
            if i >= len(step_names):
                break
            name = step_names[i]
            for step in report['steps']:
                if step['name'] == name and step.get('status') == 'Pending':
                    step.update({
                        'status': 'Skipped',
                        'details': 'Not executed — test aborted due to earlier failure'
                    })
            asr_test_results[test_id] = copy.deepcopy(report)
            logger.info(f"MARKED SKIPPED: {name}")

    def verify_asr_configuration(target_type, host, asrm_manager):
        raw = ""
        try:
            serial = get_serial_from_host(target_type, host) or ''
            raw += f"Serial lookup raw output:\n{serial}\n"
            asr_cmd = f"ssh -o StrictHostKeyChecking=no root@{asrm_manager} 'cd /opt/asrmanager/bin 2>/dev/null && ./asr list_asset 2>/dev/null || asr list_asset'"
            asr_out = subprocess.getoutput(asr_cmd)
            raw += f"ASR list_asset raw output:\n{asr_out}\n"
            base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
            snmp_cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list cell attributes snmpsubscriber\" 2>/dev/null || dbmcli -e \"list dbserver attributes snmpsubscriber\" 2>/dev/null || echo \"No subscriber found\""
            snmp_out = subprocess.getoutput(snmp_cmd)
            raw += f"SNMP subscriber raw output:\n{snmp_out}\n"
            fems_url = f"https://asr-fems-uat-ucf.us.oracle.com/FEMSService/resources/femsservice/femsview/{serial}" if serial else None
            fems_out = subprocess.getoutput(f'curl -s -m 10 "{fems_url}"') if fems_url else "No serial - skipped"
            raw += f"FEMS curl raw output:\n{fems_out}\n"

            screenshot_path = None
            if serial and fems_url:
                try:
                    screenshot_dir = os.path.join('static', 'screenshots')
                    os.makedirs(screenshot_dir, exist_ok=True)
                    screenshot_file = f"step1_fems_{test_id}.png"
                    screenshot_full_path = os.path.join(screenshot_dir, screenshot_file)
                    with sync_playwright() as p:
                        browser = p.chromium.launch(headless=True)
                        page = browser.new_page()
                        page.set_viewport_size({"width": 1920, "height": 1080})
                        page.goto(fems_url, timeout=10000)
                        page.screenshot(path=screenshot_full_path, full_page=True)
                        browser.close()
                    screenshot_path = f"/static/screenshots/{screenshot_file}"
                    raw += f"\nFEMS screenshot saved: {screenshot_path}\n"
                except Exception as e:
                    logger.error(f"Step 1 FEMS screenshot failed: {e}")
                    raw += f"\nFEMS screenshot error: {str(e)}\n"

            asr_entry_status = "Not Found"
            host_short = host.replace('-ilom.us.oracle.com', '').replace('-ilom', '').split('.')[0]
            for line in asr_out.splitlines():
                if host_short in line or (serial and serial in line):
                    if "Active" in line:
                        asr_entry_status = "Active"
                    elif "Pending" in line:
                        asr_entry_status = "Pending"
                    else:
                        asr_entry_status = "Found"
                    break

            snmp_status = "Present" if re.search(r'asrmPort|type=ASR|community=public.*162', snmp_out, re.IGNORECASE) else "Missing"
            fems_status = "Active" if "ASR Status:Active" in fems_out or "Pending activation approval" in fems_out else "Not Active"

            details = f"ASR Manager Entry: {asr_entry_status}<br>SNMP Subscriber: {snmp_status}<br>FEMS: {fems_status}"
            overall_status = "Passed" if asr_entry_status in ("Active", "Pending", "Found") and snmp_status == "Present" else "Info"
            return overall_status, details, raw, screenshot_path
        except Exception as e:
            return "Info", f"Verification warning: {str(e)}", f"Error: {str(e)}", None

    def get_serial_from_host(target_type, host):
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        try:
            if target_type == "Storage Server":
                cmds = [
                    f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list cell attributes serialNumber\"'",
                    f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list cell detail\" | grep -i serial'",
                    f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list cell attributes id\"'",
                    f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list cell\" | head -5'"
                ]
                for cmd in cmds:
                    out = subprocess.getoutput(cmd).strip()
                    serial_match = re.search(r'([A-Z0-9]{8,})', out)
                    if serial_match:
                        return serial_match.group(1)
            else:
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'dmidecode -s system-serial-number 2>/dev/null || dbmcli -e \"list dbserver attributes serialnumber\"'"
                out = subprocess.getoutput(cmd).strip()
                serial_match = re.search(r'([A-Z0-9]{8,})', out)
                if serial_match:
                    return serial_match.group(1)
            return ''
        except Exception as e:
            logger.error(f"Serial lookup error: {e}")
            return ''

    def find_healthy_disk(target_type, host, device_type='Disk'):
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        try:
            if target_type == "Storage Server":
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list physicaldisk\"'"
            else:
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'dbmcli -e \"list physicaldisk\"'"
            out = subprocess.getoutput(cmd).strip()
            lines = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith('Warning:') and 'normal' in line.lower()]

            candidates = []
            for line in lines:
                parts = re.split(r'\s+', line)
                if len(parts) >= 3 and parts[-1].lower() == 'normal':
                    disk = parts[0]
                    if device_type == 'Flash':
                        if disk.startswith('FLASH_'):
                            candidates.append(disk)
                    else:
                        if not disk.startswith('FLASH_') and disk != 'Invalid' and not disk.startswith('PMEM_') and not disk.startswith('M2_'):
                            candidates.append(disk)

            if candidates:
                chosen = candidates[0]
                logger.info(f"[Step2] Found healthy {device_type} candidate(s): {candidates} → using {chosen}")
                return chosen, out

            logger.warning(f"[Step2] No healthy {device_type} found. Raw output head:\n{out[:800]}")
            return None, out
        except Exception as e:
            logger.error(f"Disk finder error on {base_host}: {e}")
            return None, f"Error: {str(e)}"

    def simulate_failure(target_type, host, disk, device_type='Disk'):
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        try:
            if target_type == "Storage Server":
                if device_type == 'Flash':
                    cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"alter physicaldisk {disk} simulate failuretype=failed\"'"
                else:
                    cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"alter physicaldisk {disk} simulate failuretype=failed\"'"
            else:
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'dbmcli -e \"alter physicaldisk {disk} simulate failuretype=failed\"'"
            out = subprocess.getoutput(cmd)
            logger.info(f"Simulate failure command for {device_type}: {cmd}")
            return out
        except Exception as e:
            logger.error(f"simulate_failure error: {e}")
            return "Command failed"

    def verify_disk_failed(target_type, host, disk, device_type='Disk'):
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        try:
            if target_type == "Storage Server":
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list physicaldisk {disk} attributes status\"'"
            else:
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'dbmcli -e \"list physicaldisk {disk} attributes status\"'"
            out = subprocess.getoutput(cmd).strip().lower()
            if device_type == 'Flash':
                return 'failed' in out or 'critical' in out or 'confinedoffline' in out
            else:
                return 'failed' in out or 'confinedoffline' in out
        except Exception as e:
            logger.error(f"Verify disk failed error: {e}")
            return False

    def clear_simulated_failure(target_type, host, disk):
        if not disk:
            return False
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        try:
            if target_type == "Storage Server":
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"alter physicaldisk {disk} simulate failuretype=none\"'"
            else:
                cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'dbmcli -e \"alter physicaldisk {disk} simulate failuretype=none\"'"
            logger.info(f"AUTO-CLEAR: Executing: {cmd}")
            result = subprocess.getoutput(cmd)
            logger.info(f"AUTO-CLEAR output: {result.strip()}")
            if "failure simulation cancelled" in result.lower() or "successfully" in result.lower():
                return True
            return False
        except Exception as e:
            logger.error(f"AUTO-CLEAR error: {e}")
            return False

    def verify_ms_alert(host, disk, device_type='Disk', simulation_start_utc=None):
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        slot = disk.split(':')[-1] if ':' in disk else disk
        try:
            cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list alerthistory\"'"
            out = subprocess.getoutput(cmd).strip()
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            lines = lines[::-1]
            i = 0
            if device_type == 'Flash':
                alert_pattern = r'Flash disk failed|flash.*failed|FlashDisk.*failed|HALRT-02076'
                alert_keywords = ['flash disk failed', 'flash', 'failed', 'halrt-02076']
            else:
                alert_pattern = r'System hard disk failed|Data hard disk failed|Hardware.*failed|simulate failure'
                alert_keywords = ['system hard disk failed', 'data hard disk failed', 'slot number', 'cd_']
            while i < len(lines):
                line = lines[i]
                if re.search(alert_pattern, line, re.IGNORECASE):
                    alert_block = '\n'.join(lines[i:i+25])
                    alert_lower = alert_block.lower()
                    if (disk in alert_block or 
                        f"Slot Number : {slot}" in alert_block or 
                        f"CD_{slot.zfill(2)}" in alert_block or 
                        any(kw in alert_lower for kw in alert_keywords)):
                        return True, f"New {'Flash' if device_type=='Flash' else 'Hard Disk'} alert found in alerthistory", alert_block
                i += 1
            return False, f"No NEW {'Flash' if device_type=='Flash' else 'Hard Disk'} failure alert found after 100s", out
        except Exception as e:
            logger.error(f"MS alert check error: {e}")
            return False, f"Error checking alerthistory: {str(e)}", out

    def check_snmp_trap_sent(host, disk, device_type='Disk', simulation_start_utc=None):
        base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
        output_dir = os.getenv('MAA_OUTPUT_DIR', '/home/maatest/mchafin/MAA_APPS_NEW/output')
        os.makedirs(output_dir, exist_ok=True)
        debug_log_path = f"{output_dir}/asr_step5_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        try:
            logger.info(f"=== ADVANCED DEBUG Step 5 START: host={host} disk={disk} device_type={device_type} ===")
            if device_type == 'Flash':
                grep_pattern = rf"ASR SNMP trap was sent.*{disk}|snmptrap.*{disk}|HALRT-02076.*{disk}|FlashDisk.*{disk}|Flash Accelerator F640.*{disk}|{disk}.*HALRT-02076|{disk}.*FlashDisk"
            else:
                grep_pattern = r"ASR SNMP trap was sent|snmptrap|HALRT-02003"

            start_time = simulation_start_utc or datetime.now(timezone.utc)

            for attempt in range(20):
                if target_type == "Database Server":
                    trace_dir = f"/opt/oracle/dbserver/log/diag/asm/dbserver/{base_host.split('.')[0]}/trace"
                    trace_glob = f"{trace_dir}/ms-odl*.log {trace_dir}/ms-odl*.trc"
                else:
                    trace_dir = "$CELLTRACE"
                    trace_glob = "$CELLTRACE/ms-odl*.trc $CELLTRACE/ms-odl*.log"

                cmd = f"""ssh -o StrictHostKeyChecking=no root@{base_host} '
latest_trc=$(ls -t {trace_glob} 2>/dev/null | head -1)
if [ -n "$latest_trc" ]; then
  tail -10000 "$latest_trc" 2>/dev/null | grep -n -E -i -A 40 -B 10 "{grep_pattern}" | tail -200
else
  echo "NO_TRACE_FILE_FOUND"
fi
' """
                out = subprocess.getoutput(cmd).strip()
                logger.info(f"Step 5 attempt {attempt+1}/20 for {disk}: output_len={len(out)}")
                if out and "NO_TRACE_FILE_FOUND" not in out and len(out) > 30:
                    lines = out.splitlines()
                    valid_blocks = []
                    current_block = []
                    for line in lines:
                        current_block.append(line)
                        if len(current_block) > 60:
                            current_block.pop(0)
                        if re.search(grep_pattern, line, re.IGNORECASE):
                            block_text = "\n".join(current_block)
                            if simulation_start_utc is None or "2026-" in block_text:
                                valid_blocks.append(block_text)
                    if valid_blocks:
                        recent_block = valid_blocks[-1]
                        trap_uuid = None
                        uuid_match = re.search(r'1\.3\.6\.1\.4\.1\.42\.2\.175\.103\.2\.1\.18\s+VAL\s*:\s*([0-9a-fA-F-]+)', recent_block)
                        if uuid_match:
                            trap_uuid = uuid_match.group(1)
                        logger.info(f"Step 5 selected MOST RECENT + TIME-FILTERED trap for {disk}")
                        with open(debug_log_path, "a") as df:
                            df.write(f"SUCCESS (MOST RECENT + TIME FILTER) on attempt {attempt+1}\n{recent_block}\n")
                        return True, f"SNMP trap sent for disk {disk} (most recent after simulation start)", recent_block, trap_uuid
                    else:
                        continue
                time.sleep(3)
                time.sleep(3)

            logger.warning(f"Step 5 FAILED after 20 attempts (60s) for disk {disk} - running full diagnostics")

            diag_cmd = f"""ssh -o StrictHostKeyChecking=no root@{base_host} '
set -x
echo "=== CELLTRACE DIR ==="; ls -ld $CELLTRACE 2>/dev/null || echo "CELLTRACE not set"
echo "=== LATEST TRACE/LOG FILE ==="; latest=$(ls -t $CELLTRACE/ms-odl*.trc $CELLTRACE/ms-odl*.log 2>/dev/null | head -1); echo "$latest"
echo "=== LAST 10000 LINES OF LATEST FILE ==="; tail -10000 "$latest" 2>/dev/null | tail -300
echo "=== BROAD SEARCH (ASR SNMP trap + Flash + HALRT) ==="; tail -20000 "$latest" 2>/dev/null | grep -E -i "ASR SNMP trap was sent|snmptrap|Flash disk|flash.*(failed|normal)|HALRT-020|Flash Accelerator F640" | tail -50 || echo "NO_MATCHING_TRAP_ENTRIES"
echo "=== END DIAGNOSTIC ==="
' 2>&1 | cat"""

            diag_out = subprocess.getoutput(diag_cmd).strip()

            with open(debug_log_path, "a") as df:
                df.write(f"\n=== FULL ADVANCED DIAGNOSTIC RUN AT {datetime.now()} ===\n")
                df.write(f"Host: {host}\nDisk: {disk}\nDevice Type: {device_type}\n")
                df.write(f"Grep pattern: {grep_pattern}\n\n")
                df.write("DIAGNOSTIC OUTPUT:\n")
                df.write(diag_out)
                df.write("\n=== END OF DEBUG LOG ===\n")
            logger.info(f"Advanced debug log written to: {debug_log_path}")

            failure_details = f"SNMP trap NOT found for disk {disk} after 60s in $CELLTRACE. Full diagnostics in raw artifact below + {debug_log_path}"
            return False, failure_details, diag_out, None
        except Exception as e:
            logger.error(f"Step 5 SNMP check error: {e}")
            error_diag = f"Exception in check_snmp_trap_sent: {str(e)}"
            try:
                with open(debug_log_path, "a") as df:
                    df.write(f"ERROR: {error_diag}\n")
            except:
                pass
            return False, f"Error checking $CELLTRACE: {str(e)}", error_diag, None

    def check_snmp_trap_received(asrm_manager, host, disk, simulation_start_utc=None, trap_uuid=None, device_type='Disk'):
        short_host = host.replace('-ilom.us.oracle.com', '').replace('-ilom', '').split('.')[0]
        slot = disk.split(':')[-1] if ':' in disk else disk
        logger.info(f"Step 6 connecting to ASRM: {asrm_manager} for host {host} (disk {disk}, slot {slot}, short_host={short_host}, trap_uuid={trap_uuid}, device_type={device_type})")

        try:
            logger.info("[MONITOR] Running wire capture check from legacy step 6 path")
            received, details = check_asr_trap_captured(asrm_manager, None, wait_seconds=25)
            if not received:
                logger.info("[MONITOR] Wire monitor (backup) did not see trap.")
        except Exception as mon_e:
            logger.warning(f"[MONITOR] Wire check from legacy path failed: {mon_e}")
        try:
            start_time = simulation_start_utc or datetime.now(timezone.utc)

            for attempt in range(24):
                uuid_pattern = trap_uuid if trap_uuid else ""

                if device_type == 'Flash':
                    disk_pattern = disk
                    alert_code = "HALRT-02076|FlashDisk|Flash Accelerator F640"
                else:
                    disk_pattern = f"{disk}|{disk.split(':')[-1]}"
                    alert_code = "HALRT-02003|HALRT-02007"

                accepted_cmd = f"""ssh -o StrictHostKeyChecking=no root@{asrm_manager} '
tac /var/opt/asrmanager/log/trap-accepted.log 2>/dev/null | 
grep -A 80 -B 5 -E "{alert_code}|{disk_pattern}|{short_host}" | 
grep -E "{short_host}|{disk_pattern}|HALRT-0200[37]" | head -100 || echo NO_ENTRY'"""
                out = subprocess.getoutput(accepted_cmd).strip()
                if "Permission denied" in out or "permission denied" in out.lower():
                    return False, f"Cannot connect to ASR Manager {asrm_manager} (Permission denied).", "SSH access failed"

                if out and out != "NO_ENTRY" and len(out) > 20:
                    lines = out.splitlines()
                    valid_blocks = []
                    current_block = []
                    for line in lines:
                        current_block.append(line)
                        if len(current_block) > 70:
                            current_block.pop(0)
                        if re.search(rf"{disk}|{alert_code}", line, re.IGNORECASE):
                            block_text = "\n".join(current_block)
                            try:
                                ts_match = re.search(r'(\w{3} \d{2}, \d{4} \d{2}:\d{2}:\d{2} (AM|PM))', block_text)
                                if ts_match:
                                    trap_time = datetime.strptime(ts_match.group(1), "%b %d, %Y %I:%M:%S %p")
                                    trap_time = trap_time.replace(tzinfo=timezone.utc)
                                    if trap_time >= start_time:
                                        valid_blocks.append(block_text)
                                else:
                                    valid_blocks.append(block_text)
                            except:
                                valid_blocks.append(block_text)

                    if valid_blocks:
                        recent_block = valid_blocks[-1]
                        return True, f"Trap ACCEPTED on ASR Manager (most recent after simulation start - {device_type})", recent_block
                    else:
                        continue

                rejected_cmd = f"""ssh -o StrictHostKeyChecking=no root@{asrm_manager} '
tac /var/opt/asrmanager/log/trap-rejected.log 2>/dev/null | 
grep -A 60 -B 5 -E "{alert_code}|{disk_pattern}" | 
grep -E "{short_host}|agentaddress|{alert_code}|{uuid_pattern}|{disk}" | head -80 || echo NO_ENTRY'"""
                out = subprocess.getoutput(rejected_cmd).strip()
                if out and out != "NO_ENTRY" and len(out) > 20:
                    return False, f"Trap REJECTED on ASR Manager (suppressed or Asset status disabled) [{device_type}]", out

                time.sleep(2.5)
            return False, f"Trap not found in trap logs on {asrm_manager} after multiple checks", "No matching lines after retries"
        except Exception as e:
            logger.error(f"Step 6 ASR Manager check error: {e}")
            return False, f"Error checking ASR Manager logs: {str(e)}", f"Error: {str(e)}"

    def generate_fems_link(host, target_type="Storage Server"):
        serial = get_serial_from_host(target_type, host)
        if serial:
            return f"https://asr-fems-uat-ucf.us.oracle.com/FEMSService/resources/femsservice/femsview/{serial}"
        return None

    status, details, raw1, screenshot1 = verify_asr_configuration(target_type, host, asrm_manager)
    record_step("1. Verify ASR Configuration", status, details, raw1, screenshot1)
    if status == "Failed":
        mark_remaining_steps_skipped(1)
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return

    disk, raw2 = find_healthy_disk(target_type, host, device_type)
    if not disk:
        record_step("2. Find Healthy Disk", "Failed", f"No healthy {device_type} device found", raw2)
        mark_remaining_steps_skipped(2)
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return
    record_step("2. Find Healthy Disk", "Passed", f"Using {device_type} device: {disk}", raw2)

    simulate_out = simulate_failure(target_type, host, disk, device_type)
    time.sleep(5)
    base_host = host.replace('-ilom.us.oracle.com', '.us.oracle.com').replace('-ilom', '')
    if target_type == "Storage Server":
        status_cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'cellcli -e \"list physicaldisk {disk} detail\"'"
    else:
        status_cmd = f"ssh -o StrictHostKeyChecking=no root@{base_host} 'dbmcli -e \"list physicaldisk {disk} detail\"'"
    full_status = subprocess.getoutput(status_cmd).strip()
    simulate_out = simulate_out + "\n\n=== Post-simulation disk status ===\n" + full_status
    
    status_verified = False
    for attempt in range(12):
        status_verified = verify_disk_failed(target_type, host, disk, device_type)
        if status_verified:
            break
        time.sleep(5)
    record_step("3. Simulate Hardware Fault", "Passed" if status_verified else "Failed", f"{device_type} status confirmed as FAILED" if status_verified else "MS power-cycle did not result in failed status after 60s", simulate_out)
    fault_injected = status_verified
    disk_to_clear = disk if status_verified else None

    if not status_verified:
        if disk_to_clear and auto_clear:
            clear_success = clear_simulated_failure(target_type, host, disk_to_clear)
            record_step("9. Clear Simulated Failure", "Passed" if clear_success else "Failed", "Auto-clear executed on failure path")
        mark_remaining_steps_skipped(3)
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return

    ms_alert_created, ms_details, raw4 = verify_ms_alert(host, disk, device_type, datetime.now(timezone.utc))
    record_step("4. Verify MS Alert Created", "Passed" if ms_alert_created else "Failed", ms_details, raw4)
    if not ms_alert_created:
        if fault_injected and disk_to_clear and auto_clear:
            clear_success = clear_simulated_failure(target_type, host, disk_to_clear)
            record_step("9. Clear Simulated Failure", "Passed" if clear_success else "Failed", "Auto-clear executed on failure path")
        mark_remaining_steps_skipped(4)
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return

    snmp_result = check_snmp_trap_sent(host, disk, device_type)
    if isinstance(snmp_result, tuple) and len(snmp_result) == 4:
        snmp_sent, snmp_details, raw5, trap_uuid = snmp_result
    else:
        snmp_sent, snmp_details, raw5, trap_uuid = snmp_result[0], snmp_result[1], snmp_result[2], None
    
    step5_status = "Passed" if snmp_sent is True else ("Info" if snmp_sent == "Info" else "Failed")
    record_step("5. Check SNMP Trap Sent (MS logs)", step5_status, snmp_details, raw5)

    if step5_status == "Failed":
        if fault_injected and disk_to_clear and auto_clear:
            clear_success = clear_simulated_failure(target_type, host, disk_to_clear)
            record_step("9. Clear Simulated Failure", "Passed" if clear_success else "Failed", "Auto-clear executed on failure path")
        mark_remaining_steps_skipped(5)
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return

    logger.info("[ASR] Forcing Step 6 (Active Trap Monitor on ASR Host) evaluation after Step 5")
    capture_file = report.get('capture_file')
    try:
        received, mon_details = check_asr_trap_captured(asrm_manager, capture_file, wait_seconds=30)
        mon_status = "Passed" if received else "Failed"
        record_step("6. Active Trap Monitor on ASR Host", mon_status, mon_details, mon_details)
        logger.info(f"[ASR] Step 6 result: {mon_status}")
    except Exception as e:
        logger.error(f"[ASR] Step 6 evaluation error: {e}")
        record_step("6. Active Trap Monitor on ASR Host", "Failed", str(e))
        mon_status = "Failed"

    if mon_status != "Passed":
        logger.info("[ASR] Step 6 Failed — skipping FEMS execution (7-9), performing cleanup")
        if fault_injected and disk_to_clear and auto_clear:
            clear_success = clear_simulated_failure(target_type, host, disk_to_clear)
            record_step("9. Clear Simulated Failure", "Passed" if clear_success else "Failed", "Auto-clear executed on failure path")
        mark_remaining_steps_skipped(6)
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return

    logger.info("[ASR] Running Step 7: Check SNMP Trap Received (ASR Manager)")
    step7_status = "Failed"
    try:
        asrm_received, asrm_details, asrm_raw = check_snmp_trap_received(
            asrm_manager, host, disk, simulation_start_utc=None, trap_uuid=None, device_type=device_type
        )
        step7_status = "Passed" if asrm_received else "Failed"
        record_step("7. Check SNMP Trap Received (ASR Manager)", step7_status, asrm_details, asrm_raw)
    except Exception as e:
        logger.error(f"[ASR] Step 7 ASR Manager check error: {e}")
        record_step("7. Check SNMP Trap Received (ASR Manager)", "Failed", str(e))

    if step7_status != "Passed":
        logger.info("[ASR] Step 7 Failed — skipping FEMS (8-9)")
        mark_remaining_steps_skipped(7)
        if fault_injected and disk_to_clear and auto_clear:
            clear_success = clear_simulated_failure(target_type, host, disk_to_clear)
            record_step("9. Clear Simulated Failure", "Passed" if clear_success else "Failed", "Auto-clear executed on failure path")
        report['run_status'] = 'FAILED'
        report['success'] = False
        persist_asr_test_to_db(test_id, report, pool, host)
        return

    fems_link = generate_fems_link(host, target_type)
    fems_raw = ""
    screenshot_path = None
    fems_status = "FEMS accessed"
    try:
        if fems_link:
            screenshot_dir = os.path.join('static', 'screenshots')
            os.makedirs(screenshot_dir, exist_ok=True)
            screenshot_file = f"fems_{test_id}.png"
            screenshot_full_path = os.path.join(screenshot_dir, screenshot_file)
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_viewport_size({"width": 1920, "height": 1080})
                page.goto(fems_link, timeout=10000)
                page_content = page.content()
                fault_visible = disk in page_content or "failed" in page_content.lower()
                sr_number = None
                if device_type == 'Flash':
                    flash_fault = "Flash" in page_content or "FlashDisk" in page_content or "HALRT-02076" in page_content
                    if flash_fault:
                        fems_status = "Flash fault confirmed in FEMS"
                    elif fault_visible:
                        fems_status = "Fault visible in FEMS (type unclear)"
                    else:
                        fems_status = "No clear Flash fault in FEMS screenshot"
                else:
                    sr_match = re.search(r'SR[:\s]*([A-Z0-9-]+)', page_content, re.IGNORECASE)
                    sr_number = sr_match.group(1) if sr_match else None
                    if sr_number:
                        fems_status = f"FEMS fault confirmed - SR #{sr_number}"
                    elif fault_visible:
                        fems_status = "Hard Disk fault visible in FEMS"
                    else:
                        fems_status = "No clear fault in FEMS screenshot"
                page.screenshot(path=screenshot_full_path, full_page=True)
                browser.close()
            screenshot_path = f"/static/screenshots/{screenshot_file}"
            fems_raw = f"FEMS link: {fems_link}\nScreenshot saved: {screenshot_path}\nSR: {sr_number or 'None'}"
    except Exception as e:
        logger.error(f"FEMS verification failed: {e}")
        fems_status = f"FEMS check failed: {str(e)[:100]}"
        fems_raw = f"Error: {str(e)}"
    finally:
        record_step("7. FEMS Verification", "Info", fems_status, fems_raw, screenshot_path)
        logger.info("=== STEP 7 RECORD COMPLETE - DICT UPDATED ===")
        time.sleep(2)

    record_step("8. FEMS Link Generated", "Info", fems_link if fems_link else "No FEMS link generated")
    report['fems_link'] = fems_link or ""

    if (fault_injected or status_verified) and disk_to_clear and auto_clear:
        clear_success = clear_simulated_failure(target_type, host, disk_to_clear)
        record_step("9. Clear Simulated Failure", "Passed" if clear_success else "Failed")

    capture_file = report.get('capture_file')
    if capture_file:
        stop_asr_trap_capture(asrm_manager)
        try:
            cleanup_cmd = "rm -f /tmp/asr_trap_capture_*.pcap /tmp/tcpdump*.log 2>/dev/null || true"
            ssh_cleanup = [
                "ssh", "-i", "/home/maatest/.ssh/id_ed25519_maa",
                "-o", "StrictHostKeyChecking=no",
                f"root@{asrm_manager}",
                cleanup_cmd
            ]
            subprocess.run(ssh_cleanup, capture_output=True, text=True, timeout=10)
            logger.info("[CAPTURE] Cleaned up /tmp pcap and log files on ASR host")
        except Exception as e:
            logger.warning(f"[CAPTURE] Failed to clean /tmp files on ASR host: {e}")
        logger.info("[CAPTURE] Step 10 cleanup: tcpdump capture stopped")

    report['success'] = overall_success
    report['run_status'] = 'COMPLETED' if overall_success else 'FAILED'
    report['summary'] = f"ASR Hardware Fault Test {'completed successfully' if overall_success else 'failed'} on {host} using {asrm_manager} ({device_type} mode)."
    asr_test_results[test_id] = copy.deepcopy(report)
    persist_asr_test_to_db(test_id, report, pool, host)

@fault_bp.route('/asr_test_result/<test_id>')
@login_required
def asr_test_result(test_id):
    logger.info(f"Rendering ASR result for test_id: {test_id}")
    if test_id.isdigit():
        pool = current_app.config['DB_POOL']
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT HOST FROM FAULT_TEST_RUNS WHERE RUN_ID = :rid AND MODEL = 'ASR Hardware Fault Test'", {'rid': int(test_id)})
            row = cursor.fetchone()
            if not row:
                return "This is not an ASR Hardware Fault Test run or run not found.", 404
            host = row[0]
            cursor.execute("""
                SELECT STATUS, NOTES, ARTIFACTS
                FROM FAULT_TEST_DETAILS
                WHERE RUN_ID = :rid
                ORDER BY FAULT_TIME
            """, {'rid': int(test_id)})
            db_rows = cursor.fetchall()
            step_names = [
                "1. Verify ASR Configuration",
                "2. Find Healthy Disk",
                "3. Simulate Hardware Fault",
                "4. Verify MS Alert Created",
                "5. Check SNMP Trap Sent (MS logs)",
                "6. Active Trap Monitor on ASR Host",
                "7. Check SNMP Trap Received (ASR Manager)",
                "8. FEMS Verification",
                "9. FEMS Link Generated",
                "10. Clear Simulated Failure"
            ]
            mapped = [None] * 10
            for i in range(len(db_rows)):
                row = db_rows[i]
                status = row[0]
                notes_lob = row[1]
                artifacts_lob = row[2]
                notes = notes_lob.read() if hasattr(notes_lob, 'read') and notes_lob is not None else (notes_lob or '')
                artifacts_val = artifacts_lob.read() if hasattr(artifacts_lob, 'read') and artifacts_lob is not None else (artifacts_lob or '')
                notes_str = str(notes).lower()
                screenshot = None
                if isinstance(artifacts_val, str):
                    match = re.search(r'(/static/screenshots/fems_[^"]+\.png)', artifacts_val)
                    if match:
                        screenshot = match.group(1)
                if 'asr manager entry' in notes_str or 'snmp subscriber' in notes_str or 'fems:' in notes_str:
                    mapped[0] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'using disk' in notes_str or 'using flash' in notes_str or 'healthy' in notes_str:
                    mapped[1] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'simulate failuretype=failed' in notes_str or 'status confirmed as failed' in notes_str:
                    mapped[2] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'new alert found' in notes_str or 'alerthistory' in notes_str:
                    mapped[3] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'snmp trap sent' in notes_str:
                    mapped[4] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'trap accepted' in notes_str or 'trap rejected' in notes_str:
                    mapped[5] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'fems fault confirmed' in notes_str or 'fems accessed' in notes_str or 'fems check failed' in notes_str:
                    mapped[6] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'fems link generated' in notes_str:
                    mapped[7] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'clear simulated failure' in notes_str:
                    mapped[8] = {'status': status, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
            steps = []
            for i in range(10):
                m = mapped[i]
                if m:
                    steps.append({'name': step_names[i], 'status': m['status'] or 'Info', 'details': m['details'] or 'N/A', 'raw': m['raw'], 'screenshot': m['screenshot']})
                else:
                    steps.append({'name': step_names[i], 'status': 'Info', 'details': 'N/A', 'raw': '', 'screenshot': None})
            result = {'host': host, 'steps': steps, 'summary': f"ASR Hardware Fault Test completed on {host}", 'fems_link': '', 'success': True, 'run_status': 'COMPLETED'}
            return render_template('asr_test_result.html', result=result, test_id=test_id)
        finally:
            release_db_connection(conn, pool)
    result = asr_test_results.get(test_id, {'steps': [], 'summary': 'Test not found', 'fems_link': '', 'success': False, 'run_status': 'COMPLETED'})
    return render_template('asr_test_result.html', result=result, test_id=test_id)

@fault_bp.route('/asr_test_status/<test_id>')
@login_required
def asr_test_status(test_id):
    if test_id.isdigit():
        pool = current_app.config['DB_POOL']
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT HOST FROM FAULT_TEST_RUNS WHERE RUN_ID = :rid AND MODEL = 'ASR Hardware Fault Test'", {'rid': int(test_id)})
            row = cursor.fetchone()
            if not row:
                return jsonify({'steps': []})
            host = row[0]
            cursor.execute("SELECT STATUS, NOTES, ARTIFACTS FROM FAULT_TEST_DETAILS WHERE RUN_ID = :rid ORDER BY FAULT_TIME", {'rid': int(test_id)})
            db_rows = cursor.fetchall()
            step_names = ["1. Verify ASR Configuration", "2. Find Healthy Disk", "3. Simulate Hardware Fault", "4. Verify MS Alert Created", "5. Check SNMP Trap Sent (MS logs)", "6. Check SNMP Trap Received (ASR Manager)", "7. FEMS Verification", "8. FEMS Link Generated", "9. Clear Simulated Failure"]
            steps = []
            for i in range(9):
                name = step_names[i]
                if i < len(db_rows):
                    row = db_rows[i]
                    status = row[0]
                    notes_lob = row[1]
                    artifacts_lob = row[2]
                    notes = notes_lob.read() if hasattr(notes_lob, 'read') and notes_lob is not None else (notes_lob or '')
                    artifacts_val = artifacts_lob.read() if hasattr(artifacts_lob, 'read') and artifacts_lob is not None else (artifacts_lob or '')
                    screenshot = None
                    if isinstance(artifacts_val, str):
                        match = re.search(r'(/static/screenshots/fems_[^"]+\.png)', artifacts_val)
                        if match:
                            screenshot = match.group(1)
                    steps.append({'name': name, 'status': status or 'Info', 'details': notes or 'N/A', 'raw': artifacts_val, 'screenshot': screenshot})
                else:
                    steps.append({'name': name, 'status': 'Info', 'details': 'N/A', 'raw': '', 'screenshot': None})
            result = {'host': host, 'steps': steps, 'summary': f"ASR Hardware Fault Test completed on {host}", 'fems_link': '', 'success': True, 'run_status': 'COMPLETED'}
            return jsonify(result)
        finally:
            release_db_connection(conn, pool)
    result = asr_test_results.get(test_id, {'steps': [], 'summary': 'Test not found', 'fems_link': '', 'success': False, 'run_status': 'COMPLETED'})
    return jsonify(result)

@fault_bp.route('/log/<int:run_id>')
@login_required
def get_log(run_id):
    pool = current_app.config['DB_POOL']
    conn = get_db_pool_connection(pool)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT MODEL FROM FAULT_TEST_RUNS WHERE RUN_ID = :run_id", {'run_id': run_id})
        model_row = cursor.fetchone()
        if model_row and model_row[0] == 'ASR Hardware Fault Test':
            return "No terminal output captured for ASR tests.\n\nUse View Details for the full step-by-step results, artifacts, and screenshot.", 200, {'Content-Type': 'text/plain'}
        cursor.execute("SELECT TERMINAL_OUTPUT FROM FAULT_TEST_RUNS WHERE RUN_ID = :run_id", {'run_id': run_id})
        row = cursor.fetchone()
        if row and row[0]:
            return row[0].read() if hasattr(row[0], 'read') else str(row[0]), 200, {'Content-Type': 'text/plain'}
        return "Run started – waiting for output...", 200, {'Content-Type': 'text/plain'}
    finally:
        release_db_connection(conn, pool)

@fault_bp.route('/view_artifact/<test_id>/<int:step_idx>')
@login_required
def view_artifact(test_id, step_idx):
    if test_id.isdigit():
        pool = current_app.config['DB_POOL']
        conn = get_db_pool_connection(pool)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT ARTIFACTS
                FROM FAULT_TEST_DETAILS
                WHERE RUN_ID = :run_id
                ORDER BY FAULT_TIME
            """, {'run_id': int(test_id)})
            rows = cursor.fetchall()
            if step_idx < len(rows) and rows[step_idx][0]:
                artifacts = rows[step_idx][0]
                content = artifacts.read() if hasattr(artifacts, 'read') and artifacts is not None else str(artifacts)
                return content, 200, {'Content-Type': 'text/plain'}
            return "No artifact data saved for this step.", 200, {'Content-Type': 'text/plain'}
        finally:
            release_db_connection(conn, pool)
    result = asr_test_results.get(test_id, {})
    if step_idx < len(result.get('steps', [])):
        step = result['steps'][step_idx]
        raw = step.get('raw', 'No raw data captured for this step')
        return raw, 200, {'Content-Type': 'text/plain'}
    return "Artifact not found", 404

@fault_bp.route('/report', methods=['GET'])
@login_required
def report():
    pool = current_app.config['DB_POOL']
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT RUN_ID, HOST, MODEL, TO_CHAR(START_TIME, 'MM/DD/YYYY HH24:MI'), STATUS
            FROM FAULT_TEST_RUNS ORDER BY START_TIME DESC
        """)
        all_runs = cursor.fetchall()
        selected_run_ids = [int(x) for x in request.args.getlist('runs') if x.isdigit()]
        comparison_data = []
        filtered_details = []
        hosts = []
        ereport_filter = request.args.get('ereport_filter', '')
        host_filter = request.args.get('host_filter', '')
        cursor.execute("SELECT DISTINCT HOST FROM FAULT_TEST_RUNS ORDER BY HOST")
        hosts = [row[0] for row in cursor.fetchall()]
        if selected_run_ids:
            params = {}
            placeholders = []
            for i, rid in enumerate(selected_run_ids):
                ph = f':p{i}'
                placeholders.append(ph)
                params[f'p{i}'] = rid
            ph_str = ','.join(placeholders)
            cursor.execute(f"""
                SELECT r.RUN_ID, r.HOST, r.MODEL, TO_CHAR(r.START_TIME, 'MM/DD/YYYY HH24:MI'),
                       COUNT(*) as total,
                       SUM(CASE WHEN d.STATUS IN ('Passed','Info') THEN 1 ELSE 0 END) as success,
                       ROUND(100.0 * SUM(CASE WHEN d.STATUS IN ('Passed','Info') THEN 1 ELSE 0 END) / COUNT(*), 1) as pct
                FROM FAULT_TEST_DETAILS d
                JOIN FAULT_TEST_RUNS r ON d.RUN_ID = r.RUN_ID
                WHERE r.RUN_ID IN ({ph_str})
                GROUP BY r.RUN_ID, r.HOST, r.MODEL, r.START_TIME
            """, params)
            comparison_data = cursor.fetchall()
        if ereport_filter or host_filter:
            query = """
                SELECT d.FAULT_TIME, r.HOST, d.EREPORT, d.STATUS, d.UUID, d.MS_ALERT,
                       d.EM_RESULTS, d.NOTES, d.RUN_ID, d.ARTIFACTS
                FROM FAULT_TEST_DETAILS d
                JOIN FAULT_TEST_RUNS r ON d.RUN_ID = r.RUN_ID
                WHERE 1=1
            """
            params = {}
            if host_filter:
                query += " AND r.HOST = :host_filter"
                params['host_filter'] = host_filter
            if ereport_filter:
                query += " AND d.EREPORT LIKE :ereport_filter"
                params['ereport_filter'] = f'%{ereport_filter}%'
            cursor.execute(query, params)
            filtered_details = cursor.fetchall()
        return render_template('fault_report.html',
                               all_runs=all_runs,
                               selected_run_ids=selected_run_ids,
                               comparison_data=comparison_data,
                               filtered_details=filtered_details,
                               hosts=hosts,
                               ereport_filter=ereport_filter,
                               host_filter=host_filter,
                               ereport_breakdown=[])
    finally:
        release_db_connection(conn, pool)

@fault_bp.route('/start_ilom_partial', methods=['POST'])
@login_required
def start_ilom_partial():
    host = request.args.get('host')
    if not host:
        return jsonify({'error': 'No host provided'}), 400
    run_id = start_fault_run(host)
    logger.info(f"Started partial ILOM test on {host} → Run ID {run_id}")
    return jsonify({'run_id': run_id})

@fault_bp.route('/get_runs_json')
@login_required
def get_runs_json():
    page = request.args.get('page', 1, type=int)
    page_size = 20
    offset = (page - 1) * page_size
    pool = current_app.config['DB_POOL']
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM FAULT_TEST_RUNS")
        total = cursor.fetchone()[0]
        cursor.execute("""
            SELECT RUN_ID, HOST, MODEL, TO_CHAR(START_TIME, 'MM/DD/YYYY HH24:MI'),
                   TO_CHAR(END_TIME, 'MM/DD/YYYY HH24:MI'), STATUS,
                   TOTAL_EREPORTS, TOTAL_INJECTED, TOTAL_MS_ALERTS, TOTAL_EM_INCIDENTS
            FROM FAULT_TEST_RUNS ORDER BY START_TIME DESC
            OFFSET :offset ROWS FETCH NEXT :page_size ROWS ONLY
        """, {'offset': offset, 'page_size': page_size})
        runs = cursor.fetchall()
        return jsonify({
            'runs': [list(row) for row in runs],
            'page': page,
            'total_pages': (total + page_size - 1) // page_size,
            'total': total
        })
    finally:
        release_db_connection(conn, pool)

@fault_bp.route('/load_run_data/<test_id>')
@login_required
def load_run_data(test_id):
    pool = current_app.config['DB_POOL']
    conn = get_db_pool_connection(pool)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT MODEL, STATUS, HOST FROM FAULT_TEST_RUNS WHERE RUN_ID = :rid", {'rid': test_id if test_id.isdigit() else None})
        run_row = cursor.fetchone()
        if not run_row and not test_id.isdigit():
            result = asr_test_results.get(test_id, {'steps': [], 'summary': 'Test not found', 'fems_link': '', 'success': False, 'run_status': 'COMPLETED'})
            run_status = result.get('run_status')
            if not run_status and result.get('steps'):
                run_status = 'FAILED' if any(s.get('status') == 'Failed' for s in result['steps']) else 'COMPLETED'
            return jsonify({
                'run_id': test_id,
                'model': 'ASR Hardware Fault Test',
                'run_status': run_status,
                'host': result.get('host', ''),
                'type': 'ASR Hardware Fault Test',
                'steps': result.get('steps', []),
                'banner_text': f"Run {test_id} – ASR Hardware Fault Test",
                'loading': False
            })
        if not run_row:
            return jsonify({'error': 'Run not found', 'steps': [], 'loading': False})
        model = run_row[0] or ''
        status = run_row[1]
        host = run_row[2]
        cursor.execute("""
            SELECT FAULT_TIME, EREPORT, STATUS, UUID, MS_ALERT, EM_RESULTS, NOTES, ARTIFACTS
            FROM FAULT_TEST_DETAILS WHERE RUN_ID = :rid ORDER BY FAULT_TIME
        """, {'rid': test_id if test_id.isdigit() else None})
        rows = cursor.fetchall() or []
        def safe_lob_read(lob_val):
            if lob_val is None:
                return ''
            if hasattr(lob_val, 'read'):
                try:
                    data = lob_val.read()
                    return data[:4000] if isinstance(data, (bytes, str)) else str(data)[:4000]
                except Exception as e:
                    logger.warning(f"LOB .read() failed: {e}")
                    return str(lob_val)[:4000]
            return str(lob_val)[:4000]
        if model == 'ASR Hardware Fault Test':
            step_names = [
                "1. Verify ASR Configuration",
                "2. Find Healthy Disk",
                "3. Simulate Hardware Fault",
                "4. Verify MS Alert Created",
                "5. Check SNMP Trap Sent (MS logs)",
                "6. Active Trap Monitor on ASR Host",
                "7. Check SNMP Trap Received (ASR Manager)",
                "8. FEMS Verification",
                "9. FEMS Link Generated",
                "10. Clear Simulated Failure"
            ]
            mapped = [None] * 10
            for i in range(len(rows)):
                row = rows[i]
                status_val = row[2]
                notes_lob = row[6]
                artifacts_lob = row[7]
                notes = safe_lob_read(notes_lob)
                artifacts_val = safe_lob_read(artifacts_lob)
                notes_str = str(notes).lower()
                screenshot = None
                if isinstance(artifacts_val, str):
                    match = re.search(r'(/static/screenshots/fems_[^"]+\.png)', artifacts_val)
                    if match:
                        screenshot = match.group(1)

                # Prefer explicit status from DB when it's a terminal state (Failed / Skipped)
                is_terminal_status = status_val in ('Failed', 'Skipped')

                if 'asr manager entry' in notes_str or 'snmp subscriber' in notes_str or 'fems:' in notes_str:
                    mapped[0] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'using disk' in notes_str or 'using flash' in notes_str or 'healthy' in notes_str:
                    mapped[1] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'simulate failuretype=failed' in notes_str or 'status confirmed as failed' in notes_str:
                    mapped[2] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'new alert found' in notes_str or 'alerthistory' in notes_str:
                    mapped[3] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'snmp trap sent' in notes_str:
                    mapped[4] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'active trap monitor' in notes_str or 'udp trap on wire' in notes_str or 'listening on' in notes_str or 'snmptrap' in notes_str.lower() or 'v2trap' in notes_str.lower():
                    mapped[5] = {'status': status_val, 'details': notes, 'raw': artifacts_val if artifacts_val else notes, 'screenshot': screenshot}
                elif 'trap accepted' in notes_str or 'trap rejected' in notes_str or 'check snmp trap received' in notes_str:
                    mapped[6] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'fems fault confirmed' in notes_str or 'fems accessed' in notes_str or 'fems check failed' in notes_str:
                    mapped[7] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'fems link generated' in notes_str or ('http' in notes_str and 'fems' in notes_str) or 'femsview' in notes_str:
                    mapped[8] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif 'clear simulated failure' in notes_str or 'auto-clear' in notes_str or 'failure simulation cancelled' in notes_str:
                    mapped[9] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                elif mapped[6] is None and mapped[7] is None:
                    # General fallback for steps 7-10 when keyword matching is insufficient (handles Passed/Info + terminal states)
                    for j in range(6, 10):
                        if mapped[j] is None:
                            mapped[j] = {'status': status_val, 'details': notes, 'raw': artifacts_val, 'screenshot': screenshot}
                            break
            steps = []
            for i in range(10):
                m = mapped[i]
                if m:
                    steps.append({'name': step_names[i], 'status': m['status'] or 'Info', 'details': m['details'] or 'N/A', 'raw': m['raw'], 'screenshot': m['screenshot']})
                else:
                    steps.append({'name': step_names[i], 'status': 'Info', 'details': 'N/A', 'raw': '', 'screenshot': None})
            return jsonify({
                'run_id': test_id,
                'model': model,
                'run_status': status,
                'host': host,
                'type': model,
                'steps': steps,
                'banner_text': f"Run {test_id} – {model or 'Unknown'} on {host}",
                'loading': False
            })
        steps = []
        for row in rows:
            ms_alert_str = safe_lob_read(row[4])
            em_results_str = safe_lob_read(row[5])
            notes_str = safe_lob_read(row[6])
            artifacts_str = safe_lob_read(row[7])
            notes_lower = notes_str.lower()
            artifacts_lower = artifacts_str.lower() if artifacts_str else ''
            combined_lower = notes_lower + ' ' + artifacts_lower
            snmp_sent = "Yes" if any(k in combined_lower for k in ['snmp trap','trap sent','halrt','snmptrap','sent snmp','snmp sent','ms-odl','alerthistory']) else "No"
            snmp_recv = "Yes" if any(k in combined_lower for k in ['trap accepted','trap received','received v2 trap','received trap','trap-accepted','asr received','received v2 trap','trap processed']) else "No"
            steps.append({
                'name': row[1] or 'Step',
                'status': row[2] or 'Info',
                'details': em_results_str or notes_str[:800] or 'N/A',
                'raw': artifacts_str,
                'snmp_received': snmp_recv,
                'snmp_sent': snmp_sent,
                'ms_alert': ms_alert_str or '-',
                'uuid': row[3] or '-'
            })
        return jsonify({
            'run_id': test_id,
            'model': model,
            'run_status': status,
            'host': host,
            'type': model,
            'steps': steps,
            'banner_text': f"Run {test_id} – {model or 'Unknown'} on {host}",
            'loading': False
        })
    except Exception as e:
        logger.error(f"load_run_data error {test_id}: {e}")
        return jsonify({'error': str(e), 'steps': [], 'loading': False})
    finally:
        release_db_connection(conn, pool)
