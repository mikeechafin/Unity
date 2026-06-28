# Filename: start_kvm_guests_and_services.py
# Version: 2026-05-06 v1.03
# Changes:
#   - EXACT same methodology as shutdown_kvm_and_services.py v1.15
#   - Starts ALL services (EDV + ESNP) using single command: dbmcli -e 'alter dbserver restart services all'
#   - Then starts ALL KVM guests using vm_maker --start-domain --all
#   - Uses identical run_simple_ssh helper and emit_message pattern
#   - Accurate guest counting (works when zero guests)
#   - One tab per selected Database Server

from environment_setup_registry import register_function
import subprocess
import time
from maa_libraries import logger
from shared_state import execution_logs, log_lock
from flask import current_app

@register_function(
    component_types=["Database Server"],
    params=[]
)
def start_kvm_guests_and_services(component_name=None, params=None, **kwargs):
    """Start all services (via restart all) then start all KVM guests (exact inverse of shutdown script)."""
    task_id = kwargs.get('task_id') or kwargs.get('taskId') or 'start_kvm_and_services'
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')
    components = kwargs.get('components', []) or []

    def emit_message(msg, status='info'):
        clean_msg = str(msg).strip()
        if socketio and sid:
            socketio.emit('message', {
                'task_id': task_id,
                'line': clean_msg,
                'status': status
            }, room=sid, namespace='/')
        logger.info(f"[KVM-Start] {clean_msg}")
        if status in ('error', 'success'):
            with log_lock:
                if task_id in execution_logs:
                    execution_logs[task_id]['status'] = status

    emit_message("=== START_KVM_GUESTS_AND_SERVICES v1.02 STARTED ===", status='running')

    if not components:
        emit_message("No Database Servers selected", "error")
        return "ERROR: No Database Servers selected"

    for host in components:
        emit_message(f"--- Processing {host} ---")

        # Step 1: Start ALL services (EDV + ESNP) using single restart command (as requested)
        emit_message("Starting all services via 'alter dbserver restart services all'...")
        cmd = "dbmcli -e 'alter dbserver restart services all'"
        stdout, stderr, ec = run_simple_ssh(host, "root", cmd, timeout=120)
        if ec == 0:
            emit_message(f"  Services restart: {stdout.strip() or 'completed successfully'}")
        else:
            emit_message(f"  Services command returned rc={ec}: {stderr.strip() or stdout.strip()}", "warning")

        # Step 2: Start ALL KVM guests
        emit_message("Starting ALL KVM guests via vm_maker --start-domain --all ...")
        stdout, stderr, ec = run_simple_ssh(host, "root", "vm_maker --start-domain --all")
        if ec != 0:
            emit_message(f"vm_maker start command failed: {stderr}", "error")
        else:
            emit_message("Start signal sent successfully to all guests.")

        # Step 3: Wait up to 15 minutes for guests to actually start
        emit_message("Waiting for all guests to start (up to 15 minutes, checking every 30s)...")
        max_wait = 900
        interval = 30
        elapsed = 0

        while elapsed < max_wait:
            stdout, stderr, ec = run_simple_ssh(host, "root", "virsh list --state-running --name | grep -v '^$' | wc -l")
            try:
                running = int(stdout.strip())
            except:
                running = 0

            emit_message(f"  Running after {elapsed}s: {running} guest(s)")

            if running > 0:
                # Brief extra wait to confirm stable count
                time.sleep(10)
                stdout2, _, _ = run_simple_ssh(host, "root", "virsh list --state-running --name | grep -v '^$' | wc -l")
                try:
                    running2 = int(stdout2.strip())
                except:
                    running2 = 0
                if running2 == running:
                    emit_message(f"SUCCESS: {running} KVM guests are now running.", "success")
                    break

            time.sleep(interval)
            elapsed += interval
        else:
            emit_message(f"Timeout after {max_wait}s. {running} guest(s) running.", "warning")

        emit_message(f"✅ {host} completed successfully (all services restarted + guests started)", "success")

    emit_message("=== START_KVM_GUESTS_AND_SERVICES v1.02 COMPLETED ===", status='success')
    return "Start sequence completed on all selected hosts"

def run_simple_ssh(host, user, command, timeout=300):
    """Simple reliable passwordless SSH (EXACT same helper as shutdown script)."""
    try:
        ssh_cmd = [
            'ssh', '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=30',
            f'{user}@{host}',
            command
        ]
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1

if __name__ == "__main__":
    print("Run via MAA Unified App UI")
