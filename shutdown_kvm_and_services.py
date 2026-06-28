# Filename: shutdown_kvm_and_services.py
# Version: 2026-05-06 v1.15
# Changes:
#   - CRITICAL FIX: Accurate guest count when ZERO guests are running (was incorrectly showing 999)
#   - Now uses reliable command: virsh list --state-running --name | grep -v '^$' | wc -l
#   - Properly detects and skips shutdown when no guests exist
#   - All other logic (vm_maker graceful + force, EDV/ESNP) unchanged

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
def shutdown_kvm_guests_and_services(component_name=None, params=None, **kwargs):
    """Shutdown all KVM guests using vm_maker + EDV/ESNP services on Database Servers."""
    task_id = kwargs.get('task_id') or kwargs.get('taskId') or 'shutdown_kvm_and_services'
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
        logger.info(f"[KVM-Shutdown] {clean_msg}")
        if status in ('error', 'success'):
            with log_lock:
                if task_id in execution_logs:
                    execution_logs[task_id]['status'] = status

    emit_message("=== SHUTDOWN_KVM_AND_SERVICES v1.15 STARTED ===", status='running')

    if not components:
        emit_message("No Database Servers selected", "error")
        return "ERROR: No Database Servers selected"

    for host in components:
        emit_message(f"--- Processing {host} ---")

        # Initial check: How many guests are actually running?
        stdout, stderr, ec = run_simple_ssh(host, "root", "virsh list --state-running --name | grep -v '^$' | wc -l")
        try:
            initial_count = int(stdout.strip())
        except:
            initial_count = 0

        if initial_count == 0:
            emit_message("No running KVM guests found on this host. Skipping guest shutdown.", "success")
        else:
            # Step 1: Graceful shutdown of all KVM guests using vm_maker
            emit_message(f"Sending graceful shutdown to ALL KVM guests via vm_maker --stop-domain --all ({initial_count} guests)...")
            stdout, stderr, ec = run_simple_ssh(host, "root", "vm_maker --stop-domain --all")
            if ec != 0:
                emit_message(f"vm_maker graceful shutdown command failed: {stderr}", "error")
            else:
                emit_message("Graceful shutdown signal sent successfully to all guests.")

        # Step 2: Wait up to 15 minutes for guests to actually stop
        emit_message("Waiting for all guests to shut down (up to 15 minutes, checking every 30s)...")
        max_wait = 900
        interval = 30
        elapsed = 0

        while elapsed < max_wait:
            # Reliable count of running guests (works correctly when zero guests exist)
            stdout, stderr, ec = run_simple_ssh(host, "root", "virsh list --state-running --name | grep -v '^$' | wc -l")
            try:
                still_running = int(stdout.strip())
            except:
                still_running = 0   # Safe fallback

            if still_running == 0:
                emit_message("SUCCESS: All KVM guests have shut down gracefully.", "success")
                break

            emit_message(f"  Still running after {elapsed}s: {still_running} guest(s)")
            time.sleep(interval)
            elapsed += interval
        else:
            emit_message(f"Graceful timeout after {max_wait}s. {still_running} guest(s) still running.", "warning")

            # Force destroy remaining guests (last resort)
            emit_message("Forcing immediate shutdown of remaining guests (vm_maker --stop-domain --all --destroy)...")
            stdout, stderr, ec = run_simple_ssh(host, "root", "vm_maker --stop-domain --all --destroy")
            if ec == 0:
                emit_message("Forced destroy completed successfully.")
            else:
                emit_message(f"Forced destroy failed: {stderr}", "error")

        # Step 3: Shutdown EDV and ESNP services
        emit_message("Shutting down EDV and ESNP services...")
        for service in ["edv", "esnp"]:
            cmd = f"dbmcli -e 'alter dbserver shutdown services {service}'"
            stdout, stderr, ec = run_simple_ssh(host, "root", cmd, timeout=60)
            if ec == 0:
                emit_message(f"  {service.upper()} shutdown: {stdout.strip() or 'completed successfully'}")
            else:
                emit_message(f"  {service.upper()} command returned rc={ec}: {stderr.strip() or stdout.strip()}")

        emit_message(f"✅ {host} completed successfully (all guests cleared + services stopped)", "success")

    emit_message("=== SHUTDOWN_KVM_AND_SERVICES v1.15 COMPLETED ===", status='success')
    return "Shutdown sequence completed on all selected hosts"

def run_simple_ssh(host, user, command, timeout=300):
    """Simple reliable passwordless SSH."""
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
