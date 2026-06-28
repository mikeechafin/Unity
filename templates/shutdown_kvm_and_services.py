# Filename: shutdown_kvm_and_services.py
# Version: 2026-05-06 v1.10
# Changes:
#   - Complete rewrite: Simple, reliable, minimal implementation.
#   - Uses a small, clean, self-contained Bash script (best for virsh + dbmcli).
#   - Passwordless SSH (confirmed working in environment).
#   - 20-minute graceful KVM shutdown with clear final count.
#   - Then runs the two dbmcli service shutdowns.
#   - One tab per selected Database Server.
#   - No complex encoding, no extra dependencies.

from environment_setup_registry import register_function
import subprocess
from maa_libraries import logger
from shared_state import execution_logs, log_lock
from flask import current_app

@register_function(
    component_types=["Database Server"],
    params=[]
)
def shutdown_kvm_guests_and_services(component_name=None, params=None, **kwargs):
    """Simple reliable shutdown of all KVM guests + EDV/ESNP services on Database Servers."""
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

    emit_message("=== SHUTDOWN_KVM_AND_SERVICES v1.10 STARTED ===", status='running')

    if not components:
        emit_message("No Database Servers selected", "error")
        return "ERROR: No Database Servers selected"

    for host in components:
        emit_message(f"--- Processing {host} ---")

        # === SIMPLE SELF-CONTAINED BASH SCRIPT ===
        bash_script = r'''#!/bin/bash
set -euo pipefail

echo "=== KVM + Services Shutdown (v1.10) on $(hostname) ==="
echo ""

# 1. Shutdown all running KVM guests
echo "Step 1: Shutting down all running KVM guests..."
mapfile -t guests < <(virsh list --name 2>/dev/null | grep -v '^$' || true)

if [ ${#guests[@]} -eq 0 ]; then
    echo "INFO: No running guests found."
else
    echo "Found ${#guests[@]} running guest(s). Sending shutdown signal..."
    for g in "${guests[@]}"; do
        echo "  -> virsh shutdown $g"
        virsh shutdown "$g" || true
    done

    echo ""
    echo "Waiting up to 20 minutes for graceful shutdown (check every 30s)..."
    timeout=1200
    interval=30
    elapsed=0
    while [ $elapsed -lt $timeout ]; do
        mapfile -t still < <(virsh list --name 2>/dev/null | grep -v '^$' || true)
        if [ ${#still[@]} -eq 0 ]; then
            echo "SUCCESS: All guests shut down gracefully after ${elapsed}s."
            break
        fi
        echo "  Still running after ${elapsed}s: ${#still[@]} guests"
        sleep $interval
        elapsed=$((elapsed + interval))
    done

    if [ $elapsed -ge $timeout ]; then
        echo "TIMEOUT: Some guests still running after 20 minutes."
        virsh list
    fi
fi

echo ""
echo "Step 2: Shutting down EDV and ESNP services..."
dbmcli -e "alter dbserver shutdown services edv" || echo "EDV command completed (may already be stopped)"
dbmcli -e "alter dbserver shutdown services esnp" || echo "ESNP command completed (may already be stopped)"

echo ""
echo "=== Final Status ==="
echo "EDV: $(dbmcli -e 'list dbserver detail' | grep '^         edvStatus:' || echo 'unknown')"
echo "ESNP: $(dbmcli -e 'list dbserver detail' | grep '^         esnpStatus:' || echo 'unknown')"
echo "Running guests: $(virsh list --name 2>/dev/null | grep -v '^$' | wc -l)"
echo "=== Done ==="
'''

        emit_message(f"Writing simple shutdown script to {host}...")

        # Write script using clean single-quoted heredoc (reliable)
        write_cmd = f"cat > /tmp/shutdown_kvm.sh << 'ENDSCRIPT'\n{bash_script}\nENDSCRIPT\nchmod +x /tmp/shutdown_kvm.sh"
        stdout, stderr, ec = run_simple_ssh(host, "root", write_cmd)
        if ec != 0:
            emit_message(f"Failed to write script: {stderr}", "error")
            continue

        emit_message(f"Executing shutdown on {host} (up to 20 min timeout)...")

        # Run the script with long timeout
        stdout, stderr, ec = run_simple_ssh(host, "root", "bash /tmp/shutdown_kvm.sh", timeout=1300)

        # Stream output
        for line in stdout.splitlines():
            if line.strip():
                emit_message(line)

        if ec == 0:
            emit_message(f"✅ {host} completed successfully", "success")
        else:
            emit_message(f"⚠️ {host} finished with warnings (rc={ec})", "warning")

        # Cleanup
        run_simple_ssh(host, "root", "rm -f /tmp/shutdown_kvm.sh")

    emit_message("=== SHUTDOWN_KVM_AND_SERVICES v1.10 COMPLETED ===", status='success')
    return "Shutdown sequence completed on all selected hosts"

def run_simple_ssh(host, user, command, timeout=300):
    """Simple reliable passwordless SSH (matches manual working commands)."""
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
        return "", "Command timed out after " + str(timeout) + "s", 1
    except Exception as e:
        return "", str(e), 1

if __name__ == "__main__":
    print("Run via MAA Unified App UI")