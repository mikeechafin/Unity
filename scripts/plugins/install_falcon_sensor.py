# Filename: scripts/plugins/install_falcon_sensor.py
# Version: 2026-04-10 v1.1.0
# Changes: Standardized emit() helper with ANSI stripping + fallback logger (exact match to patch_nxos_switch and patch_infiniband_switch). Added ultra-visible reload marker. Fixed broken dcli group file (now properly creates and populates temp node list). Prevents tab output intermingling during concurrent tasks.
from environment_setup_registry import register_function
import tempfile
import os
import subprocess
from maa_libraries import logger
@register_function(
    component_types=["Guest", "Database Server", "Storage Server"],
    params=[] # ZERO parameters - exactly as before
)
def install_falcon_sensor(component_name, params, **kwargs):
    """Original Falcon install - no parameters required."""
    task_id = kwargs.get('task_id')
    sid = kwargs.get('sid')
    socketio = kwargs.get('socketio')

    def emit(msg, status='running'):
        clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
        if socketio and sid:
            socketio.emit('message', {
                'task_id': task_id,
                'line': f'[{component_name}] {clean_line}',
                'status': status
            }, room=sid, namespace='/')
        else:
            logger.warning(f"[install_falcon_sensor] Socket emit skipped - line: {clean_line}")

    # === ULTRA-VISIBLE RELOAD MARKER - MUST APPEAR TO CONFIRM NEW CODE IS RUNNING ===
    emit("=== INSTALL_FALCON_SENSOR v1.1.0 ROBUST EMIT + ANSI CLEANING LOADED - CONCURRENT TAB ISOLATION FIXED ===", status='running')

    try:
        # Create proper temp node list (standard group mode pattern)
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as list_file:
            list_file.write(component_name + '\n')
            list_path = list_file.name

        # Original Falcon install flow (fixed dcli)
        cmd = [
            '/usr/bin/dcli', '-l', 'root', '-g', list_path,
            'wget -q https://falcon.crowdstrike.com/sensor/install.sh -O /tmp/falcon_install.sh && '
            'chmod +x /tmp/falcon_install.sh && '
            '/tmp/falcon_install.sh --cid=YOUR_CID_HERE --tags=exadata && '
            'systemctl start falcon-sensor && '
            'falconctl -g --tags'
        ]

        emit("Starting Falcon sensor install (no parameters)")

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

        for line in iter(process.stdout.readline, ''):
            line = line.rstrip()
            if line.strip():
                emit(line)

        process.wait()

        if process.returncode == 0:
            success_msg = f'Falcon sensor installed and started successfully'
            logger.info(success_msg)
            emit(success_msg, status='success')
            return success_msg
        else:
            error_msg = f'Falcon install failed (exit {process.returncode})'
            logger.error(error_msg)
            emit(error_msg, status='error')
            return error_msg

    except Exception as e:
        error_msg = f'ERROR during Falcon install: {str(e)}'
        logger.error(error_msg)
        emit(error_msg, status='error')
        return error_msg

    finally:
        if 'list_path' in locals() and os.path.exists(list_path):
            try:
                os.unlink(list_path)
            except:
                pass
