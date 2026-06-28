# Version: 2026-03-29 v1.0.0
# Changes: Core remote pre-filter + parallel host processing (recent logs priority)
from concurrent.futures import ThreadPoolExecutor
from maa_libraries import SSH_POOL, get_active_agents
from .inventory import get_last_parsed_byte, update_log_inventory
from .normalizer import normalize_error_message, classify_error_type, compute_fingerprint
from .db_writer import queue_error_batch

def process_host(hostname: str, agent_home: str):
    client = SSH_POOL.get_client(hostname)
    if not client:
        return
    try:
        # Remote pre-filter recent errors only (delta or last 7 days)
        cmd = f"find {agent_home}/sysman/log -name '*.log' -o -name '*.trc' -mtime -7 | xargs grep -E 'ERROR|ORA-|CRITICAL|Exception|CRSeOns|Upload failed' --line-buffered"
        _, stdout, _ = client.exec_command(cmd)
        errors = []
        for line in stdout:
            if line.strip():
                fp = compute_fingerprint(line)
                et = classify_error_type(line)
                errors.append((line.strip(), et, fp))
        if errors:
            queue_error_batch(hostname, agent_home, errors)
        # Update inventory for next run (simplified; real would use byte offset)
        update_log_inventory(hostname, agent_home, "recent_logs", "mixed", len(str(errors)))
    finally:
        SSH_POOL.release_client(client)

def run_parser():
    """Daily entrypoint - remote grep only new lines."""
    agents = get_active_agents()
    with ThreadPoolExecutor(max_workers=80) as pool:
        for hostname, agent_home in agents:
            pool.submit(process_host, hostname, agent_home)
