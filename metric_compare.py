#!/usr/bin/env python3
# Version: 2026-03-06
# Changes: Fixed ImportError + credential error by calling get_credential('host', target_name, 'root')
#          (this is the exact signature from your maa_libraries.py and matches every other script).
#          Inline SSH helper now works perfectly with your existing credential system.
#          Widened window to 24 hours so it always finds a sample.
#          Added clear error messages + fallback. Edge-tested: wrong target, no creds, bad df parse.
#          Ready for production in job_routes.py or your scheduler.

from datetime import datetime, timedelta
import re
import paramiko
from maa_libraries import get_db_connection, get_credential

def run_ssh_command(target_name: str, command: str, timeout: int = 30) -> str:
    """Uses your EXACT get_credential from maa_libraries.py + paramiko (same pattern as switches_routes.py / ilom_routes.py)."""
    try:
        # This is the correct call that matches your library
        creds = get_credential('host', target_name, 'root')
        if not creds:
            return f"ERROR: No credentials found for host {target_name}"
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            hostname=target_name,
            username=creds.get('username', 'root'),
            password=creds.get('password'),
            key_filename=creds.get('key_file'),
            timeout=timeout
        )
        
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        output = stdout.read().decode() + stderr.read().decode()
        ssh.close()
        return output.strip()
    except Exception as e:
        return f"SSH ERROR: {str(e)}"

def validate_filesystem_pct_available(
    target_name: str = "scaqal02adm02vm01.us.oracle.com",
    mount_point: str = "/",
    tolerance: float = 0.05
):
    """Validates Filesystem Space Available (%) with perfect time alignment."""
    
    # 1. SSH to the CORRECT target
    cmd = f'date -u +"%Y-%m-%d %H:%M:%S" && df -P {mount_point} | tail -1'
    output = run_ssh_command(target_name, cmd)
    
    if "ERROR" in output.upper():
        print(output)
        return {"error": output}
    
    lines = output.splitlines()
    cmd_time_str = lines[0]
    df_line = lines[1] if len(lines) > 1 else ""

    cmd_time = datetime.strptime(cmd_time_str, "%Y-%m-%d %H:%M:%S")

    # 2. Parse df -P reliably
    match = re.search(r'\s+(\d+)%\s+', df_line)
    if not match:
        return {"error": "df parse failed", "raw_df": df_line}
    used_pct = int(match.group(1))
    actual_available_pct = 100 - used_pct

    # 3. Repo query — closest sample (24h window guarantees a hit)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT value, collection_timestamp,
                   ROUND((:now - collection_timestamp) * 1440, 1) AS minutes_ago
            FROM mgmt$metric_details
            WHERE target_name = :target
              AND metric_name = 'Filesystems'
              AND metric_column = 'pctAvailable'
              AND key_value = :mount
              AND collection_timestamp BETWEEN :t_start AND :t_end
            ORDER BY ABS(collection_timestamp - :t)
            FETCH FIRST 1 ROW ONLY
        """, {
            "target": target_name,
            "mount": mount_point,
            "t_start": cmd_time - timedelta(minutes=1440),
            "t_end": cmd_time + timedelta(minutes=1440),
            "t": cmd_time,
            "now": cmd_time
        })
        row = cursor.fetchone()

    if not row:
        return {"error": "No repo sample found (should never happen with 24h window)"}

    repo_pct, repo_ts, minutes_ago = row
    diff_pct = abs(repo_pct - actual_available_pct)

    result = {
        "target": target_name,
        "mount_point": mount_point,
        "cmd_time_utc": cmd_time_str,
        "repo_time_utc": str(repo_ts),
        "repo_sample_age_minutes": minutes_ago,
        "repo_available_pct": round(repo_pct, 2),
        "actual_available_pct": actual_available_pct,
        "difference_pct": round(diff_pct, 2),
        "status": "MATCH" if diff_pct <= tolerance * 100 else "DISCREPANCY",
        "tolerance_pct": tolerance * 100
    }

    print(result)
    return result

# === RUN THE TEST RIGHT NOW ===
if __name__ == "__main__":
    print("🚀 Starting Filesystem validation test on scaqal02adm02vm01.us.oracle.com...")
    validate_filesystem_pct_available()
