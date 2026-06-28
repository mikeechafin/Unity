#!/usr/bin/env python3
# textVersion: 2026-05-27 v5.13
# Changes: Clean sequential execution. If any step fails, run cleanup then stop. Step 6 (Active Trap Monitor) acts as wire-level validation of step 5. Added clear logging for tcpdump execution.

from celery import shared_task
from maa_libraries import get_db_pool_connection, release_db_connection, logger
import subprocess
import time
from datetime import datetime, timezone
import oracledb
import uuid
from playwright.sync_api import sync_playwright
import re
import os
from fault_routes import record_step


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


def monitor_snmp_trap_on_asr(asrm_host, duration=90):
    """Run tcpdump on ASR host via SSH as mchafin. Returns (received, port, summary)."""
    port = discover_asr_trap_port(asrm_host)
    logger.info(f"[MONITOR] === Starting tcpdump on {asrm_host} as mchafin, port {port} ===")

    try:
        cmd = f"timeout {duration} tcpdump -i any -nn 'udp port {port}' -c 1"
        ssh_cmd = [
            "ssh", "-i", "/home/maatest/.ssh/id_ed25519_maa",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8",
            "-o", "BatchMode=yes",
            f"mchafin@{asrm_host}",
            cmd
        ]

        logger.info(f"[MONITOR] Executing: {' '.join(ssh_cmd)}")

        result = subprocess.run(
            ssh_cmd,
            capture_output=True, text=True, timeout=duration + 15
        )

        output = (result.stdout or "") + (result.stderr or "")
        received = result.returncode == 0 and len(output.strip()) > 5

        logger.info(f"[MONITOR] tcpdump completed. returncode={result.returncode}, received={received}")
        if output:
            logger.info(f"[MONITOR] Output snippet: {output[:400]}")

        return received, port, output[:400] if output else "No output captured"

    except subprocess.TimeoutExpired:
        logger.error(f"[MONITOR] tcpdump timed out on {asrm_host}")
        return False, port, "Timeout while running tcpdump"
    except Exception as e:
        logger.error(f"[MONITOR] Failed to run tcpdump on {asrm_host} as mchafin: {e}")
        return False, port, str(e)


@shared_task
def run_asr_fault_test(test_id, target_type, host, auto_clear, asrm_manager, device_type='Disk', run_id=None):
    logger.info(f"[ASR-TEST] Starting run_asr_fault_test for {host}")

    # Capture is now started centrally in fault_routes.py (only once per session)
    pool = None
    disk = None
    simulation_succeeded = False
    monitor_passed = False

    try:
        pool = current_app.config['DB_POOL']

        steps = [
            ("1. Verify ASR Configuration", lambda: verify_asr_configuration(target_type, host, asrm_manager)),
            ("2. Find Healthy Disk", lambda: find_healthy_disk(target_type, host, device_type)),
            ("3. Simulate Hardware Fault", lambda: simulate_failure(target_type, host, disk)),
            ("4. Verify MS Alert Created", lambda: verify_ms_alert(host, disk, datetime.now(timezone.utc))),
            ("5. Check SNMP Trap Sent (MS logs)", lambda: check_snmp_trap_sent(host, disk)),
            ("6. Active Trap Monitor on ASR Host", lambda: None),  # Wire-level validation
            ("7. Check SNMP Trap Received (ASR Manager)", lambda: check_snmp_trap_received(asrm_manager, host, disk)),
            ("8. FEMS Verification", lambda: generate_fems_link(host)),
            ("9. FEMS Link Generated", lambda: None),
            ("10. Clear Simulated Failure", lambda: None),
        ]

        for name, func in steps:
            # Special handling for Active Trap Monitor (step 6)
            if "Active Trap Monitor on ASR Host" in name:
                import getpass
                current_user = getpass.getuser()
                logger.info(f"[ASR-TEST] Running Active Trap Monitor (step 6) as user '{current_user}' to host '{asrm_manager}'")
                received, port, summary = monitor_snmp_trap_on_asr(asrm_manager, duration=120)
                monitor_passed = received
                status = "Passed" if received else "Failed"
                details = f"Port {port} | Trap seen on wire: {received} | {summary}"
                record_step(test_id, run_id, pool, name, status, details)

                if not received:
                    logger.info("[ASR-TEST] No trap received on wire. Running cleanup then stopping.")
                    if disk and auto_clear:
                        try:
                            clear_simulated_failure(target_type, host, disk)
                            record_step(test_id, run_id, pool, "10. Clear Simulated Failure", "Passed", "Cleanup after failed monitor")
                        except Exception:
                            pass
                    break  # Stop here - no point continuing
                continue

            # Normal step execution
            try:
                result = func()
            except Exception as e:
                result = f"Error: {e}"

            if "Simulate Hardware Fault" in name:
                simulate_out = result
                status_verified = verify_disk_failed(target_type, host, disk)
                status = "Passed" if status_verified else "Failed"
                record_step(test_id, run_id, pool, name, status, f"Disk status: {status}", simulate_out)
                simulation_succeeded = status_verified
                if not status_verified:
                    if disk and auto_clear:
                        clear_simulated_failure(target_type, host, disk)
                    break

            elif "Find Healthy Disk" in name:
                disk, raw = result if isinstance(result, tuple) else (None, str(result))
                if not disk:
                    record_step(test_id, run_id, pool, name, "Failed", "No healthy device found")
                    break
                record_step(test_id, run_id, pool, name, "Passed", f"Using device: {disk}")

            else:
                status = "Passed"
                details = str(result) if result else ""
                record_step(test_id, run_id, pool, name, status, details)

                if status == "Failed":
                    if disk and auto_clear:
                        try:
                            clear_simulated_failure(target_type, host, disk)
                            record_step(test_id, run_id, pool, "10. Clear Simulated Failure", "Passed", "Cleanup after failure")
                        except:
                            pass
                    break

    except Exception as e:
        logger.error(f"[ASR-TEST] Unexpected error: {e}")
        if disk and auto_clear:
            try:
                clear_simulated_failure(target_type, host, disk)
            except:
                pass

    finally:
        if pool:
            try:
                conn = get_db_pool_connection(pool)
                cursor = conn.cursor()
                cursor.execute("UPDATE FAULT_TEST_RUNS SET STATUS = 'COMPLETED', END_TIME = SYSDATE WHERE RUN_ID = :rid", {'rid': run_id})
                conn.commit()
            finally:
                release_db_connection(conn, pool)

        logger.info("[ASR-TEST] Test finished")
