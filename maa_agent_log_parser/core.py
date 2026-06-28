# Version: 2026-06-28 v2.0.0
# Unified fleet agent log crawler with incremental parsing, normalize, classify, rollup.
import logging
import os
import shlex
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import config
from maa_libraries import get_db_connection_standalone

from .ssh_pool import POOL
from .normalizer import extract_error_from_line
from .inventory import get_last_parsed_byte, update_log_inventory, touch_host_inventory
from . import db_writer
from .global_rollup import populate_agent_error_global
from .regression import run_regression_analysis
from .codex_analyzer import run_codex_analysis

logger = logging.getLogger(__name__)

LOG_FILE_PATTERN = (
    r'^(gcagent\.log|gcagent_sdk\.trc|gcagent_errors\.log|emagent\.log|emctl\.log|'
    r'emdctlj\.log|xa_analytics_.*\.log|\w+\.trc|\w+\.out|OraInstallNG.*\.log)(\.\d+)?$'
)
MAX_LOG_SIZE_MB = 1000
SMALL_FILE_SIZE_MB = 10
SSH_COMMAND_TIMEOUT = 1200
MAX_WORKERS = 50
TEMP_DIR = '/tmp/maa_agent_logs'


def _setup_logging(debug=False):
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    log = logging.getLogger('maa_agent_log_parser')
    if log.handlers:
        return log
    log.setLevel(logging.DEBUG if debug else logging.INFO)
    fh = logging.FileHandler(config.AGENT_PARSER_LOG)
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    log.addHandler(fh)
    if debug:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
        log.addHandler(sh)
    return log


def _read_remote_file(client, log_path, file_size, last_byte):
    """Read new content from log file starting at last_byte offset."""
    if file_size <= last_byte:
        return []

    if file_size < SMALL_FILE_SIZE_MB * 1024 * 1024:
        if last_byte > 0:
            cmd = f"tail -c +{last_byte + 1} {shlex.quote(log_path)}"
        else:
            cmd = f"cat {shlex.quote(log_path)}"
        _, stdout, _ = client.exec_command(cmd, timeout=SSH_COMMAND_TIMEOUT)
        return stdout.readlines()

    local_path = os.path.join(TEMP_DIR, os.path.basename(log_path))
    os.makedirs(TEMP_DIR, exist_ok=True)
    with client.open_sftp() as sftp:
        sftp.get(log_path, local_path)
    with open(local_path, 'r', errors='replace') as f:
        if last_byte > 0:
            f.seek(last_byte)
        lines = f.readlines()
    try:
        os.remove(local_path)
    except OSError:
        pass
    return lines


def process_host(hostname, agent_home, port=None):
    """Crawl one agent home, extract + queue normalized errors."""
    client = None
    files_processed = 0
    errors_found = 0
    try:
        client = POOL.get_client(hostname)
        if not client:
            logger.error('SSH failed for %s', hostname)
            return 0, 0

        find_cmd = (
            f"find {shlex.quote(agent_home + '/sysman/log/')} -type f "
            f"-regextype posix-egrep -regex '{LOG_FILE_PATTERN}' "
            f"-printf '%s\\t%p\\n' 2>/dev/null"
        )
        _, stdout, _ = client.exec_command(find_cmd, timeout=SSH_COMMAND_TIMEOUT)
        log_files = []
        for line in stdout:
            parts = line.strip().split('\t', 1)
            if len(parts) == 2:
                log_files.append((int(parts[0]), parts[1]))

        logger.info('Found %d log files on %s:%s', len(log_files), hostname, agent_home)

        for file_size, log_path in log_files:
            if file_size > MAX_LOG_SIZE_MB * 1024 * 1024:
                continue

            last_byte = get_last_parsed_byte(hostname, agent_home, log_path)
            if file_size <= last_byte:
                continue

            files_processed += 1
            log_type = os.path.splitext(os.path.basename(log_path))[1].lstrip('.') or 'log'
            lines = _read_remote_file(client, log_path, file_size, last_byte)

            for line in lines:
                parsed = extract_error_from_line(line)
                if not parsed:
                    continue
                raw, et, fp, norm = parsed
                db_writer.queue_error(hostname, agent_home, port, raw, norm, et, fp)
                errors_found += 1

            update_log_inventory(hostname, agent_home, log_path, log_type, file_size)

        touch_host_inventory(hostname, agent_home)
        return files_processed, errors_found
    except Exception as exc:
        logger.error('Error processing %s:%s — %s', hostname, agent_home, exc)
        return files_processed, errors_found
    finally:
        if client:
            POOL.release_client(client)


def _get_agent_homes(test_host=None):
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        if test_host:
            cursor.execute(
                'SELECT hostname, agent_home, port FROM maamd.agent_home_info WHERE hostname = :1',
                (test_host,),
            )
        else:
            cursor.execute('SELECT hostname, agent_home, port FROM maamd.agent_home_info')
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def run_parser(debug=False, test_host=None, max_workers=MAX_WORKERS):
    """Crawl fleet agent logs and write normalized errors to DB."""
    log = _setup_logging(debug)
    start = time.time()
    log.info('=== MAA Agent Log Parser v2.0 STARTED ===')

    db_writer.start_writer()
    agents = _get_agent_homes(test_host)
    log.info('Processing %d agent homes', len(agents))

    total_files = 0
    total_errors = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_host, h, ah, p): (h, ah)
            for h, ah, p in agents
        }
        for i, future in enumerate(as_completed(futures), 1):
            hostname, agent_home = futures[future]
            files_proc, err_count = future.result()
            total_files += files_proc
            total_errors += err_count
            log.info('[%d/%d] %s:%s — %d files, %d errors queued',
                     i, len(agents), hostname, agent_home, files_proc, err_count)

    db_writer.flush_and_stop()
    elapsed = time.time() - start
    log.info('Parser finished in %.1fs — %d files, %d errors queued', elapsed, total_files, total_errors)
    return {'files_processed': total_files, 'errors_queued': total_errors, 'elapsed_sec': elapsed}


def run_full_pipeline(debug=False, test_host=None, use_codex=None, max_workers=MAX_WORKERS):
    """
    Full pipeline: crawl → global rollup → regression detection → Codex analysis.
    Set use_codex=True to force AI analysis; None = auto if available.
    """
    log = _setup_logging(debug)
    log.info('=== MAA Agent Log Full Pipeline STARTED ===')

    parse_result = run_parser(debug=debug, test_host=test_host, max_workers=max_workers)

    rollup_count = 0
    try:
        rollup_count = populate_agent_error_global()
    except Exception as exc:
        log.error('Global rollup failed: %s', exc)

    changes = {}
    try:
        changes = run_regression_analysis()
    except Exception as exc:
        log.error('Regression analysis failed: %s', exc)

    analysis = {}
    codex_requested = use_codex if use_codex is not None else config.CODEX_ENABLED
    if codex_requested:
        try:
            analysis = run_codex_analysis(changes)
        except Exception as exc:
            log.error('Codex analysis failed: %s', exc)
            analysis = {'skipped': True, 'reason': str(exc)}

    result = {
        'parse': parse_result,
        'rollup_patterns': rollup_count,
        'changes': {
            'new_count': changes.get('new_count', 0),
            'regression_count': changes.get('regression_count', 0),
            'is_first_run': changes.get('is_first_run', False),
        },
        'codex': {
            'skipped': analysis.get('skipped', False),
            'source': analysis.get('source'),
        },
    }
    log.info('=== Full Pipeline COMPLETE: %s ===', result)
    return result