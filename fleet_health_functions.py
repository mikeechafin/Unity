#!/usr/bin/env python3
"""Parse production logs for SSH and ILOM failure trends."""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

import config

SSH_UNREACHABLE = re.compile(r'Port 22 not reachable')
SSH_AUTH_FAIL = re.compile(r'Authentication failed|atomic force-append for root failed|root-fallback for oracle failed|Bootstrap failed')
SSH_DCLI_WARN = re.compile(r'dcli -l root -k returned non-zero')
ILOM_TIMEOUT = re.compile(r'Connection timed out to (.+?) after')
ILOM_SKIP = re.compile(r'Skipping unreachable ILOM host')
ILOM_NO_CREDS = re.compile(r'No ILOM credentials in ACCESS_CREDENTIALS')
FAILED_HOSTS_LINE = re.compile(r'FAILED hosts \((\d+)\):')
TS_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})')


def _parse_ts(line):
    m = TS_PATTERN.match(line)
    if not m:
        return None
    raw = m.group(1).replace('T', ' ')
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S,%f'):
        try:
            return datetime.strptime(raw.split(',')[0], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
    return None


def _read_log_tail(path, max_lines=50000):
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
        return lines[-max_lines:]
    except OSError:
        return []


def parse_ssh_log(lines=None):
    lines = lines if lines is not None else _read_log_tail(config.SSH_SETUP_LOG)
    stats = {
        'unreachable': 0,
        'auth_failed': 0,
        'dcli_warnings': 0,
        'failed_runs': [],
        'top_failed_hosts': Counter(),
        'daily_errors': defaultdict(int),
    }
    for line in lines:
        ts = _parse_ts(line)
        day = ts.strftime('%Y-%m-%d') if ts else 'unknown'
        if 'ERROR' in line or 'WARNING' in line:
            stats['daily_errors'][day] += 1
        if SSH_UNREACHABLE.search(line):
            stats['unreachable'] += 1
        if SSH_AUTH_FAIL.search(line):
            stats['auth_failed'] += 1
            host_m = re.search(r'\[([^\]]+)\]', line)
            if host_m:
                stats['top_failed_hosts'][host_m.group(1)] += 1
        if SSH_DCLI_WARN.search(line):
            stats['dcli_warnings'] += 1
        fm = FAILED_HOSTS_LINE.search(line)
        if fm:
            stats['failed_runs'].append({
                'count': int(fm.group(1)),
                'timestamp': ts.isoformat() if ts else None,
            })
    stats['failed_runs'] = stats['failed_runs'][-20:]
    stats['top_failed_hosts'] = stats['top_failed_hosts'].most_common(15)
    stats['daily_errors'] = dict(sorted(stats['daily_errors'].items())[-14:])
    stats['log_exists'] = os.path.isfile(config.SSH_SETUP_LOG)
    stats['log_size_mb'] = round(os.path.getsize(config.SSH_SETUP_LOG) / 1048576, 2) if stats['log_exists'] else 0
    return stats


def parse_ilom_log(lines=None):
    lines = lines if lines is not None else _read_log_tail(config.ILOM_COLLECT_LOG)
    stats = {
        'timeouts': 0,
        'skipped_unreachable': 0,
        'no_credentials': 0,
        'timeout_hosts': Counter(),
        'daily_errors': defaultdict(int),
    }
    for line in lines:
        ts = _parse_ts(line)
        day = ts.strftime('%Y-%m-%d') if ts else 'unknown'
        if 'ERROR' in line:
            stats['daily_errors'][day] += 1
        tm = ILOM_TIMEOUT.search(line)
        if tm:
            stats['timeouts'] += 1
            stats['timeout_hosts'][tm.group(1)] += 1
        if ILOM_SKIP.search(line):
            stats['skipped_unreachable'] += 1
        if ILOM_NO_CREDS.search(line):
            stats['no_credentials'] += 1
    stats['timeout_hosts'] = stats['timeout_hosts'].most_common(15)
    stats['daily_errors'] = dict(sorted(stats['daily_errors'].items())[-14:])
    stats['log_exists'] = os.path.isfile(config.ILOM_COLLECT_LOG)
    stats['log_size_mb'] = round(os.path.getsize(config.ILOM_COLLECT_LOG) / 1048576, 2) if stats['log_exists'] else 0
    return stats


def get_fleet_health_summary():
    ssh = parse_ssh_log()
    ilom = parse_ilom_log()
    last_ssh_run = ssh['failed_runs'][-1] if ssh['failed_runs'] else None
    return {
        'ssh': ssh,
        'ilom': ilom,
        'summary': {
            'ssh_unreachable': ssh['unreachable'],
            'ssh_auth_failed': ssh['auth_failed'],
            'ssh_last_failed_count': last_ssh_run['count'] if last_ssh_run else 0,
            'ilom_timeouts': ilom['timeouts'],
            'ilom_skipped': ilom['skipped_unreachable'],
            'health_score': _compute_health_score(ssh, ilom),
        },
    }


def _compute_health_score(ssh, ilom):
    """Simple 0-100 score — higher is healthier."""
    penalty = min(100, (
        ssh['unreachable'] * 0.01
        + ssh['auth_failed'] * 0.05
        + ilom['timeouts'] * 0.1
    ))
    return max(0, round(100 - penalty, 1))