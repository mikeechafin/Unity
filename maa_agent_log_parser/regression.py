# Version: 2026-06-28 v1.0.0
# Detect new errors and regressions by comparing fingerprint snapshots between runs.
import json
import logging
import os
from datetime import datetime, timezone

import config

logger = logging.getLogger(__name__)


def _load_json(path):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as exc:
        logger.warning('Failed to read %s: %s', path, exc)
        return None


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def build_snapshot_from_db():
    """Build current fingerprint snapshot from agent_errors."""
    from maa_libraries import get_db_connection_standalone
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT error_hash, error_type,
                   MAX(normalized_message) AS normalized_message,
                   MAX(error_message) AS sample_message,
                   SUM(occurrence_count) AS total_count,
                   COUNT(DISTINCT hostname) AS host_count
            FROM maamd.agent_errors
            GROUP BY error_hash, error_type
        """)
        fingerprints = {}
        for fp, et, norm, sample, total, hosts in cursor:
            fingerprints[fp] = {
                'error_type': et,
                'normalized_message': (norm or sample or '')[:500],
                'sample_message': (sample or '')[:500],
                'total_count': int(total or 0),
                'host_count': int(hosts or 0),
            }
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'fingerprint_count': len(fingerprints),
            'fingerprints': fingerprints,
        }
    finally:
        cursor.close()
        conn.close()


def detect_changes(current, previous):
    """Return dict with new_errors and regressions lists."""
    if not previous:
        return {
            'new_errors': list(current.get('fingerprints', {}).values())[:50],
            'regressions': [],
            'is_first_run': True,
        }

    prev_fps = previous.get('fingerprints', {})
    curr_fps = current.get('fingerprints', {})
    new_errors = []
    regressions = []

    for fp, data in curr_fps.items():
        if fp not in prev_fps:
            new_errors.append({**data, 'fingerprint': fp, 'change': 'new'})
            continue
        prev_count = prev_fps[fp].get('total_count', 0)
        curr_count = data.get('total_count', 0)
        delta = curr_count - prev_count
        if prev_count > 0:
            pct = (delta / prev_count) * 100
        else:
            pct = 100 if delta > 0 else 0
        if delta >= config.REGRESSION_MIN_DELTA and pct >= config.REGRESSION_SPIKE_PCT:
            regressions.append({
                **data,
                'fingerprint': fp,
                'previous_count': prev_count,
                'current_count': curr_count,
                'delta': delta,
                'pct_change': round(pct, 1),
                'change': 'regression',
            })

    new_errors.sort(key=lambda x: x.get('total_count', 0), reverse=True)
    regressions.sort(key=lambda x: x.get('pct_change', 0), reverse=True)
    return {
        'new_errors': new_errors[:50],
        'regressions': regressions[:50],
        'is_first_run': False,
        'new_count': len([fp for fp in curr_fps if fp not in prev_fps]),
        'regression_count': len(regressions),
    }


def run_regression_analysis():
    """Snapshot DB state, compare to previous, persist results."""
    current = build_snapshot_from_db()
    previous = _load_json(config.AGENT_ERROR_PREVIOUS_SNAPSHOT)
    changes = detect_changes(current, previous)

    _save_json(config.AGENT_ERROR_SNAPSHOT_FILE, current)

    history_dir = os.path.join(config.AGENT_ERROR_ANALYSIS_DIR, 'history')
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    _save_json(os.path.join(history_dir, f'snapshot_{ts}.json'), current)

    result = {
        'timestamp': current['timestamp'],
        'fingerprint_count': current['fingerprint_count'],
        **changes,
    }
    _save_json(config.AGENT_ERROR_CHANGES_FILE, result)

    # Rotate: current becomes previous for next run
    _save_json(config.AGENT_ERROR_PREVIOUS_SNAPSHOT, current)

    logger.info(
        'Regression analysis: %d new fingerprints, %d regressions',
        result.get('new_count', len(changes.get('new_errors', []))),
        result.get('regression_count', 0),
    )
    return result