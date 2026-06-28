# Version: 2026-06-28 v1.0.0
# AI-powered fleet error analysis — new issues, regressions, recommended actions.
import json
import logging
import os
from datetime import datetime, timezone

import config

logger = logging.getLogger(__name__)


def _build_prompt(changes: dict, top_global: list) -> str:
    new_errors = changes.get('new_errors', [])[:15]
    regressions = changes.get('regressions', [])[:15]

    lines = [
        'Analyze this Oracle Enterprise Manager agent fleet error report.',
        'Identify: (1) new issues requiring attention, (2) regressions/spikes,',
        '(3) patterns across agents, (4) recommended remediation priority.',
        '',
        f"Snapshot time: {changes.get('timestamp', 'unknown')}",
        f"Total unique fingerprints: {changes.get('fingerprint_count', 0)}",
        f"New error patterns: {changes.get('new_count', len(new_errors))}",
        f"Regressions detected: {changes.get('regression_count', len(regressions))}",
        '',
        '=== NEW ERROR PATTERNS (first appearance) ===',
    ]
    for i, err in enumerate(new_errors, 1):
        lines.append(
            f"{i}. [{err.get('error_type')}] hosts={err.get('host_count')} "
            f"count={err.get('total_count')}: {err.get('normalized_message', '')[:200]}"
        )

    lines.append('')
    lines.append('=== REGRESSIONS (occurrence spike) ===')
    for i, err in enumerate(regressions, 1):
        lines.append(
            f"{i}. [{err.get('error_type')}] +{err.get('delta')} ({err.get('pct_change')}%) "
            f"{err.get('previous_count')} -> {err.get('current_count')}: "
            f"{err.get('normalized_message', '')[:200]}"
        )

    lines.append('')
    lines.append('=== TOP FLEET-WIDE ERRORS (AGENT_ERROR_GLOBAL) ===')
    for i, row in enumerate(top_global[:10], 1):
        lines.append(
            f"{i}. [{row.get('error_type')}] occurrences={row.get('total_occurrences')} "
            f"agents={row.get('agent_home_count')}: {row.get('error_message', '')[:200]}"
        )

    lines.append('')
    lines.append(
        'Respond in markdown with sections: Executive Summary, New Issues, '
        'Regressions, Fleet Patterns, Recommended Actions (prioritized P1/P2/P3).'
    )
    return '\n'.join(lines)


def _fetch_top_global_errors(limit=15):
    from maa_libraries import get_db_connection_standalone
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            SELECT NORMALIZED_ERROR_MESSAGE, ERROR_TYPE, TOTAL_OCCURRENCES, AGENT_HOME_COUNT
            FROM MAAMD.AGENT_ERROR_GLOBAL
            ORDER BY TOTAL_OCCURRENCES DESC
            FETCH FIRST {int(limit)} ROWS ONLY
        """)
        rows = []
        for msg, et, total, homes in cursor:
            rows.append({
                'error_message': msg,
                'error_type': et,
                'total_occurrences': int(total or 0),
                'agent_home_count': int(homes or 0),
            })
        return rows
    finally:
        cursor.close()
        conn.close()


def run_codex_analysis(changes: dict = None, force: bool = False) -> dict:
    """
    Run Codex AI analysis on latest regression data.
    Returns analysis dict saved to AGENT_ERROR_ANALYSIS_FILE.
    """
    from maa_codex_client import run_codex_prompt, is_codex_available

    if not force and not is_codex_available():
        logger.info('Codex not available — skipping AI analysis')
        return {'skipped': True, 'reason': 'codex_unavailable'}

    if changes is None:
        if os.path.isfile(config.AGENT_ERROR_CHANGES_FILE):
            with open(config.AGENT_ERROR_CHANGES_FILE, 'r') as f:
                changes = json.load(f)
        else:
            changes = {}

    top_global = _fetch_top_global_errors()
    prompt = _build_prompt(changes, top_global)

    try:
        ai_result = run_codex_prompt(prompt)
    except RuntimeError as exc:
        logger.warning('Codex analysis skipped: %s', exc)
        return {'skipped': True, 'reason': str(exc)}

    analysis = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'source': ai_result.get('source'),
        'model': ai_result.get('model'),
        'changes_summary': {
            'new_count': changes.get('new_count', 0),
            'regression_count': changes.get('regression_count', 0),
            'fingerprint_count': changes.get('fingerprint_count', 0),
        },
        'new_errors': changes.get('new_errors', [])[:20],
        'regressions': changes.get('regressions', [])[:20],
        'analysis_markdown': ai_result.get('text', ''),
    }

    os.makedirs(config.AGENT_ERROR_ANALYSIS_DIR, exist_ok=True)
    with open(config.AGENT_ERROR_ANALYSIS_FILE, 'w') as f:
        json.dump(analysis, f, indent=2, default=str)

    history_path = os.path.join(
        config.AGENT_ERROR_ANALYSIS_DIR, 'history',
        f"analysis_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
    )
    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    with open(history_path, 'w') as f:
        json.dump(analysis, f, indent=2, default=str)

    logger.info('Codex analysis saved to %s', config.AGENT_ERROR_ANALYSIS_FILE)
    return analysis