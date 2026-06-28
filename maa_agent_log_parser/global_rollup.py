# Version: 2026-06-28 v1.0.0
# Fleet-wide rollup: AGENT_ERRORS -> AGENT_ERROR_GLOBAL
import logging

from maa_libraries import get_db_connection_standalone
from .normalizer import normalize_error_message, classify_error_type

logger = logging.getLogger(__name__)


def populate_agent_error_global():
    """Rebuild MAAMD.AGENT_ERROR_GLOBAL from per-host agent_errors."""
    logger.info('Starting AGENT_ERROR_GLOBAL rollup')
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute('TRUNCATE TABLE MAAMD.AGENT_ERROR_GLOBAL')

        cursor.execute("""
            SELECT ae.HOSTNAME, ae.ERROR_MESSAGE, ae.ERROR_TYPE, ae.NORMALIZED_MESSAGE,
                   NVL(ae.OCCURRENCE_COUNT, 1), ahi.AGENT_HOME
            FROM MAAMD.AGENT_ERRORS ae
            JOIN MAAMD.AGENT_HOME_INFO ahi ON ae.HOSTNAME = ahi.HOSTNAME
        """)

        aggregated = {}
        for hostname, error_message, error_type, normalized_message, occurrences, agent_home in cursor:
            norm = normalized_message or normalize_error_message(error_message or '')
            et = error_type if error_type and error_type != 'ERROR' else classify_error_type(error_message or '')
            key = (norm, et)
            if key not in aggregated:
                aggregated[key] = {'total': 0, 'homes': set()}
            aggregated[key]['total'] += int(occurrences or 1)
            if agent_home:
                aggregated[key]['homes'].add(agent_home)

        batch = [
            (norm, et, data['total'], len(data['homes']), ','.join(sorted(data['homes'])))
            for (norm, et), data in aggregated.items()
        ]
        if batch:
            cursor.executemany("""
                INSERT INTO MAAMD.AGENT_ERROR_GLOBAL (
                    NORMALIZED_ERROR_MESSAGE, ERROR_TYPE, TOTAL_OCCURRENCES,
                    AGENT_HOME_COUNT, AGENT_HOMES, LAST_UPDATED
                ) VALUES (:1, :2, :3, :4, :5, SYSTIMESTAMP)
            """, batch)
        conn.commit()
        logger.info('AGENT_ERROR_GLOBAL rollup complete: %d unique error patterns', len(batch))
        return len(batch)
    finally:
        cursor.close()
        conn.close()