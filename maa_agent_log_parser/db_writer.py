# Version: 2026-06-28 v1.0.1
# Async batch writer for maamd.agent_errors with normalized_message + fingerprint dedup.
import logging
from queue import Queue, Empty
from threading import Thread

from maa_libraries import get_db_connection_standalone

logger = logging.getLogger(__name__)

DB_BATCH_SIZE = 5000

_ERROR_QUEUE = Queue()
_WRITER_THREAD = None


_MERGE_FULL = """
    MERGE INTO maamd.agent_errors dest
    USING (
        SELECT :1 hostname, :2 agent_home, :3 port, :4 error_message,
               :5 error_message_trunc, :6 normalized_message,
               :7 error_type, :8 error_hash FROM dual
    ) src
    ON (dest.hostname = src.hostname AND dest.error_hash = src.error_hash)
    WHEN MATCHED THEN UPDATE SET
        occurrence_count = occurrence_count + 1,
        last_seen = SYSTIMESTAMP,
        last_updated = SYSDATE
    WHEN NOT MATCHED THEN INSERT (
        hostname, agent_home, port, error_message, error_message_trunc,
        normalized_message, error_type, error_hash,
        occurrence_count, first_seen, last_seen, last_updated
    ) VALUES (
        src.hostname, src.agent_home, src.port, src.error_message,
        src.error_message_trunc, src.normalized_message, src.error_type,
        src.error_hash, 1, SYSTIMESTAMP, SYSTIMESTAMP, SYSDATE
    )
"""

_MERGE_LEGACY = """
    MERGE INTO maamd.agent_errors dest
    USING (
        SELECT :1 hostname, :3 port, :4 error_message,
               :5 error_message_trunc, :7 error_type, :8 error_hash FROM dual
    ) src
    ON (dest.hostname = src.hostname AND dest.error_hash = src.error_hash)
    WHEN MATCHED THEN UPDATE SET
        occurrence_count = occurrence_count + 1,
        last_updated = SYSDATE
    WHEN NOT MATCHED THEN INSERT (
        hostname, port, error_message, error_message_trunc,
        error_type, error_hash, occurrence_count, last_updated
    ) VALUES (
        src.hostname, src.port, src.error_message, src.error_message_trunc,
        src.error_type, src.error_hash, 1, SYSDATE
    )
"""


def _insert_batch(batch):
    conn = None
    try:
        conn = get_db_connection_standalone()
        cursor = conn.cursor()
        use_full = True
        for row in batch:
            try:
                if use_full:
                    cursor.execute(_MERGE_FULL, row)
                else:
                    cursor.execute(_MERGE_LEGACY, row)
            except Exception as col_exc:
                if use_full and 'ORA-' in str(col_exc):
                    logger.warning('Falling back to legacy agent_errors MERGE (missing columns)')
                    conn.rollback()
                    use_full = False
                    cursor.execute(_MERGE_LEGACY, row)
                else:
                    raise
        conn.commit()
        logger.debug('Committed batch of %d agent errors', len(batch))
    except Exception as exc:
        logger.error('Batch insert failed (%d rows): %s', len(batch), exc)
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        if conn:
            conn.close()


def _writer_loop():
    batch = []
    while True:
        try:
            item = _ERROR_QUEUE.get(timeout=1)
            if item is None:
                if batch:
                    _insert_batch(batch)
                return
            batch.append(item)
            if len(batch) >= DB_BATCH_SIZE:
                _insert_batch(batch)
                batch = []
        except Empty:
            if batch:
                _insert_batch(batch)
                batch = []


def start_writer():
    global _WRITER_THREAD
    if _WRITER_THREAD and _WRITER_THREAD.is_alive():
        return
    _WRITER_THREAD = Thread(target=_writer_loop, name='AgentErrorDBWriter', daemon=True)
    _WRITER_THREAD.start()


def queue_error(hostname, agent_home, port, raw, normalized, error_type, fingerprint):
    _ERROR_QUEUE.put((
        hostname, agent_home, port, raw, raw[:4000], normalized, error_type, fingerprint,
    ))


def flush_and_stop():
    _ERROR_QUEUE.put(None)
    if _WRITER_THREAD:
        _WRITER_THREAD.join(timeout=300)