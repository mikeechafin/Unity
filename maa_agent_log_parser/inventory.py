# Version: 2026-06-28 v1.0.1
# Incremental byte-offset tracking via AGENT_LOG_INVENTORY.
import logging

from maa_libraries import get_db_connection_standalone

logger = logging.getLogger(__name__)


def get_last_parsed_byte(hostname: str, agent_home: str, log_path: str) -> int:
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT LAST_PARSED_BYTE FROM MAAMD.AGENT_LOG_INVENTORY
            WHERE HOSTNAME = :1 AND AGENT_HOME = :2 AND LOG_PATH = :3
        """, (hostname, agent_home, log_path))
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception as exc:
        logger.debug('Inventory read failed for %s %s: %s', hostname, log_path, exc)
        return 0
    finally:
        cursor.close()
        conn.close()


def update_log_inventory(hostname: str, agent_home: str, log_path: str, log_type: str, last_byte: int):
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            MERGE INTO MAAMD.AGENT_LOG_INVENTORY t
            USING (SELECT :1 hostname, :2 agent_home, :3 log_path FROM dual) s
            ON (t.HOSTNAME = s.hostname AND t.AGENT_HOME = s.agent_home AND t.LOG_PATH = s.log_path)
            WHEN MATCHED THEN
                UPDATE SET LAST_PARSED_BYTE = :4, LAST_MODIFIED = SYSDATE, PARSED_DATE = SYSDATE,
                           LOG_TYPE = :5
            WHEN NOT MATCHED THEN
                INSERT (HOSTNAME, AGENT_HOME, LOG_PATH, LOG_TYPE, LAST_PARSED_BYTE, LAST_MODIFIED, PARSED_DATE)
                VALUES (:1, :2, :3, :5, :4, SYSDATE, SYSDATE)
        """, (hostname, agent_home, log_path, last_byte, log_type))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def touch_host_inventory(hostname: str, agent_home: str):
    """Update host-level parsed_date when per-file inventory columns are absent."""
    conn = get_db_connection_standalone()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            MERGE INTO MAAMD.AGENT_LOG_INVENTORY dest
            USING (SELECT :1 hostname, :2 agent_home, SYSDATE parsed_date FROM dual) src
            ON (dest.hostname = src.hostname AND dest.agent_home = src.agent_home)
            WHEN MATCHED THEN UPDATE SET dest.parsed_date = src.parsed_date
            WHEN NOT MATCHED THEN INSERT (hostname, agent_home, parsed_date)
            VALUES (src.hostname, src.agent_home, src.parsed_date)
        """, (hostname, agent_home))
        conn.commit()
    finally:
        cursor.close()
        conn.close()