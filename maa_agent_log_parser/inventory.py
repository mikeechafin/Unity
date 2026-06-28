# Version: 2026-03-29 v1.0.0
# Changes: Incremental offset tracking using new AGENT_LOG_INVENTORY table
import oracledb
from maa_libraries import get_db_pool_connection

def get_last_parsed_byte(hostname: str, agent_home: str, log_path: str) -> int:
    """Return last parsed byte offset (0 if new file)."""
    conn = get_db_pool_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT LAST_PARSED_BYTE FROM MAAMD.AGENT_LOG_INVENTORY 
        WHERE HOSTNAME = :1 AND AGENT_HOME = :2 AND LOG_PATH = :3
    """, (hostname, agent_home, log_path))
    row = cursor.fetchone()
    conn.commit()
    return row[0] if row else 0

def update_log_inventory(hostname: str, agent_home: str, log_path: str, log_type: str, last_byte: int):
    """MERGE offset for next run."""
    conn = get_db_pool_connection()
    cursor = conn.cursor()
    cursor.execute("""
        MERGE INTO MAAMD.AGENT_LOG_INVENTORY t
        USING (SELECT :1 hostname, :2 agent_home, :3 log_path FROM dual) s
        ON (t.HOSTNAME = s.hostname AND t.AGENT_HOME = s.agent_home AND t.LOG_PATH = s.log_path)
        WHEN MATCHED THEN
            UPDATE SET LAST_PARSED_BYTE = :4, LAST_MODIFIED = SYSDATE, PARSED_DATE = SYSDATE
        WHEN NOT MATCHED THEN
            INSERT (HOSTNAME, AGENT_HOME, LOG_PATH, LOG_TYPE, LAST_PARSED_BYTE, LAST_MODIFIED, PARSED_DATE)
            VALUES (:1, :2, :3, :5, :4, SYSDATE, SYSDATE)
    """, (hostname, agent_home, log_path, last_byte, log_type))
    conn.commit()
