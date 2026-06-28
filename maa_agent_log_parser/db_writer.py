# Version: 2026-03-29 v1.0.0
# Changes: Batch writer for AGENT_ERRORS + AGENT_ERROR_GLOBAL + AGENT_ERROR_HISTORY
def queue_error_batch(hostname: str, agent_home: str, error_list):
    """MERGE using fingerprint as unique key for dedup + global rollup."""
    conn = get_db_pool_connection()
    cursor = conn.cursor()
    for raw, et, fp in error_list:
        cursor.execute("""
            MERGE INTO maamd.agent_errors t
            USING (SELECT :1 hostname, :2 agent_home, :3 raw, :4 et, :5 fp FROM dual) s
            ON (t.hostname = s.hostname AND t.error_hash = s.fp)
            WHEN MATCHED THEN UPDATE SET occurrence_count = occurrence_count + 1
            WHEN NOT MATCHED THEN INSERT (hostname, agent_home, error_message, error_type, error_hash, occurrence_count)
            VALUES (s.hostname, s.agent_home, s.raw, s.et, s.fp, 1)
        """, (hostname, agent_home, raw, et, fp))
    conn.commit()
