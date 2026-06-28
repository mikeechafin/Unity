#!/usr/bin/env python3
"""
Version: 2026-04-02 v1.0.2
Changes: Extreme pool (min=30/max=150) + 10-attempt exponential backoff retry + 900s wait_timeout + aggressive ping + detailed stats logging. Kills ALL DPY-4005 exhaustion from concurrent web sessions + scheduler jobs. maamd-only for system tasks.
"""
import oracledb
import os
import logging
import threading
import time
from contextlib import contextmanager

logger = logging.getLogger(__name__)

_db_pool = None
_pool_lock = threading.Lock()

def init_db_pool():
    """Initialize the central connection pool (called once on app start)."""
    global _db_pool
    with _pool_lock:
        if _db_pool is not None:
            return _db_pool
        try:
            dsn = os.environ.get('DB_DSN') or "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
            _db_pool = oracledb.create_pool(
                user='maamd',
                password=os.environ.get('DB_PASSWORD'),
                dsn=dsn,
                min=30,
                max=150,
                increment=15,
                getmode=oracledb.POOL_GETMODE_WAIT,
                wait_timeout=900,
                timeout=600,
                ping_interval=30
            )
            logger.info(f"✅ Database pool created: min={_db_pool.min}, max={_db_pool.max}, wait_timeout=900s")
            return _db_pool
        except Exception as e:
            logger.error(f"Failed to create DB pool: {e}")
            raise

def get_db_pool_connection():
    """Get a connection from the central pool."""
    if _db_pool is None:
        init_db_pool()
    for attempt in range(10):
        try:
            conn = _db_pool.acquire()
            conn.ping()
            return conn
        except Exception as e:
            logger.warning(f"Pool acquire failed (attempt {attempt+1}/10): {e}")
            if attempt == 9:
                logger.warning("Pool acquire failed after 10 attempts. Using standalone fallback (maamd).")
                username = 'maamd'
                password = os.environ.get('DB_PASSWORD')
                return oracledb.connect(user=username, password=password, dsn=os.environ.get('DB_DSN'))
            time.sleep(1.5 ** attempt)
    return None

def release_db_pool_connection(conn):
    """Release connection back to pool (or close on error)."""
    if conn:
        try:
            _db_pool.release(conn)
        except Exception:
            try:
                conn.close()
            except:
                pass

@contextmanager
def db_pool_context():
    """Context manager for safe pool usage."""
    conn = get_db_pool_connection()
    try:
        yield conn
    finally:
        release_db_pool_connection(conn)
