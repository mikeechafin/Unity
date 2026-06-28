#!/usr/bin/env python3
import oracledb
import re
import logging
import sys
import os
import time
import signal
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Set, List, Tuple
import spacy
from spacy.matcher import PhraseMatcher
import psutil
from maa_libraries import get_db_connection

# Configure logging with detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [PID:%(process)d] [Thread:%(threadName)s]: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/home/maatest/mchafin/MAA_APPS_NEW/output/populate_agent_error_global.log')
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DB_CONFIG = {
    'user': os.environ.get('DB_USER', 'maamd'),
    'password': os.environ.get('DB_PASS', 'welcome2'),
    'dsn': '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))'
}
BATCH_SIZE = 10000
MAX_CLOB_SIZE = 4000
SPACY_TIMEOUT = 30  # seconds

# Global variables
process = psutil.Process()
error_type_cache: Dict[str, str] = {}  # Cache for classify_unmatched_error results
running = True  # Flag for graceful shutdown

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    global running
    logger.info("Received interrupt signal, shutting down gracefully...")
    running = False
    raise KeyboardInterrupt("Graceful shutdown initiated")

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Load spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
    logger.info("Loaded spaCy model: en_core_web_sm")
except Exception as e:
    logger.error(f"Failed to load spaCy model: {e}", exc_info=True)
    raise

# Normalization patterns from parse_agent_logs.py
NORMALIZATION_PATTERNS = [
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE), "[IP]"),
    (re.compile(r"\b\d{4,5}\b", re.IGNORECASE), "[PORT]"),
    (re.compile(r"/[\w/]+/agent_inst\b", re.IGNORECASE), "[AGENT_PATH]"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b", re.IGNORECASE), "[TIMESTAMP]"),
    (re.compile(r"https?://[^\s]+/empbs/upload", re.IGNORECASE), "[URL]/empbs/upload"),
    (re.compile(r"(?i)((?:java\.\w+\.\w+Exception|oracle\.sysman\.\w+\.\w+Exception|org\.eclipse\.jetty\.\w+\.\w+Exception|at\s+oracle\.sysman\.(?:emxa\.fetchlets\.exarest\.ExaRESTFetchlet|gcagent\.addon\.fetchlet\.muws\.core\.MUWSFetchlet)\.\w+$$ .+? $$).*?)(?:\n\s*at\s+.*){5,}", re.IGNORECASE), r"\1\n[TRUNCATED]"),
    (re.compile(r"\b(?!OMS|TNS|ERROR|SEVERE|CRITICAL|WARNING|Ping|Upload|Manager|ConnectException|VirtualServer|DiskActivity|Load|memoryDetails|CellSrv|Status|Metric|oracle_database|rac_database|oracle_si_virtual_server|oracle_si_host_remote_ssh|oracle_si_server_os|oracle_listener|Response|quota|SNMPTrap|CDB\d+|PDB\d+|AutoSyncDirect|VCPUDetailsDirect|NetworkDirect|Infiniband_HCA_Performance|dataguard_11gR2|activity_pending|oracle_emd|oracle_exadata|TaskTimeoutException|MetadataExecutionException|SvrGenAlrt|SqlConnectionCache|communication|failed|fetchlet|empbs|upload|Connection|UploadConnection|emSDK|gcagent|UnknownHostException|SocketTimeoutException|ExaRESTFetchlet|MUWSFetchlet|TLS_|AES_|SHA|RSA|DHE|ECDHE|GCM|CBC|DbHome|oracle_home_config|jetty|CollectionItem|streams_statistics|MAX_INTERVAL|MINEXTENTS)[A-Z0-9_]{3,}\b(?!\.(?:oracle\.com|us\.oracle\.com|oraclevcn\.com))", re.IGNORECASE), "[TARGET]"),
    (re.compile(r"\b\d+%\b", re.IGNORECASE), "[PERCENT]"),
    (re.compile(r"(?i)\b(at|in)\s+[\w\.\$]+\s*\([^()]*\)", re.IGNORECASE), ""),
    (re.compile(r"\[\d+\]", re.IGNORECASE), "[N]"),
    (re.compile(r"\d+", re.IGNORECASE), "N"),
]

def normalize_error_message(error_message: str) -> str:
    """Normalize error messages (from parse_agent_logs.py)."""
    start_time = time.time()
    if not error_message:
        logger.debug("Empty error message, returning empty string")
        return ""
    normalized = error_message
    for pattern, replacement in NORMALIZATION_PATTERNS:
        try:
            normalized = pattern.sub(replacement, normalized)
        except re.error as e:
            logger.error(f"Normalization pattern error: {pattern} - {e}")
            continue
    normalized = normalized.strip()[:MAX_CLOB_SIZE]
    logger.debug(f"Normalized error message (len={len(error_message)}->len={len(normalized)}, time={time.time()-start_time:.2f}s): {normalized[:100]}...")
    return normalized

def classify_unmatched_error(message: str) -> str:
    """Classify unmatched errors using spaCy (from parse_agent_logs.py)."""
    start_time = time.time()
    message_hash = hash(message.lower())
    
    # Check cache
    if message_hash in error_type_cache:
        logger.debug(f"Cache hit for error message hash {message_hash}, returning: {error_type_cache[message_hash]}")
        return error_type_cache[message_hash]

    logger.debug(f"Classifying error message (len={len(message)}): {message[:100]}...")
    try:
        # Apply timeout to spaCy processing
        doc = nlp(message.lower(), timeout=SPACY_TIMEOUT)
        matcher = PhraseMatcher(nlp.vocab)
        patterns = {
            'connectivity': [nlp("timeout"), nlp("connection refused"), nlp("network error"), nlp("oms unreachable"), nlp("socket error"), nlp("ping protocol error")],
            'auth': [nlp("authentication failed"), nlp("invalid credentials"), nlp("permission denied"), nlp("login failed")],
            'resource': [nlp("out of memory"), nlp("disk full"), nlp("insufficient resources"), nlp("cpu limit"), nlp("disk space error"), nlp("cpu utilization"), nlp("memory utilization"), nlp("ssh sessions"), nlp("used space"), nlp("free memory")],
            'plugin': [nlp("plugin execution failed"), nlp("metric collection failed")]
        }
        for error_type, phrases in patterns.items():
            matcher.add(error_type, phrases)
        matches = matcher(doc)
        error_types = [nlp.vocab.strings[match_id] for match_id, start, end in matches]
        result = error_types[0] if error_types else 'unknown'
        error_type_cache[message_hash] = result
        logger.debug(f"Classified error message as '{result}' (time={time.time()-start_time:.2f}s, cache_size={len(error_type_cache)})")
        return result
    except TimeoutError:
        logger.warning(f"spaCy processing timed out after {SPACY_TIMEOUT}s for message: {message[:100]}...")
        return 'unknown'
    except Exception as e:
        logger.error(f"Error in spaCy classification: {e}", exc_info=True)
        return 'unknown'

def log_memory_usage():
    """Log current memory usage."""
    mem = process.memory_info()
    logger.debug(f"Memory usage: RSS={mem.rss / 1024**2:.2f} MB, VMS={mem.vms / 1024**2:.2f} MB")

def populate_agent_error_global():
    """Populate MAAMD.AGENT_ERROR_GLOBAL from MAAMD.AGENT_ERRORS."""
    global running
    logger.info("Starting population of MAAMD.AGENT_ERROR_GLOBAL")
    start_time = time.time()
    conn = None
    cursor = None

    try:
        # Connect to database
        logger.debug(f"Connecting to database with user={DB_CONFIG['user']}, dsn={DB_CONFIG['dsn']}")
        conn = get_db_connection(DB_CONFIG['user'], DB_CONFIG['password'], DB_CONFIG['dsn'])
        cursor = conn.cursor()
        logger.info("Database connection established")
        log_memory_usage()

        # Estimate total rows
        cursor.execute("SELECT COUNT(*) FROM MAAMD.AGENT_ERRORS")
        total_rows = cursor.fetchone()[0]
        logger.info(f"Total rows to process in MAAMD.AGENT_ERRORS: {total_rows}")

        # Clear existing data
        logger.debug("Truncating MAAMD.AGENT_ERROR_GLOBAL")
        start_truncate = time.time()
        cursor.execute("TRUNCATE TABLE MAAMD.AGENT_ERROR_GLOBAL")
        conn.commit()
        logger.info(f"Cleared MAAMD.AGENT_ERROR_GLOBAL (time={time.time()-start_truncate:.2f}s)")

        # Fetch errors with agent homes
        query = """
            SELECT ae.HOSTNAME, ae.ERROR_MESSAGE, ae.ERROR_TYPE, COUNT(*) as OCCURRENCES, ahi.AGENT_HOME
            FROM MAAMD.AGENT_ERRORS ae
            JOIN MAAMD.AGENT_HOME_INFO ahi ON ae.HOSTNAME = ahi.HOSTNAME
            GROUP BY ae.HOSTNAME, ae.ERROR_MESSAGE, ae.ERROR_TYPE, ahi.AGENT_HOME
        """
        logger.debug(f"Executing query: {query[:200]}...")
        start_query = time.time()
        cursor.execute(query)
        logger.info(f"Query executed (time={time.time()-start_query:.2f}s)")

        aggregated_data: Dict[Tuple[str, str], Dict[str, any]] = defaultdict(
            lambda: {'total_occurrences': 0, 'agent_homes': set(), 'error_type': None}
        )
        row_count = 0
        batch_start_time = time.time()

        for row in cursor:
            if not running:
                logger.info("Stopping row processing due to interrupt")
                break

            hostname, error_message, error_type, occurrences, agent_home = row
            row_count += 1

            # Log row details
            logger.debug(f"Processing row {row_count}/{total_rows}: hostname={hostname}, error_message={error_message[:100]}..., occurrences={occurrences}, agent_home={agent_home[:100]}...")

            # Normalize and classify
            start_row = time.time()
            normalized_msg = normalize_error_message(error_message)
            if not error_type or error_type == 'unknown':
                error_type = classify_unmatched_error(error_message)
            key = (normalized_msg, error_type)
            aggregated_data[key]['total_occurrences'] += occurrences
            aggregated_data[key]['agent_homes'].add(agent_home)
            aggregated_data[key]['error_type'] = error_type
            logger.debug(f"Row processed: normalized_msg={normalized_msg[:100]}..., error_type={error_type}, time={time.time()-start_row:.2f}s")

            # Batch logging and progress
            if row_count % BATCH_SIZE == 0:
                elapsed = time.time() - start_time
                batch_elapsed = time.time() - batch_start_time
                progress = (row_count / total_rows) * 100
                rows_per_sec = BATCH_SIZE / batch_elapsed if batch_elapsed > 0 else 0
                eta = (total_rows - row_count) / rows_per_sec if rows_per_sec > 0 else float('inf')
                logger.info(
                    f"Batch processed: {row_count}/{total_rows} rows ({progress:.2f}%), "
                    f"batch_time={batch_elapsed:.2f}s, rate={rows_per_sec:.2f} rows/s, "
                    f"ETA={timedelta(seconds=int(eta))}, total_time={elapsed:.2f}s"
                )
                log_memory_usage()
                batch_start_time = time.time()

        logger.info(f"Processed {row_count}/{total_rows} rows from MAAMD.AGENT_ERRORS (time={time.time()-start_time:.2f}s)")

        if not running:
            logger.info("Skipping insert due to interrupt")
            return

        # Insert aggregated data
        logger.debug("Preparing to insert aggregated data")
        batch_data = [
            (
                key[0],  # normalized_error_message
                data['error_type'],
                data['total_occurrences'],
                len(data['agent_homes']),
                ','.join(sorted(data['agent_homes']))
            )
            for key, data in aggregated_data.items()
        ]
        logger.info(f"Inserting {len(batch_data)} aggregated errors into MAAMD.AGENT_ERROR_GLOBAL")

        start_insert = time.time()
        cursor.executemany("""
            INSERT INTO MAAMD.AGENT_ERROR_GLOBAL (
                NORMALIZED_ERROR_MESSAGE, ERROR_TYPE, TOTAL_OCCURRENCES,
                AGENT_HOME_COUNT, AGENT_HOMES, LAST_UPDATED
            )
            VALUES (:1, :2, :3, :4, :5, SYSTIMESTAMP)
        """, batch_data)
        conn.commit()
        logger.info(f"Inserted {len(batch_data)} rows (time={time.time()-start_insert:.2f}s)")

        total_time = time.time() - start_time
        logger.info(f"Population completed in {total_time:.2f} seconds")
        log_memory_usage()

    except KeyboardInterrupt:
        logger.info("Caught KeyboardInterrupt, cleaning up...")
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            logger.info("Database connection closed")
        logger.info(f"Processed {row_count}/{total_rows} rows before interruption")
        sys.exit(1)
    except oracledb.Error as e:
        logger.error(f"Database error: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            logger.info("Database connection closed")

def main():
    try:
        logger.info("Script started")
        log_memory_usage()
        populate_agent_error_global()
        logger.info("Script completed successfully")
    except Exception as e:
        logger.error(f"Script failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
