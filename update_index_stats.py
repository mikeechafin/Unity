#!/usr/bin/env python3
import os
import sys
import logging
from datetime import datetime, timezone
import pytz
import oracledb
import config

# Version: 1.0.2
# Changelog:
# - 1.0.0: Initial version for updating index statistics for a single table (2025-05-30)
# - 1.0.1: Modified to update index statistics for all tables in a schema (2025-05-30)

# Constants from collect_agent_data.py
DB_USER = config.DB_USER
DB_DSN = config.DB_DSN
DB_PASSWORD = config.DB_PASSWORD
LOG_FILE = config.INDEX_STATS_LOG

# Validate environment variable
if not DB_PASSWORD:
    logging.critical("Environment variable DB_PASSWORD is not set")
    sys.exit(1)

# Logging setup similar to collect_agent_data.py
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE)
        ]
    )
    logger = logging.getLogger(__name__)
    return logger

logger = setup_logging()

def get_db_connection():
    """Establish a database connection using maamd user and DB_PASSWORD env variable."""
    try:
        conn = oracledb.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            dsn=DB_DSN
        )
        logger.info("Database connection established for user %s", DB_USER)
        return conn
    except oracledb.Error as e:
        logger.error("Failed to connect to database: %s", str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error in get_db_connection: %s", str(e))
        raise

def get_tables_in_schema(schema_name):
    """Retrieve all tables in the specified schema."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT TABLE_NAME
            FROM DBA_TABLES
            WHERE OWNER = :1
        """, [schema_name])
        tables = [row[0] for row in cursor.fetchall()]
        logger.info("Found %d tables in schema %s", len(tables), schema_name)
        return tables
    except oracledb.Error as e:
        logger.error("Error retrieving tables for schema %s: %s", schema_name, str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error retrieving tables for schema %s: %s", schema_name, str(e))
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            logger.debug("Database connection closed for table retrieval")

def get_indexes_for_table(schema_name, table_name):
    """Retrieve all indexes for a specific table in the schema."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT INDEX_NAME
            FROM DBA_INDEXES
            WHERE OWNER = :1 AND TABLE_NAME = :2
        """, [schema_name, table_name])
        indexes = [row[0] for row in cursor.fetchall()]
        logger.debug("Found %d indexes for table %s.%s", len(indexes), schema_name, table_name)
        return indexes
    except oracledb.Error as e:
        logger.error("Error retrieving indexes for table %s.%s: %s", schema_name, table_name, str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error retrieving indexes for table %s.%s: %s", schema_name, table_name, str(e))
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            logger.debug("Database connection closed for index retrieval")

def update_index_stats(schema_name):
    """Gather index statistics for all tables in the specified schema."""
    try:
        tables = get_tables_in_schema(schema_name)
        if not tables:
            logger.warning("No tables found in schema %s", schema_name)
            return

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            for table_name in tables:
                indexes = get_indexes_for_table(schema_name, table_name)
                if not indexes:
                    logger.info("No indexes found for table %s.%s, skipping", schema_name, table_name)
                    continue
                for index_name in indexes:
                    try:
                        logger.debug("Gathering stats for index %s.%s.%s", schema_name, table_name, index_name)
                        cursor.callproc("DBMS_STATS.GATHER_INDEX_STATS", [schema_name, index_name])
                        conn.commit()
                        logger.info("Updated index statistics for %s.%s.%s", schema_name, table_name, index_name)
                    except oracledb.Error as e:
                        logger.error("Error updating index stats for %s.%s.%s: %s", schema_name, table_name, index_name, str(e))
                        continue  # Continue with next index
            logger.info("Completed index statistics update for schema %s", schema_name)
        finally:
            cursor.close()
            conn.close()
            logger.debug("Database connection closed for stats update")
    except oracledb.Error as e:
        logger.error("Error processing schema %s: %s", schema_name, str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error processing schema %s: %s", schema_name, str(e))
        raise

def main():
    """Main function to process schema argument."""
    if len(sys.argv) != 2:
        logger.error("Usage: %s <schema_name>", sys.argv[0])
        sys.exit(1)

    schema_name = sys.argv[1].upper()

    try:
        update_index_stats(schema_name)
    except Exception as e:
        logger.error("Job failed: %s", str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
