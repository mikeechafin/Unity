#!/usr/bin/env python3
import sys
import os
import logging
from datetime import datetime, timedelta
import oracledb
import smtplib
from email.mime.text import MIMEText
from maa_libraries import get_db_connection  # From maa_libraries.py
import socket
from io import StringIO
import subprocess
import time

# Configure logging (aligned with maa_unified_app.py)
log_directory = '/home/maatest/mchafin/MAA_APPS_NEW/output'
log_file = f'{log_directory}/email_agent_status.log'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Set up file handler for logging
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s,%(msecs)03d %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Create logger and add file handler
logger = logging.getLogger('MAA_Unified')
logger.setLevel(logging.DEBUG)
logger.handlers = [file_handler]  # Remove default console handler

# SMTP configuration
SMTP_SERVER = 'internal-mail-router.oracle.com'
SMTP_PORT = 25
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SENDER = 'MAA Unified App <maa_reports@oracle.com>'
SMTP_TIMEOUT = 30
SMTP_RETRIES = 3
SMTP_RETRY_DELAY = 5  # seconds

# External Oracle logo URL (fallback if base64 fails)
# Replace with your internal Oracle logo URL if available
ORACLE_LOGO_URL = 'https://www.oracle.com/a/ocom/img/oracle-logo-red.png'

# Default Oracle logo base64 (commented out, ~78px height)
# Use if email client supports base64 and URL fails:
# ORACLE_LOGO_BASE64 = (
#     'iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAYAAAD0eNT6AAAACXBIWXMAAAsTAAALEwEAmpwYAAAB'
#     'e0lEQVR4nO3bPUoDQRSG4Z4yJYhVgoW9S9jY2dk7uAuWVoJ1K4hVghZSWNi7S1hoY2NjYWFhYWFh'
#     '4S4M+wBOcv6cnOQkJznJmc1mM5vN7HY7+30/nU4nk0m/35/NZjKZTGaTyWRgMpkM9Pt9NpvJZDKZ'
#     'zGYymUwGBoPBx3EcjuM0Go1Go9FoNBrNZnMcx2k4jkaj0Wg0Go1mM5vNZrPZbDYajUaj0Wj2+/1+'
#     'v99oNBrNZnMcx2k0Go1Goxn+/3Q6nU6n0+n3+0aj0Wj2+/1+v99oNBqNRrPZbDabzWaz2Ww2m81m'
#     's9lsNpvNZrPZbDYajUaj2Ww2m81ms9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRrPZbDabzWaz'
#     '2Ww2m81ms9lsNpvNZrPZbDYajUaj2Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0m81ms9lsNpvNZrPZ'
#     'bDYajUaj0Wg0Go1Goxn+/3Q6nU6n0+n3+0aj0Wg0m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9Fo'
#     'NpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0'
#     'Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYa'
#     'jUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvN'
#     'ZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81m'
#     's9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj'
#     '0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPR'
#     'aDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99o'
#     'NBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2'
#     '+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYa'
#     'jUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvN'
#     'ZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj0Wg0Go1G'
#     'o9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZbDYajUaj'
#     '0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9lsNpvNZrPZ'
#     'bDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2m81ms9ls'
#     'NpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQajUaj0Ww2'
#     'm81ms9lsNpvNZrPZbDYajUaj0Wg0Go1Go9lsNpvNZrPZbDYajUaj0Wj2+/1+v99oNBqNRqPRaDQA'
#     'AA=='
# )

# Main app URL
MAIN_APP_URL = 'http://scaqaa04celadm12.us.oracle.com:6003/agent/report'

def execute_query(conn, query, params=None):
    """Execute a database query and return results as a list of dicts."""
    cursor = conn.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        columns = [col[0] for col in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results
    except oracledb.Error as e:
        logger.error(f"Query execution failed: {str(e)}")
        raise
    finally:
        cursor.close()

def get_recipients():
    """Fetch email recipients from maamd.report_recipients."""
    try:
        dsn = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
        password = os.environ.get('DB_PASSWORD')
        if not password:
            raise ValueError("DB_PASSWORD environment variable not set")
        
        conn = get_db_connection('maamd', password, dsn, timeout=30)
        query = """
        SELECT email
        FROM maamd.report_recipients
        WHERE report_name = 'agent_status'
        """
        results = execute_query(conn, query)
        conn.close()
        recipients = [row['EMAIL'] for row in results]
        logger.info("Fetched %d recipients: %s", len(recipients), recipients)
        return recipients
    except oracledb.Error as e:
        logger.error("Database error fetching recipients: %s", str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error fetching recipients: %s", str(e))
        raise

def send_email(sender, recipients, subject, body):
    """Send an email using SMTP with retries, fallback to sendmail."""
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    
    # Capture SMTP debug output to logger
    debug_output = StringIO()
    debug_handler = logging.StreamHandler(debug_output)
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(debug_handler)
    
    # Try SMTP with retries
    for attempt in range(1, SMTP_RETRIES + 1):
        try:
            logger.debug(f"Attempting SMTP connection to {SMTP_SERVER}:{SMTP_PORT} (attempt {attempt}/{SMTP_RETRIES}) with timeout {SMTP_TIMEOUT}s")
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT)
            try:
                if SMTP_USER and SMTP_PASSWORD:
                    logger.debug("Initiating STARTTLS and authentication")
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASSWORD)
                else:
                    logger.debug("No authentication configured")
                logger.debug(f"Sending email to {recipients}")
                server.sendmail(sender, recipients, msg.as_string())
                logger.info("Email sent to %s via SMTP", recipients)
                return
            finally:
                server.quit()
                debug_content = debug_output.getvalue()
                if debug_content:
                    logger.debug("SMTP debug output:\n%s", debug_content)
        except (smtplib.SMTPException, socket.timeout, socket.error) as e:
            logger.error("SMTP attempt %d failed: %s", attempt, str(e))
            if attempt < SMTP_RETRIES:
                logger.info("Retrying in %d seconds...", SMTP_RETRY_DELAY)
                time.sleep(SMTP_RETRY_DELAY)
            else:
                logger.error("All SMTP retries failed")
    
    logger.removeHandler(debug_handler)
    debug_output.close()
    
    # Fallback to sendmail
    logger.info("Falling back to sendmail")
    try:
        process = subprocess.Popen(['sendmail', '-t'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=msg.as_string(), timeout=30)
        if process.returncode == 0:
            logger.info("Email sent to %s via sendmail", recipients)
        else:
            logger.error("Sendmail failed with exit code %d", process.returncode)
            raise RuntimeError("Sendmail failed")
    except Exception as e:
        logger.error("Sendmail error: %s", str(e))
        raise

def fetch_agent_summary():
    """Fetch agent summary data with orphaned agents count."""
    try:
        dsn = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
        password = os.environ.get('DB_PASSWORD')
        if not password:
            raise ValueError("DB_PASSWORD environment variable not set")
        
        conn = get_db_connection('maamd', password, dsn, timeout=30)
        query = """
        WITH agent_counts AS (
            SELECT /*+ MATERIALIZE */
                ahi.hostname,
                SUM(CASE WHEN EXISTS (
                    SELECT 1
                    FROM maamd.ignore_strings_table ist
                    WHERE (ist.hostname = ahi.hostname OR ist.hostname = 'default')
                    AND UPPER(TRIM(ahi.agent_home)) LIKE '%' || UPPER(TRIM(ist.exclude_string)) || '%'
                ) THEN 1 ELSE 0 END) AS known_count,
                SUM(CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM maamd.ignore_strings_table ist
                    WHERE (ist.hostname = ahi.hostname OR ist.hostname = 'default')
                    AND UPPER(TRIM(ahi.agent_home)) LIKE '%' || UPPER(TRIM(ist.exclude_string)) || '%'
                ) THEN 1 ELSE 0 END) AS unregistered_count,
                COUNT(*) AS total_count,
                SUM(CASE 
                    WHEN ahi.last_successful_upload IS NULL 
                    OR ahi.last_successful_upload < SYSDATE - 2
                    THEN 1 
                    ELSE 0 
                    END) AS orphaned_agents
            FROM maamd.agent_home_info ahi
            GROUP BY ahi.hostname
        )
        SELECT
            ac.hostname,
            ac.unregistered_count,
            ac.known_count,
            ac.total_count,
            ac.orphaned_agents
        FROM agent_counts ac
        WHERE ac.hostname NOT LIKE '%celadm%'
        ORDER BY ac.hostname
        """
        results = execute_query(conn, query)
        conn.close()
        logger.info("Fetched %d records", len(results))
        return results
    except oracledb.Error as e:
        logger.error("Database error fetching agent summary: %s", str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error fetching agent summary: %s", str(e))
        raise

def generate_html_table(data, total_unregistered, total_known, total_detected, total_orphaned):
    """Generate HTML table mimicking Agent Summary from report.html."""
    try:
        # Log Oracle logo URL usage
        logger.debug("Using Oracle logo URL: %s", ORACLE_LOGO_URL)

        # Validate input data
        for idx, row in enumerate(data):
            for key in ['HOSTNAME', 'UNREGISTERED_COUNT', 'KNOWN_COUNT', 'TOTAL_COUNT', 'ORPHANED_AGENTS']:
                if key not in row:
                    logger.error("Missing key %s in row %d: %s", key, idx, row)
                    raise ValueError(f"Missing key {key} in row {idx}")
                if key == 'HOSTNAME' and not isinstance(row[key], str):
                    logger.warning("Invalid HOSTNAME type in row %d: %s", idx, row)
                    row[key] = str(row[key]) if row[key] is not None else 'N/A'
                elif key != 'HOSTNAME' and not isinstance(row[key], (int, float)):
                    logger.warning("Invalid numeric type for %s in row %d: %s", key, idx, row)
                    row[key] = int(row[key]) if row[key] is not None else 0
            logger.debug("Validated row %d: %s", idx, row)

        # Generate HTML
        html = f"""
        <html>
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
            <style>
                .header-banner {{
                    background-color: #FF0000;
                    padding: 5px;
                    text-align: center;
                    width: 100%;
                    height: 80px;
                    box-sizing: border-box;
                    margin: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }}
                .page-title {{
                    font-size: 24px;
                    color: #FFFFFF;
                    font-family: Arial, sans-serif;
                    margin: 0;
                    text-align: center;
                }}
                .action-button {{
                    background-color: #CCCCCC;
                    color: #000000;
                    padding: 8px 16px;
                    text-decoration: none;
                    border-radius: 4px;
                    font-family: Arial, sans-serif;
                    font-size: 14px;
                    font-weight: bold;
                    display: inline-block;
                    margin-bottom: 10px;
                    border: 1px solid #999999;
                }}
                .action-button:hover {{
                    background-color: #B3B3B3;
                }}
                table.data-table {{
                    width: 100%;
                    border-collapse: collapse;
                    background-color: #D3D3D3;
                    font-family: Arial, sans-serif;
                    margin-bottom: 20px;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                    border: 1px solid #666666;
                    color: #000000;
                }}
                th {{
                    background-color: #C0C0C0;
                    font-weight: bold;
                }}
                .row-even {{
                    background-color: #E6E6E6;
                }}
                .row-odd {{
                    background-color: #F5F5F5;
                }}
                tr.total-row {{
                    background-color: #C0C0C0;
                }}
                .highlight-red {{
                    color: red;
                }}
            </style>
        </head>
        <body>
            <div class="header-banner">
                <h1 class="page-title">Agent Management Report</h1>
            </div>
            <a href="{MAIN_APP_URL}" class="action-button">Access MAA Unified</a>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>Unregistered Agents</th>
                        <th>Known MAA Agents</th>
                        <th>Total Detected Agents</th>
                        <th>Orphaned Agents</th>
                    </tr>
                </thead>
                <tbody>
        """

        # Add table rows with explicit row classes
        for idx, row in enumerate(data):
            try:
                row_class = 'row-even' if idx % 2 == 0 else 'row-odd'
                html += (
                    f"""
                    <tr class="{row_class}">
                        <td>{row['HOSTNAME']}</td>
                        <td class="{'highlight-red' if row['UNREGISTERED_COUNT'] >= 15 else ''}">{row['UNREGISTERED_COUNT']}</td>
                        <td class="{'highlight-red' if row['KNOWN_COUNT'] >= 15 else ''}">{row['KNOWN_COUNT']}</td>
                        <td class="{'highlight-red' if row['TOTAL_COUNT'] >= 15 else ''}">{row['TOTAL_COUNT']}</td>
                        <td class="{'highlight-red' if row['ORPHANED_AGENTS'] >= 15 else ''}">{row['ORPHANED_AGENTS']}</td>
                    </tr>
                    """
                )
            except Exception as e:
                logger.error("Error generating HTML for row %d: %s", idx, str(e))
                raise

        # Finalize HTML
        html += (
            f"""
                <tr class="total-row">
                    <td><strong>Total</strong></td>
                    <td class="{'highlight-red' if total_unregistered >= 15 else ''}"><strong>{total_unregistered}</strong></td>
                    <td class="{'highlight-red' if total_known >= 15 else ''}"><strong>{total_known}</strong></td>
                    <td class="{'highlight-red' if total_detected >= 15 else ''}"><strong>{total_detected}</strong></td>
                    <td class="{'highlight-red' if total_orphaned >= 15 else ''}"><strong>{total_orphaned}</strong></td>
                </tr>
            </tbody>
        </table>
    </body>
</html>
"""
        )

        return html
    except Exception as e:
        logger.error("Failed to generate HTML table: %s", str(e))
        raise

def main():
    """Main function to generate and send the email."""
    try:
        # Fetch data
        logger.info("Fetching agent summary data...")
        data = fetch_agent_summary()
        
        # Calculate totals
        total_unregistered = sum(row['UNREGISTERED_COUNT'] for row in data)
        total_known = sum(row['KNOWN_COUNT'] for row in data)
        total_detected = sum(row['TOTAL_COUNT'] for row in data)
        total_orphaned = sum(row['ORPHANED_AGENTS'] for row in data)
        
        # Generate HTML
        logger.info("Generating HTML table...")
        html_content = generate_html_table(data, total_unregistered, total_known, total_detected, total_orphaned)
        
        # Fetch recipients
        logger.info("Fetching email recipients...")
        recipients = get_recipients()
        if not recipients:
            logger.warning("No recipients found; defaulting to placeholder")
            recipients = ['mike.chafin@oracle.com']
        
        # Send email
        subject = "Enterprise Manager Agent Status Report"
        logger.info("Sending email to %s...", recipients)
        send_email(SENDER, recipients, subject, html_content)
        logger.info("Email sent successfully.")
        
        # Log job history
        dsn = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
        password = os.environ.get('DB_PASSWORD')
        conn = get_db_connection('maamd', password, dsn)
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO maamd.job_history (job_id, run_time, status, triggered_by)
                SELECT job_id, SYSTIMESTAMP, 'Completed', 'Scheduler'
                FROM maamd.scheduled_jobs WHERE script_name = :1
                """,
                ('email_agent_status.py',)
            )
            conn.commit()
        except oracledb.Error as e:
            logger.error("Failed to log job history: %s", str(e))
            conn.rollback()
        finally:
            cursor.close()
            conn.close()
    
    except Exception as e:
        logger.error("Script failed: %s", str(e))
        # Log failure in job history
        try:
            dsn = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))"
            password = os.environ.get('DB_PASSWORD')
            conn = get_db_connection('maamd', password, dsn)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    INSERT INTO maamd.job_history (job_id, run_time, status, error_message, triggered_by)
                    SELECT job_id, SYSTIMESTAMP, 'Failed', :1, 'Scheduler'
                    FROM maamd.scheduled_jobs WHERE script_name = :2
                    """,
                    (str(e), 'email_agent_status.py')
                )
                conn.commit()
            except oracledb.Error as db_e:
                logger.error("Failed to log job history: %s", str(db_e))
            finally:
                cursor.close()
                conn.close()
        except Exception as log_e:
            logger.error("Failed to log failure: %s", str(log_e))
        sys.exit(1)

if __name__ == "__main__":
    main()
