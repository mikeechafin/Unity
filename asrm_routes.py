from flask import Blueprint, render_template, url_for, flash, request, current_app
from flask_login import login_required, current_user
import oracledb
from maa_libraries import get_db_pool_connection, release_db_connection, logger

# Version: 1.0.4
# Changelog:
# - 1.0.0: Initial version
# - 1.0.1: Fixed database pool access from current_app.DB_POOL to current_app.config['DB_POOL']
# - 1.0.2: Fixed SERIAL_NUMER to SERIAL_NUMBER, added try-except for render_template, enhanced logging, removed redundant whitespace
# - 1.0.3: Added missing 'import oracledb', converted asrm_data and assets_data to dictionaries, enhanced logging for data fetch
# - 1.0.4: Fixed query in asrm_index by using aa.SERIAL_NUMER instead of a.SERIAL_NUMBER

asrm_bp = Blueprint('asrm', __name__, template_folder='templates/asrm', static_folder='static/asrm')

@asrm_bp.route('/')
@login_required
def asrm_index():
    logger.info(f"Incoming request: method=GET, path=/asrm, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL")
        current_schema = cursor.fetchone()[0]
        logger.info(f"Current schema: {current_schema}")

        query = """
            SELECT a.HOSTNAME, a.MOS_BACKEND, a.ASR_USER, a.VERSION, a.REG_STATUS, a.STATUS,
                   COUNT(aa.SERIAL_NUMER) as ASSET_COUNT
            FROM MAAMD.ASRM a
            LEFT JOIN MAAMD.ASRM_ASSETS aa ON a.HOSTNAME = aa.ASRM_HOSTNAME
            GROUP BY a.HOSTNAME, a.MOS_BACKEND, a.ASR_USER, a.VERSION, a.REG_STATUS, a.STATUS
            ORDER BY a.HOSTNAME
        """
        cursor.execute(query)
        asrm_data_raw = cursor.fetchall()

        # Convert to list of dictionaries for easier template access
        asrm_data = [
            {
                'hostname': row[0],
                'mos_backend': row[1],
                'asr_user': row[2],
                'version': row[3],
                'reg_status': row[4],
                'status': row[5],
                'asset_count': row[6]
            }
            for row in asrm_data_raw
        ]

        logger.debug(f"Fetched {len(asrm_data)} ASR records: {asrm_data[:2]}")

        if not asrm_data:
            flash("No ASR data found in the database.", "info")
            logger.info("No data found in MAAMD.ASRM")

        try:
            return render_template(
                'asrm/index.html',
                asrm_data=asrm_data,
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
        except Exception as e:
            logger.error(f"Template rendering error in asrm_index: {str(e)}", exc_info=True)
            flash(f"Template rendering error: {str(e)}", "error")
            return render_template(
                'asrm/index.html',
                asrm_data=[],
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id,
                error_message="Failed to render ASRM data."
            )
    except oracledb.Error as e:
        logger.error(f"ASR index failed for user {current_user.id}: {e}")
        flash(f"Error retrieving ASR data from database: {e}", "error")
        return render_template(
            'asrm/index.html',
            asrm_data=[],
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id,
            error_message="Database error retrieving ASRM data."
        )
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])

@asrm_bp.route('/details/<hostname>')
@login_required
def asrm_details(hostname):
    logger.info(f"Incoming request: method=GET, path=/asrm/details/{hostname}, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        host_name_filter = request.args.get('host_name', '').strip()
        serial_number_filter = request.args.get('serial_number', '').strip()
        parent_serial_filter = request.args.get('parent_serial', '').strip()
        asr_filter = request.args.get('asr', '').strip()
        asr_status_filter = request.args.get('asr_status', '').strip()
        protocol_filter = request.args.get('protocol', '').strip()
        source_filter = request.args.get('source', '').strip()
        last_heartbeat_filter = request.args.get('last_heartbeat', '').strip()
        product_name_filter = request.args.get('product_name', '').strip()

        query = """
            SELECT HOST_NAME, SERIAL_NUMER, PARENT_SERIAL, ASR, ASR_STATUS, 
                   PROTOCOL, SOURCE, LAST_HEARTBEAT, PRODUCT_NAME
            FROM MAAMD.ASRM_ASSETS
            WHERE ASRM_HOSTNAME = :1
        """
        params = [hostname]

        conditions = []
        if host_name_filter:
            conditions.append("LOWER(HOST_NAME) LIKE LOWER(:2)")
            params.append(f"%{host_name_filter}%")
        if serial_number_filter:
            conditions.append("LOWER(SERIAL_NUMER) LIKE LOWER(:3)")
            params.append(f"%{serial_number_filter}%")
        if parent_serial_filter:
            conditions.append("LOWER(PARENT_SERIAL) LIKE LOWER(:4)")
            params.append(f"%{parent_serial_filter}%")
        if asr_filter:
            conditions.append("LOWER(ASR) LIKE LOWER(:5)")
            params.append(f"%{asr_filter}%")
        if asr_status_filter:
            conditions.append("LOWER(ASR_STATUS) LIKE LOWER(:6)")
            params.append(f"%{asr_status_filter}%")
        if protocol_filter:
            conditions.append("LOWER(PROTOCOL) LIKE LOWER(:7)")
            params.append(f"%{protocol_filter}%")
        if source_filter:
            conditions.append("LOWER(SOURCE) LIKE LOWER(:8)")
            params.append(f"%{source_filter}%")
        if last_heartbeat_filter:
            conditions.append("LOWER(LAST_HEARTBEAT) LIKE LOWER(:9)")
            params.append(f"%{last_heartbeat_filter}%")
        if product_name_filter:
            conditions.append("LOWER(PRODUCT_NAME) LIKE LOWER(:10)")
            params.append(f"%{product_name_filter}%")

        if conditions:
            query += " AND " + " AND ".join(conditions)

        query += " ORDER BY SERIAL_NUMER"

        cursor.execute(query, params)
        assets_data_raw = cursor.fetchall()

        # Convert to list of dictionaries for easier template access
        assets_data = [
            {
                'host_name': row[0],
                'serial_number': row[1],
                'parent_serial': row[2],
                'asr': row[3],
                'asr_status': row[4],
                'protocol': row[5],
                'source': row[6],
                'last_heartbeat': row[7],
                'product_name': row[8]
            }
            for row in assets_data_raw
        ]

        logger.debug(f"Fetched {len(assets_data)} assets for hostname {hostname}: {assets_data[:2]}")

        if not assets_data:
            flash(f"No asset data found for hostname {hostname}.", "info")
            logger.info(f"No assets found for ASRM hostname {hostname}")

        try:
            return render_template(
                'asrm/details.html',
                hostname=hostname,
                assets_data=assets_data,
                filters={
                    'host_name': host_name_filter,
                    'serial_number': serial_number_filter,
                    'parent_serial': parent_serial_filter,
                    'asr': asr_filter,
                    'asr_status': asr_status_filter,
                    'protocol': protocol_filter,
                    'source': source_filter,
                    'last_heartbeat': last_heartbeat_filter,
                    'product_name': product_name_filter
                },
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
        except Exception as e:
            logger.error(f"Template rendering error in asrm_details: {str(e)}", exc_info=True)
            flash(f"Template rendering error: {str(e)}", "error")
            return render_template(
                'asrm/details.html',
                hostname=hostname,
                assets_data=[],
                filters={
                    'host_name': '',
                    'serial_number': '',
                    'parent_serial': '',
                    'asr': '',
                    'asr_status': '',
                    'protocol': '',
                    'source': '',
                    'last_heartbeat': '',
                    'product_name': ''
                },
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id,
                error_message="Failed to render ASRM details."
            )
    except oracledb.Error as e:
        logger.error(f"ASR details failed for user {current_user.id}: {e}")
        flash(f"Error retrieving ASR assets data: {e}", "error")
        return render_template(
            'asrm/details.html',
            hostname=hostname,
            assets_data=[],
            filters={
                'host_name': '',
                'serial_number': '',
                'parent_serial': '',
                'asr': '',
                'asr_status': '',
                'protocol': '',
                'source': '',
                'last_heartbeat': '',
                'product_name': ''
            },
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id,
            error_message="Database error retrieving ASRM assets data."
        )
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
