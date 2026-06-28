from flask import Blueprint, redirect, render_template, url_for, flash, request, session, current_app
from flask_login import login_required, current_user
import paramiko
import time
import os
import oracledb
from maa_libraries import get_db_pool_connection, release_db_connection, execute_ssh_command, reset_switch_alert_to_default, set_switch_alert_v2c, set_switch_alert_v3, logger, get_credential

# Version: 1.0.4
# Changelog:
# - 1.0.0: Initial version with switch management routes
# - 1.0.1: Fixed current_app.DB_POOL to current_app.config['DB_POOL'], added logging for blank page debugging, enhanced error handling
# - 1.0.2: Added try-except for render_template to prevent blank pages
# - 1.0.3: Added superuser error handling, debug logging for data counts, fallback messages for empty data, and enhanced SSH error handling
# - 1.0.4: Added get_credential import to fix NameError, enhanced debug logging in edit_alert route to diagnose Not Found error

switches_bp = Blueprint('switches', __name__, template_folder='templates/switches', static_folder='static/switches')

@switches_bp.route('/')
@login_required
def switch_index():
    logger.info(f"Incoming request: method=GET, path=/switches, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL")
        current_schema = cursor.fetchone()[0]
        logger.debug(f"Current schema: {current_schema}")

        hostname_filter = request.args.get('hostname', '').strip()
        switch_type_filter = request.args.get('switch_type', '').strip()

        query = """
            SELECT s.HOSTNAME, s.MAKE, s.IP_ADDRESS, COALESCE(s.MODEL, 'Unknown') AS MODEL,
                   COALESCE(s.VERSION, 'Unknown') AS VERSION, COALESCE(s.FW_VERSION, 'None') AS FW_VERSION,
                   COALESCE(s.SERIAL_NUMBER, 'Unknown') AS SERIAL_NUMBER,
                   (SELECT COUNT(*) FROM MAAMD.SWITCH_SNMP_SUBSCRIPTIONS sub 
                    WHERE LOWER(sub.SWITCH_HOSTNAME) = LOWER(s.HOSTNAME) AND sub.STATUS != 'disable') AS active_subs,
                   (SELECT COUNT(*) FROM MAAMD.SWITCH_SNMP_USERS u 
                    WHERE LOWER(u.SWITCH_HOSTNAME) = LOWER(s.HOSTNAME)) AS user_count
            FROM MAAMD.SWITCH_INFO s
            WHERE 1=1
        """
        params = {}
        if hostname_filter:
            query += " AND LOWER(s.HOSTNAME) LIKE LOWER(:hostname)"
            params['hostname'] = f"%{hostname_filter}%"
        if switch_type_filter:
            query += " AND LOWER(s.MAKE) LIKE LOWER(:switch_type)"
            params['switch_type'] = f"%{switch_type_filter}%"
        query += " ORDER BY s.HOSTNAME"

        cursor.execute(query, params)
        switches_data = cursor.fetchall()

        switches = []
        summary = {'total_switches': 0, 'production_asr_yes': 0, 'ipv4_asr_yes': 0, 'ipv6_asr_yes': 0}
        if switches_data:
            total_switches = len(switches_data)
            production_asr_yes = 0
            ipv4_asr_yes = 0
            ipv6_asr_yes = 0

            for switch in switches_data:
                hostname = switch[0].lower()
                switch_type = switch[1] if switch[1] else "Unknown"
                model = switch[3]
                version = switch[4]  # VERSION column
                fw_version = switch[5]
                serial_number = switch[6]

                cursor.execute(
                    "SELECT s.destination_ip FROM MAAMD.SWITCH_SNMP_SUBSCRIPTIONS s WHERE LOWER(s.SWITCH_HOSTNAME) = LOWER(:1)", (hostname,)
                )
                alert_ips = [row[0] for row in cursor.fetchall()]
                product_asr = "Yes" if any('asr1' in ip.lower() for ip in alert_ips if ip) else "No"
                ipv4_asr = "Yes" if any('phoenix' in ip.lower() and 'databasede3phx' in ip.lower() for ip in alert_ips if ip) else "No"
                ipv6_asr = "Yes" if any(':' in ip for ip in alert_ips if ip) else "No"

                active_subs = switch[7]
                snmp_users = switch[8]

                switches.append((hostname, switch_type, product_asr, ipv4_asr, ipv6_asr, active_subs, snmp_users, model, version, serial_number))

                if product_asr == "Yes":
                    production_asr_yes += 1
                if ipv4_asr == "Yes":
                    ipv4_asr_yes += 1
                if ipv6_asr == "Yes":
                    ipv6_asr_yes += 1

            summary = {
                'total_switches': total_switches,
                'production_asr_yes': production_asr_yes,
                'ipv4_asr_yes': ipv4_asr_yes,
                'ipv6_asr_yes': ipv6_asr_yes
            }

        logger.info(f"Fetched {len(switches)} switches for user {current_user.id}")
        logger.debug(f"Rendering switch_management_summary.html with {len(switches)} switches and summary {summary}")
        try:
            return render_template(
                'switch_management_summary.html',
                switches=switches,
                summary=summary,
                filters={'hostname': hostname_filter, 'switch_type': switch_type_filter},
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
        except Exception as e:
            logger.error(f"Template rendering error in switch_index: {str(e)}", exc_info=True)
            flash(f"Template rendering error: {str(e)}", "error")
            if 'superuser' in str(e).lower():
                flash("Superuser access issue detected.", "error")
            return render_template(
                'switch_management_summary.html',
                switches=[],
                summary={},
                filters={'hostname': hostname_filter, 'switch_type': switch_type_filter},
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id,
                error_message="No switches found or rendering failed."
            )
    except oracledb.Error as e:
        logger.error(f"Database error in switch_index: {e}")
        flash(f"Error retrieving switches from database: {e}", "error")
        return render_template(
            'switch_management_summary.html',
            switches=[],
            summary={},
            filters={'hostname': hostname_filter, 'switch_type': switch_type_filter},
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id,
            error_message="Database error retrieving switches."
        )
    except Exception as e:
        logger.error(f"Unexpected error in switch_index: {str(e)}", exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
        return render_template(
            'switch_management_summary.html',
            switches=[],
            summary={},
            filters={'hostname': hostname_filter, 'switch_type': switch_type_filter},
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id,
            error_message="Unexpected error retrieving switches."
        )
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])

@switches_bp.route('/switch_detail/<hostname>', methods=['GET', 'POST'])
@login_required
def switch_detail(hostname):
    logger.info(f"Incoming request: method={request.method}, path=/switches/switch_detail/{hostname}, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT HOSTNAME, IP_ADDRESS, MAKE, MODEL 
            FROM MAAMD.SWITCH_INFO 
            WHERE LOWER(HOSTNAME) = LOWER(:1)
        """, (hostname,))
        switch_data = cursor.fetchone()
        if not switch_data:
            flash("Switch not found", "error")
            logger.warning(f"Switch {hostname} not found for user {current_user.id}")
            return redirect(url_for('switches.switch_index'))

        hostname, ip_address, make, model = switch_data

        cursor.execute("""
            SELECT ALERT_ID, VERSION, DESTINATION_IP, COMMUNITY_STRING, USERNAME, STATUS, PORT, SECURITY_LEVEL 
            FROM MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
            WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1)
        """, (hostname,))
        alerts = cursor.fetchall()

        cursor.execute("""
            SELECT USERNAME, AUTHENTICATION_PROTOCOL, ACCESS_LEVEL 
            FROM MAAMD.SWITCH_SNMP_USERS 
            WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1)
        """, (hostname,))
        users = cursor.fetchall()

        user_data = {'users': users}
        slot_status = {'alerts_full': len(alerts) >= 15, 'users_full': len(users) >= 10}

        ssh_key_path = os.environ.get('SWITCH_SSH_KEY_PATH', '/home/maatest/.ssh/id_rsa')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        switch_username = 'admin' if make.lower() == 'cisco' else 'root'
        switch_password = get_credential(cursor, 'SWITCH', hostname, switch_username) or 'welcome2'

        flashed_ssh_errors = session.get('flashed_ssh_errors', {})
        ssh_error_key = f"ssh_error_{hostname}"

        try:
            private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
            logger.info(f"Attempting passwordless SSH to {ip_address} for switch {hostname}")
            try:
                ssh.connect(
                    hostname=ip_address,
                    username=switch_username,
                    pkey=private_key,
                    timeout=10,
                    auth_timeout=10,
                    banner_timeout=10
                )
                logger.info(f"Passwordless SSH successful to {ip_address} for switch {hostname}")
            except paramiko.AuthenticationException:
                logger.info(f"Passwordless SSH failed, falling back to {switch_username}/{switch_password} for {ip_address}")
                ssh.connect(
                    hostname=ip_address,
                    username=switch_username,
                    password=switch_password,
                    timeout=10,
                    auth_timeout=10,
                    banner_timeout=10
                )
                logger.info(f"Password-based SSH successful to {ip_address} for switch {hostname}")

            ssh.get_transport().set_keepalive(10)
            time.sleep(1)

            if request.method == 'POST':
                if 'delete_alert' in request.form:
                    alert_id = int(request.form.get('delete_alert', 0))
                    if alert_id < 1 or alert_id > 15:
                        flash(f"Invalid alert ID {alert_id}. Must be between 1 and 15.", "error")
                        logger.warning(f"Invalid alert ID {alert_id} for deletion by {current_user.id}")
                    elif not current_user.is_superuser:
                        flash("Superuser access required to delete alerts.", "error")
                        logger.warning(f"Non-superuser {current_user.id} attempted to delete alert ID {alert_id}")
                    else:
                        cursor.execute("""
                            SELECT DESTINATION_IP, VERSION, COMMUNITY_STRING, USERNAME, PORT, SECURITY_LEVEL
                            FROM MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
                            WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1) AND ALERT_ID = :2
                        """, (hostname, alert_id))
                        alert_details = cursor.fetchone()
                        if not alert_details:
                            flash(f"Alert ID {alert_id} not found for switch {hostname}", "error")
                            logger.warning(f"Alert ID {alert_id} not found for switch {hostname} by {current_user.id}")
                        else:
                            destination_ip, version, community_string, username, port, security_level = alert_details
                            result = reset_switch_alert_to_default(
                                ssh_user=switch_username,
                                switch_ip=ip_address,
                                alert_id=alert_id,
                                switch_type=make.lower(),
                                destination_ip=destination_ip,
                                version=version,
                                community_string=community_string,
                                username=username,
                                security_level=security_level,
                                port=port,
                                confirm_delete=False,
                                ssh=ssh
                            )

                            if result['status'] == 'prompt':
                                session['pending_delete'] = {
                                    'alert_id': alert_id,
                                    'switch_hostname': hostname,
                                    'destination_ip': destination_ip,
                                    'version': version,
                                    'community_string': community_string,
                                    'username': username,
                                    'security_level': security_level,
                                    'port': port,
                                    'switch_config': result['switch_config']
                                }
                                return redirect(url_for('switches.confirm_snmp_deletion', hostname=hostname))

                            if make.lower() == 'cisco':
                                verify_command = f"show snmp host | include {destination_ip}"
                                stdin, stdout, stderr = ssh.exec_command(verify_command, timeout=30)
                                verify_output = stdout.read().decode().strip()
                                logger.info(f"Post-deletion verification output for {hostname}: {verify_output}")
                                if f"{destination_ip}" in verify_output and f"{port}" in verify_output:
                                    flash(f"Failed to delete SNMP host: Configuration still present on switch", "error")
                                    logger.error(f"SNMP host {destination_ip} port {port} still present on {hostname} after deletion attempt: {verify_output}")
                                    return redirect(url_for('switches.switch_detail', hostname=hostname))

                            if result['status'] == 'success':
                                cursor.execute("""
                                    UPDATE MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
                                    SET VERSION = 'v2c', DESTINATION_IP = '0.0.0.0', COMMUNITY_STRING = 'public', 
                                        USERNAME = NULL, STATUS = 'disable', PORT = 0, SECURITY_LEVEL = 'noauth'
                                    WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1) AND ALERT_ID = :2
                                """, (hostname, alert_id))
                                conn.commit()
                                flash(f"Alert ID {alert_id} successfully deleted", "success")
                                logger.info(f"Alert ID {alert_id} disabled for switch {hostname} by {current_user.id}")
                            else:
                                flash(result.get('message', 'Failed to delete SNMP host'), "error")
                                logger.error(f"Failed to reset alert ID {alert_id} for switch {hostname}: {result.get('message', 'Unknown error')}")

                            alerts = cursor.execute("""
                                SELECT ALERT_ID, VERSION, DESTINATION_IP, COMMUNITY_STRING, USERNAME, STATUS, PORT, SECURITY_LEVEL 
                                FROM MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
                                WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1)
                            """, (hostname,)).fetchall()

            logger.debug(f"Rendering switch_detail.html for switch {hostname} with {len(alerts)} alerts")
            try:
                return render_template(
                    'switch_detail.html',
                    switch_data=switch_data,
                    alerts=alerts,
                    user_data=user_data,
                    slot_status=slot_status,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    username=current_user.id
                )
            except Exception as e:
                logger.error(f"Template rendering error in switch_detail: {str(e)}", exc_info=True)
                flash(f"Template rendering error: {str(e)}", "error")
                if 'superuser' in str(e).lower():
                    flash("Superuser access issue detected.", "error")
                return render_template(
                    'switch_detail.html',
                    switch_data=switch_data,
                    alerts=[],
                    user_data={'users': []},
                    slot_status=slot_status,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    username=current_user.id,
                    error_message="Failed to render switch details."
                )
        except paramiko.SSHException as e:
            if ssh_error_key not in flashed_ssh_errors:
                flash(f"SSH connection failed: {e}", "error")
                session['flashed_ssh_errors'] = flashed_ssh_errors
                session['flashed_ssh_errors'][ssh_error_key] = True
            logger.error(f"SSH connection failed for {ip_address} by {current_user.id}: {e}")
            try:
                return render_template(
                    'switch_detail.html',
                    switch_data=switch_data,
                    alerts=alerts,
                    user_data=user_data,
                    slot_status=slot_status,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    username=current_user.id
                )
            except Exception as e:
                logger.error(f"Template rendering error in switch_detail (SSH error): {str(e)}", exc_info=True)
                flash(f"Template rendering error: {str(e)}", "error")
                return render_template(
                    'switch_detail.html',
                    switch_data=switch_data,
                    alerts=[],
                    user_data={'users': []},
                    slot_status=slot_status,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    username=current_user.id,
                    error_message="Failed to render switch details due to SSH error."
                )
        finally:
            ssh.close()
    except oracledb.Error as e:
        logger.error(f"Database error in switch_detail for {hostname} by {current_user.id}: {e}")
        flash(f"Database error: {e}", "error")
        return redirect(url_for('switches.switch_index'))
    except Exception as e:
        logger.error(f"Unexpected error in switch_detail: {str(e)}", exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
        return redirect(url_for('switches.switch_index'))
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])

@switches_bp.route('/confirm_snmp_deletion/<hostname>', methods=['GET', 'POST'])
@login_required
def confirm_snmp_deletion(hostname):
    logger.info(f"Incoming request: method={request.method}, path=/switches/confirm_snmp_deletion/{hostname}, user={current_user.id}")
    if 'pending_delete' not in session:
        flash("No pending deletion found.", "error")
        logger.warning(f"No pending deletion found for switch {hostname} by {current_user.id}")
        return redirect(url_for('switches.switch_detail', hostname=hostname))

    pending_delete = session['pending_delete']
    if pending_delete['switch_hostname'].lower() != hostname.lower():
        flash("Hostname mismatch in pending deletion.", "error")
        logger.warning(f"Hostname mismatch in pending deletion: {pending_delete['switch_hostname']} vs {hostname} by {current_user.id}")
        session.pop('pending_delete', None)
        return redirect(url_for('switches.switch_detail', hostname=hostname))

    if request.method == 'POST':
        if 'confirm' in request.form:
            if not current_user.is_superuser:
                flash("Superuser access required to confirm deletion.", "error")
                logger.warning(f"Non-superuser {current_user.id} attempted to confirm deletion for alert ID {pending_delete['alert_id']}")
                session.pop('pending_delete', None)
                return redirect(url_for('switches.switch_detail', hostname=hostname))

            conn = get_db_pool_connection(current_app.config['DB_POOL'])
            cursor = conn.cursor()
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_key_path = os.environ.get('SWITCH_SSH_KEY_PATH', '/home/maatest/.ssh/id_rsa')
            switch_username = 'admin'
            switch_password = get_credential(cursor, 'SWITCH', hostname, switch_username) or 'welcome2'

            try:
                cursor.execute("""
                    SELECT IP_ADDRESS, MAKE 
                    FROM MAAMD.SWITCH_INFO 
                    WHERE LOWER(HOSTNAME) = LOWER(:1)
                """, (hostname,))
                switch_data = cursor.fetchone()
                if not switch_data:
                    flash("Switch not found", "error")
                    logger.error(f"Switch {hostname} not found in MAAMD.SWITCH_INFO by {current_user.id}")
                    return redirect(url_for('switches.switch_detail', hostname=hostname))
                ip_address, make = switch_data

                private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
                logger.info(f"Attempting passwordless SSH to {ip_address} for switch {hostname}")
                try:
                    ssh.connect(
                        hostname=ip_address,
                        username=switch_username,
                        pkey=private_key,
                        timeout=10,
                        auth_timeout=10,
                        banner_timeout=10
                    )
                    logger.info(f"Passwordless SSH successful to {ip_address} for switch {hostname}")
                except paramiko.AuthenticationException:
                    logger.info(f"Passwordless SSH failed, falling back to {switch_username}/{switch_password} for {ip_address}")
                    ssh.connect(
                        hostname=ip_address,
                        username=switch_username,
                        password=switch_password,
                        timeout=10,
                        auth_timeout=10,
                        banner_timeout=10
                    )
                    logger.info(f"Password-based SSH successful to {ip_address} for switch {hostname}")

                ssh.get_transport().set_keepalive(10)
                time.sleep(1)

                result = reset_switch_alert_to_default(
                    ssh=ssh,
                    alert_id=pending_delete['alert_id'],
                    switch_type=make.lower(),
                    destination_ip=pending_delete['destination_ip'],
                    version=pending_delete['version'],
                    community_string=pending_delete['community_string'],
                    username=pending_delete['username'],
                    security_level=pending_delete['security_level'],
                    port=pending_delete['port'],
                    confirm_delete=True
                )

                if result['status'] == 'success':
                    cursor.execute("""
                        UPDATE MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
                        SET VERSION = 'v2c', DESTINATION_IP = '0.0.0.0', COMMUNITY_STRING = 'public', 
                            USERNAME = NULL, STATUS = 'disable', PORT = 0, SECURITY_LEVEL = 'noauth'
                        WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1) AND ALERT_ID = :2
                    """, (hostname, pending_delete['alert_id']))
                    conn.commit()
                    flash(f"Alert ID {pending_delete['alert_id']} successfully deleted", "success")
                    logger.info(f"Alert ID {pending_delete['alert_id']} disabled for switch {hostname} by {current_user.id}")
                else:
                    flash(result.get('message', 'Failed to delete SNMP host'), "error")
                    logger.error(f"Failed to reset alert ID {pending_delete['alert_id']} for switch {hostname}: {result.get('message', 'Unknown error')}")

            except (paramiko.SSHException, oracledb.Error) as e:
                logger.error(f"Error during confirmed deletion for switch {hostname} by {current_user.id}: {e}")
                flash(f"Error during deletion: {str(e)}", "error")
                if 'superuser' in str(e).lower():
                    flash("Superuser access issue detected.", "error")
            finally:
                ssh.close()
                cursor.close()
                release_db_connection(conn, current_app.config['DB_POOL'])
        else:
            flash("Deletion canceled.", "info")
            logger.info(f"Deletion of alert ID {pending_delete['alert_id']} for switch {hostname} canceled by {current_user.id}")

        session.pop('pending_delete', None)
        return redirect(url_for('switches.switch_detail', hostname=hostname))

    logger.debug(f"Rendering confirm_snmp_deletion.html with alert_id={pending_delete['alert_id']}")
    try:
        return render_template(
            'confirm_snmp_deletion.html',
            hostname=hostname,
            alert_id=pending_delete['alert_id'],
            switch_config=pending_delete['switch_config'],
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id
        )
    except Exception as e:
        logger.error(f"Template rendering error in confirm_snmp_deletion: {str(e)}", exc_info=True)
        flash(f"Template rendering error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
        return redirect(url_for('switches.switch_detail', hostname=hostname))

@switches_bp.route('/edit_alert/<hostname>/<int:alert_id>', methods=['GET', 'POST'])
@login_required
def edit_alert(hostname, alert_id):
    logger.info(f"Incoming request: method={request.method}, path=/switches/edit_alert/{hostname}/{alert_id}, user={current_user.id}")
    logger.debug(f"User superuser status: {current_user.is_superuser}")
    if not current_user.is_superuser:
        flash("Superuser access required to edit alerts.", "error")
        logger.warning(f"Non-superuser {current_user.id} attempted to edit alert ID {alert_id}")
        logger.debug("Redirecting to switch_detail due to non-superuser access")
        return redirect(url_for('switches.switch_detail', hostname=hostname))

    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()

    try:
        logger.debug(f"Querying switch data for hostname: {hostname}")
        cursor.execute("""
            SELECT HOSTNAME, IP_ADDRESS, MAKE, MODEL 
            FROM MAAMD.SWITCH_INFO 
            WHERE LOWER(HOSTNAME) = LOWER(:1)
        """, (hostname,))
        switch_data = cursor.fetchone()
        if not switch_data:
            flash("Switch not found", "error")
            logger.warning(f"Switch {hostname} not found for user {current_user.id}")
            logger.debug("Redirecting to switch_index due to switch not found")
            return redirect(url_for('switches.switch_index'))

        logger.debug(f"Querying alert data for hostname: {hostname}, alert_id: {alert_id}")
        cursor.execute("""
            SELECT ALERT_ID, VERSION, DESTINATION_IP, COMMUNITY_STRING, USERNAME, STATUS, PORT 
            FROM MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
            WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:1) AND ALERT_ID = :2
        """, (hostname, alert_id))
        alert = cursor.fetchone()
        if not alert:
            flash(f"Alert ID {alert_id} not found for switch {hostname}", "error")
            logger.warning(f"Alert ID {alert_id} not found for switch {hostname} by {current_user.id}")
            logger.debug("Redirecting to switch_detail due to alert not found")
            return redirect(url_for('switches.switch_detail', hostname=hostname))

        hostname, ip_address, make, model = switch_data
        old_alert_id, old_version, old_destination_ip, old_community_string, old_username, old_status, old_port = alert

        ssh_key_path = os.environ.get('SWITCH_SSH_KEY_PATH', '/home/maatest/.ssh/id_rsa')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        switch_username = 'admin' if make.lower() == 'cisco' else 'root'
        logger.debug(f"Fetching credentials for switch_username: {switch_username}, hostname: {hostname}")
        switch_password = get_credential(cursor, 'SWITCH', hostname, switch_username) or 'welcome2'

        flashed_ssh_errors = session.get('flashed_ssh_errors', {})
        ssh_error_key = f"ssh_error_{hostname}"

        try:
            private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
            logger.info(f"Attempting passwordless SSH to {ip_address} for switch {hostname}")
            try:
                ssh.connect(
                    hostname=ip_address,
                    username=switch_username,
                    pkey=private_key,
                    timeout=10,
                    auth_timeout=10,
                    banner_timeout=10
                )
                logger.info(f"Passwordless SSH successful to {ip_address} for switch {hostname}")
            except paramiko.AuthenticationException:
                logger.info(f"Passwordless SSH failed, falling back to {switch_username}/{switch_password} for {ip_address}")
                ssh.connect(
                    hostname=ip_address,
                    username=switch_username,
                    password=switch_password,
                    timeout=10,
                    auth_timeout=10,
                    banner_timeout=10
                )
                logger.info(f"Password-based SSH successful to {ip_address} for switch {hostname}")

            ssh.get_transport().set_keepalive(10)
            time.sleep(1)

            if request.method == 'POST' and 'update_alert' in request.form:
                alert_id_from_form = int(request.form.get('alert_id', 0))
                if alert_id_from_form < 1 or alert_id_from_form > 15:
                    flash(f"Invalid alert ID {alert_id_from_form}. Must be between 1 and 15.", "error")
                    logger.warning(f"Invalid alert ID {alert_id_from_form} for update by {current_user.id}")
                elif alert_id_from_form != alert_id:
                    flash(f"Alert ID mismatch: {alert_id_from_form} does not match {alert_id}", "error")
                    logger.warning(f"Alert ID mismatch: {alert_id_from_form} vs {alert_id} by {current_user.id}")
                else:
                    version = request.form.get('version', 'v2c')
                    destination_ip = request.form.get('destination_ip', '0.0.0.0')
                    port = int(request.form.get('port', 0))
                    community_string = request.form.get('community_string', 'public') if version == 'v2c' else None
                    username = request.form.get('username', None) if version == 'v3' else None
                    status = request.form.get('status', 'disable')

                    try:
                        if version == 'v2c':
                            set_switch_alert_v2c(ssh, alert_id, destination_ip, port, community_string, status, make)
                        else:
                            set_switch_alert_v3(
                                ssh, alert_id, destination_ip, port, username, status, make,
                                old_destination_ip=old_destination_ip, old_version=old_version,
                                old_port=old_port, old_username=old_username
                            )

                        cursor.execute("""
                            UPDATE MAAMD.SWITCH_SNMP_SUBSCRIPTIONS 
                            SET VERSION = :1, DESTINATION_IP = :2, COMMUNITY_STRING = :3, USERNAME = :4, STATUS = :5, PORT = :6 
                            WHERE LOWER(SWITCH_HOSTNAME) = LOWER(:7) AND ALERT_ID = :8
                        """, (version, destination_ip, community_string, username, status, port, hostname, alert_id))
                        conn.commit()
                        flash(f"Alert ID {alert_id} updated successfully", "success")
                        logger.info(f"Alert ID {alert_id} updated for switch {hostname} by {current_user.id}")
                        return redirect(url_for('switches.switch_detail', hostname=hostname))
                    except Exception as e:
                        logger.error(f"Failed to update alert ID {alert_id}: {str(e)}", exc_info=True)
                        flash(f"Failed to update alert: {str(e)}", "error")
                        if 'superuser' in str(e).lower():
                            flash("Superuser access issue detected.", "error")

            logger.debug(f"Rendering edit_snmp_alert_switch.html with alert={alert}")
            try:
                return render_template(
                    'edit_snmp_alert_switch.html',
                    hostname=hostname,
                    alert_id=alert_id,
                    alert=alert,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    username=current_user.id
                )
            except Exception as e:
                logger.error(f"Template rendering error in edit_alert: {str(e)}", exc_info=True)
                flash(f"Template rendering error: {str(e)}", "error")
                if 'superuser' in str(e).lower():
                    flash("Superuser access issue detected.", "error")
                return render_template(
                    'edit_snmp_alert_switch.html',
                    hostname=hostname,
                    alert_id=alert_id,
                    alert=None,
                    logo_base64=current_app.ORACLE_LOGO_BASE64,
                    oracle_red=current_app.ORACLE_RED,
                    username=current_user.id,
                    error_message="Failed to render alert details."
                )
        except paramiko.SSHException as e:
            if ssh_error_key not in flashed_ssh_errors:
                flash(f"SSH connection failed: {e}", "error")
                session['flashed_ssh_errors'] = flashed_ssh_errors
                session['flashed_ssh_errors'][ssh_error_key] = True
            logger.error(f"SSH connection failed for {ip_address} by {current_user.id}: {e}")
            logger.debug("Redirecting to switch_detail due to SSH failure")
            return redirect(url_for('switches.switch_detail', hostname=hostname))
        finally:
            ssh.close()
    except oracledb.Error as e:
        logger.error(f"Database error in edit_alert for {hostname} by {current_user.id}: {e}")
        flash(f"Database error: {e}", "error")
        logger.debug("Redirecting to switch_index due to database error")
        return redirect(url_for('switches.switch_index'))
    except Exception as e:
        logger.error(f"Unexpected error in edit_alert: {str(e)}", exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
        logger.debug("Redirecting to switch_index due to unexpected error")
        return redirect(url_for('switches.switch_index'))
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
