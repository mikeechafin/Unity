from flask import Blueprint, redirect, render_template, url_for, flash, request, session, current_app
from flask_login import login_required, current_user
import paramiko
import threading
import oracledb
import os
import time
from maa_libraries import get_db_pool_connection, release_db_connection, fetch_host_details, get_slot_counts, execute_ssh_command, set_alert_v2c, set_alert_v3, reset_alert_to_default, create_snmp_user, logger

# Version: 1.0.3
# Changelog:
# - 1.0.0: Initial version
# - 1.0.1: Improved SSH error handling
# - 1.0.2: Added try-except for render_template
# - 1.0.3: Added superuser error handling, debug logging, and empty data message

ilom_bp = Blueprint('ilom', __name__, template_folder='templates/ilom', static_folder='static/ilom')

@ilom_bp.route('/')
@login_required
def ilom_index():
    logger.info(f"Incoming request: method=GET, path=/ilom, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL")
        current_schema = cursor.fetchone()[0]
        logger.info(f"Current schema: {current_schema}")

        hostname_filter = request.args.get('hostname', '').strip()

        query = "SELECT hostname FROM MAAMD.ilom_hosts WHERE 1=1"
        params = {}
        if hostname_filter:
            query += " AND LOWER(hostname) LIKE LOWER(:hostname)"
            params['hostname'] = f"%{hostname_filter}%"
        query += " ORDER BY hostname"

        cursor.execute(query, params)
        hosts = cursor.fetchall()

        extended_hosts = []
        summary = {'total_iloms': 0, 'production_asr_yes': 0, 'ipv4_asr_yes': 0, 'ipv6_asr_yes': 0}
        if hosts:
            total_iloms = len(hosts)
            production_asr_yes = 0
            ipv4_asr_yes = 0
            ipv6_asr_yes = 0

            for host in hosts:
                hostname = host[0].lower()
                cursor.execute(
                    "SELECT s.destination_ip FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                )
                alert_ips = [row[0] for row in cursor.fetchall()]
                product_asr = "Yes" if cursor.execute(
                    "SELECT COUNT(*) FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1) AND UPPER(s.destination_ip) LIKE '%PEO-DIS-ENGSYS-ASR1%'",
                    (hostname,)
                ).fetchone()[0] > 0 else "No"
                ipv4_asr = "Yes" if cursor.execute(
                    "SELECT COUNT(*) FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1) AND UPPER(s.destination_ip) LIKE '%PHOENIX235943%'",
                    (hostname,)
                ).fetchone()[0] > 0 else "No"
                ipv6_asr = "Yes" if cursor.execute(
                    "SELECT COUNT(*) FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1) AND UPPER(s.destination_ip) LIKE '%SCAQAA04CELADM12%'",
                    (hostname,)
                ).fetchone()[0] > 0 else "No"
                cursor.execute(
                    "SELECT COUNT(*) FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1) AND s.destination_ip NOT IN ('0.0.0.0', '1.1.1.1') AND s.port != 0",
                    (hostname,)
                )
                active_alerts = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT COUNT(*) FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                )
                snmp_users = cursor.fetchone()[0]
                extended_hosts.append((hostname, product_asr, ipv4_asr, ipv6_asr, active_alerts, snmp_users))
                if product_asr == "Yes":
                    production_asr_yes += 1
                if ipv4_asr == "Yes":
                    ipv4_asr_yes += 1
                if ipv6_asr == "Yes":
                    ipv6_asr_yes += 1

            summary = {
                'total_iloms': total_iloms,
                'production_asr_yes': production_asr_yes,
                'ipv4_asr_yes': ipv4_asr_yes,
                'ipv6_asr_yes': ipv6_asr_yes
            }

        logger.debug(f"Rendering ilom/index.html with {len(extended_hosts)} hosts and summary {summary}")
        try:
            return render_template(
                'ilom/index.html',
                hosts=extended_hosts,
                summary=summary,
                filters={'hostname': hostname_filter},
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
        except Exception as e:
            logger.error(f"Template rendering error in ilom_index: {str(e)}", exc_info=True)
            flash(f"Template rendering error: {str(e)}", "error")
            if 'superuser' in str(e).lower():
                flash("Superuser access issue detected.", "error")
            return render_template(
                'ilom/index.html',
                hosts=[],
                summary={},
                filters={'hostname': hostname_filter},
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id,
                error_message="No ILOM hosts found or rendering failed."
            )
    except oracledb.Error as e:
        logger.error(f"Database error in ilom_index: {e}")
        flash(f"Error retrieving hosts from database: {e}", "error")
        return render_template(
            'ilom/index.html',
            hosts=[],
            summary={},
            filters={'hostname': hostname_filter},
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id,
            error_message="Database error retrieving ILOM hosts."
        )
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])

@ilom_bp.route('/delete_hosts', methods=['POST'])
@login_required
def delete_hosts():
    logger.info(f"Incoming request: method=POST, path=/ilom/delete_hosts, user={current_user.id}")
    if not current_user.is_superuser:
        flash("Superuser access required to delete hosts.", "error")
        logger.warning(f"Non-superuser {current_user.id} attempted to delete hosts")
        return redirect(url_for('ilom.ilom_index'))

    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        hostnames = request.form.getlist('hostnames')
        if not hostnames:
            flash("No hosts selected for deletion.", "error")
            logger.warning("No hostnames selected for deletion")
        else:
            for hostname in hostnames:
                hostname = hostname.lower()
                cursor.execute("DELETE FROM MAAMD.snmp_subscriptions WHERE LOWER(ILOM_HOSTNAME) = LOWER(:1)", (hostname,))
                cursor.execute("DELETE FROM MAAMD.snmp_users WHERE LOWER(ILOM_HOSTNAME) = LOWER(:1)", (hostname,))
                cursor.execute("DELETE FROM MAAMD.ilom_hosts WHERE LOWER(hostname) = LOWER(:1)", (hostname,))
            conn.commit()
            flash(f"Successfully deleted {len(hostnames)} host(s).", "success")
            logger.info(f"Deleted {len(hostnames)} hosts by user {current_user.id}")
    except oracledb.Error as e:
        logger.error(f"Database error deleting hosts: {e}")
        conn.rollback()
        flash("Error deleting hosts from database.", "error")
    except Exception as e:
        logger.error(f"Unexpected error in delete_hosts: {str(e)}", exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
    return redirect(url_for('ilom.ilom_index'))

@ilom_bp.route('/host/<hostname>', methods=['GET', 'POST'])
@login_required
def host_detail(hostname):
    logger.info(f"Incoming request: method={request.method}, path=/ilom/host/{hostname}, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    host, alerts, user_data = fetch_host_details(cursor, hostname)
    if not host:
        flash("Host not found", "error")
        logger.warning(f"Host {hostname} not found for user {current_user.id}")
        release_db_connection(conn, current_app.config['DB_POOL'])
        return redirect(url_for('ilom.ilom_index'))

    hostname, ilom_ip = host
    ssh_key_path = os.environ.get('ILOM_SSH_KEY_PATH', '/home/maatest/.ssh/id_rsa')
    ilom_username = os.environ.get('ILOM_USERNAME', 'root')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    slot_status = {'alerts_full': False, 'users_full': False}

    flashed_ssh_errors = session.get('flashed_ssh_errors', {})
    ssh_error_key = f"ssh_error_{hostname}"

    try:
        private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        logger.info(f"Connecting to {ilom_ip} with username {ilom_username} using SSH key at {ssh_key_path}")
        ssh.connect(
            hostname=ilom_ip,
            username=ilom_username,
            pkey=private_key,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10
        )
        ssh.get_transport().set_keepalive(10)
        time.sleep(1)
        slot_status = get_slot_counts(ssh, hostname)

        if request.method == 'POST':
            logger.debug(f"POST form data: {request.form}")
            if 'delete_user' in request.form:
                username = request.form.get('delete_user', '')
                if cursor.execute("SELECT COUNT(*) FROM MAAMD.protected_entries WHERE type = 'snmp_user' AND value = :1", (username,)).fetchone()[0] > 0 and not current_user.is_superuser:
                    flash("Cannot delete protected user", "error")
                    logger.warning(f"Non-superuser {current_user.id} attempted to delete protected user {username}")
                else:
                    execute_ssh_command(ssh, f"delete /SP/services/snmp/users/{username}", interactive=True)
                    cursor.execute(
                        "DELETE FROM MAAMD.snmp_users WHERE LOWER(ILOM_HOSTNAME) = LOWER(:1) AND username = :2",
                        (hostname, username)
                    )
                    conn.commit()
                    flash("User deleted from ILOM and database", "success")
                    logger.info(f"User {username} deleted for hostname {hostname} by {current_user.id}")
                    user_data['users'] = cursor.execute(
                        "SELECT u.username, u.authentication_protocol, u.access_level FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                    ).fetchall()
                    user_data['available_users'] = [str(row[0]) for row in cursor.execute(
                        "SELECT DISTINCT u.username FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                    ).fetchall() if row[0] is not None] or ['No users available']
            elif 'delete_alert' in request.form:
                alert_id = int(request.form.get('delete_alert', 0))
                logger.debug(f"Delete request received: alert_id={alert_id}")
                if alert_id < 1 or alert_id > 15:
                    flash(f"Invalid alert ID {alert_id}. Must be between 1 and 15.", "error")
                    logger.warning(f"Invalid alert ID {alert_id} for deletion by {current_user.id}")
                elif alert_id == 1 and not current_user.is_superuser:
                    flash("Cannot delete alert ID 1", "error")
                    logger.warning(f"Non-superuser {current_user.id} attempted to delete protected alert ID 1")
                else:
                    reset_alert_to_default(ssh, alert_id)
                    cursor.execute(
                        "UPDATE MAAMD.snmp_subscriptions SET version = 'v2c', destination_ip = '0.0.0.0', community_string = 'public', username = NULL, status = 'disable', port = 0 WHERE LOWER(ILOM_HOSTNAME) = LOWER(:1) AND alert_id = :2",
                        (hostname, alert_id)
                    )
                    conn.commit()
                    flash(f"Alert ID {alert_id} updated to disabled state on ILOM and database", "success")
                    logger.info(f"Alert ID {alert_id} disabled for hostname {hostname} by {current_user.id}")
                    alerts = cursor.execute(
                        "SELECT s.alert_id, s.version, s.destination_ip, s.community_string, s.username, s.status, s.port FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                    ).fetchall()
            elif 'delete_all_unprotected_alerts' in request.form:
                if not current_user.is_superuser:
                    flash("Superuser access required to delete all unprotected alerts.", "error")
                    logger.warning(f"Non-superuser {current_user.id} attempted to delete all unprotected alerts")
                else:
                    deleted_count = 0
                    for alert in alerts:
                        alert_id = alert[0]
                        if alert_id == 1:
                            continue
                        reset_alert_to_default(ssh, alert_id)
                        cursor.execute(
                            "UPDATE MAAMD.snmp_subscriptions SET version = 'v2c', destination_ip = '0.0.0.0', community_string = 'public', username = NULL, status = 'disable', port = 0 WHERE LOWER(ILOM_HOSTNAME) = LOWER(:1) AND alert_id = :2",
                            (hostname, alert_id)
                        )
                        deleted_count += 1
                    conn.commit()
                    flash(f"Successfully deleted {deleted_count} unprotected SNMP alerts on ILOM and database", "success")
                    logger.info(f"Deleted {deleted_count} unprotected SNMP alerts for hostname {hostname} by {current_user.id}")
                    alerts = cursor.execute(
                        "SELECT s.alert_id, s.version, s.destination_ip, s.community_string, s.username, s.status, s.port FROM MAAMD.snmp_subscriptions s WHERE LOWER(s.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                    ).fetchall()
            elif 'add_user' in request.form:
                username = request.form.get('username', '').strip()
                authentication_protocol = request.form.get('authentication_protocol', 'SHA')
                privacy_protocol = request.form.get('privacy_protocol', 'AES')
                access_level = request.form.get('access_level', 'ro')
                authentication_password = request.form.get('authentication_password', '').strip()
                privacy_password = request.form.get('privacy_password', '').strip()

                if not username or not authentication_password or not privacy_password:
                    flash("Username, authentication password, and privacy password are required", "error")
                    logger.warning(f"Missing required fields for adding SNMP user by {current_user.id}")
                elif not current_user.is_superuser:
                    flash("Superuser access required to add SNMP users.", "error")
                    logger.warning(f"Non-superuser {current_user.id} attempted to add SNMP user")
                else:
                    create_snmp_user(ssh, username, authentication_protocol, privacy_protocol, access_level, authentication_password, privacy_password)
                    cursor.execute(
                        "INSERT INTO MAAMD.snmp_users (ILOM_HOSTNAME, username, authentication_protocol, privacy_protocol, access_level) VALUES (:1, :2, :3, :4, :5)",
                        (hostname, username, authentication_protocol, privacy_protocol, access_level)
                    )
                    conn.commit()
                    flash(f"SNMP user {username} added successfully on ILOM and database", "success")
                    logger.info(f"SNMP user {username} added for hostname {hostname} by {current_user.id}")
                    user_data['users'] = cursor.execute(
                        "SELECT u.username, u.authentication_protocol, u.access_level FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                    ).fetchall()
                    user_data['available_users'] = [str(row[0]) for row in cursor.execute(
                        "SELECT DISTINCT u.username FROM MAAMD.snmp_users u WHERE LOWER(u.ILOM_HOSTNAME) = LOWER(:1)", (hostname,)
                    ).fetchall() if row[0] is not None] or ['No users available']

        logger.debug(f"Rendering ilom/host_detail.html with host_data={host}, alerts={len(alerts)}, users={len(user_data['users'])}")
        try:
            return render_template(
                'ilom/host_detail.html',
                host_data=host,
                alerts=alerts,
                user_data=user_data,
                slot_status=slot_status,
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
        except Exception as e:
            logger.error(f"Template rendering error in host_detail: {str(e)}", exc_info=True)
            flash(f"Template rendering error: {str(e)}", "error")
            if 'superuser' in str(e).lower():
                flash("Superuser access issue detected.", "error")
            return render_template(
                'ilom/host_detail.html',
                host_data=host,
                alerts=[],
                user_data={'users': [], 'available_users': ['No users available']},
                slot_status=slot_status,
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id,
                error_message="Failed to render host details."
            )
    except paramiko.SSHException as e:
        if ssh_error_key not in flashed_ssh_errors:
            flash(f"SSH connection failed: {str(e)}", "error")
            session['flashed_ssh_errors'] = flashed_ssh_errors
            session['flashed_ssh_errors'][ssh_error_key] = True
        logger.error(f"SSH connection failed for {ilom_ip} by {current_user.id}: {str(e)}")
        return render_template(
            'ilom/host_detail.html',
            host_data=host,
            alerts=alerts,
            user_data=user_data,
            slot_status=slot_status,
            logo_base64=current_app.ORACLE_LOGO_BASE64,
            oracle_red=current_app.ORACLE_RED,
            username=current_user.id
        )
    except Exception as e:
        logger.error(f"Unexpected error in host_detail: {str(e)}", exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
        return redirect(url_for('ilom.ilom_index'))
    finally:
        ssh.close()
        release_db_connection(conn, current_app.config['DB_POOL'])

@ilom_bp.route('/edit_alert/<hostname>/<alert_id>', methods=['GET', 'POST'])
@login_required
def edit_alert(hostname, alert_id):
    logger.info(f"Incoming request: method={request.method}, path=/ilom/edit_alert/{hostname}/{alert_id}, user={current_user.id}")
    if not current_user.is_superuser:
        flash("Superuser access required to edit alerts.", "error")
        logger.warning(f"Non-superuser {current_user.id} attempted to edit alert {alert_id}")
        return redirect(url_for('ilom.host_detail', hostname=hostname))

    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    host, alerts, user_data = fetch_host_details(cursor, hostname)
    if not host:
        flash("Host not found", "error")
        logger.warning(f"Host {hostname} not found for user {current_user.id}")
        release_db_connection(conn, current_app.config['DB_POOL'])
        return redirect(url_for('ilom.ilom_index'))

    alert = None
    for a in alerts:
        if str(a[0]) == str(alert_id):
            alert = a
            break
    if not alert:
        flash(f"Alert ID {alert_id} not found for host {hostname}", "error")
        logger.warning(f"Alert ID {alert_id} not found for host {hostname} by {current_user.id}")
        release_db_connection(conn, current_app.config['DB_POOL'])
        return redirect(url_for('ilom.host_detail', hostname=hostname))

    hostname, ilom_ip = host
    ssh_key_path = os.environ.get('ILOM_SSH_KEY_PATH', '/home/maatest/.ssh/id_rsa')
    ilom_username = os.environ.get('ILOM_USERNAME', 'root')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    slot_status = {'alerts_full': False, 'users_full': False}

    flashed_ssh_errors = session.get('flashed_ssh_errors', {})
    ssh_error_key = f"ssh_error_{hostname}"

    try:
        private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        logger.info(f"Connecting to {ilom_ip} with username {ilom_username} using SSH key at {ssh_key_path}")
        ssh.connect(
            hostname=ilom_ip,
            username=ilom_username,
            pkey=private_key,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10
        )
        ssh.get_transport().set_keepalive(10)
        time.sleep(1)
        slot_status = get_slot_counts(ssh, hostname)

        if request.method == 'POST' and 'update_alert' in request.form:
            alert_id_form = int(request.form.get('alert_id', 0))
            if alert_id_form < 1 or alert_id_form > 15:
                flash(f"Invalid alert ID {alert_id_form}. Must be between 1 and 15.", "error")
                logger.warning(f"Invalid alert ID {alert_id_form} for update by {current_user.id}")
            elif alert_id_form != int(alert_id):
                flash(f"Alert ID mismatch: {alert_id_form} does not match {alert_id}", "error")
                logger.warning(f"Alert ID mismatch: {alert_id_form} vs {alert_id} by {current_user.id}")
            elif alert_id_form == 1 and not current_user.is_superuser:
                flash("Cannot update alert ID 1", "error")
                logger.warning(f"Non-superuser {current_user.id} attempted to update protected alert ID 1")
            else:
                version = request.form.get('version', 'v2c')
                destination_ip = request.form.get('destination_ip', '0.0.0.0')
                port = int(request.form.get('port', 0))
                community_string = request.form.get('community_string', 'public') if version == 'v2c' else None
                username = request.form.get('username', None) if version == 'v3' else None
                level = request.form.get('status', 'disable')

                try:
                    if version == 'v2c':
                        set_alert_v2c(ssh, alert_id_form, destination_ip, port, community_string, level)
                    else:
                        set_alert_v3(ssh, alert_id_form, destination_ip, port, username, level)

                    cursor.execute(
                        "UPDATE MAAMD.snmp_subscriptions SET version = :1, destination_ip = :2, community_string = :3, username = :4, status = :5, port = :6 WHERE LOWER(ILOM_HOSTNAME) = LOWER(:7) AND alert_id = :8",
                        (version, destination_ip, community_string, username, level, port, hostname, alert_id_form)
                    )
                    conn.commit()
                    flash(f"Alert ID {alert_id_form} updated successfully on ILOM and database", "success")
                    logger.info(f"Alert ID {alert_id_form} updated for hostname {hostname} by {current_user.id} with level={level}")
                    return redirect(url_for('ilom.host_detail', hostname=hostname))
                except Exception as e:
                    logger.error(f"Failed to update alert ID {alert_id_form}: {str(e)}", exc_info=True)
                    flash(f"Failed to update alert: {str(e)}", "error")
                    if 'superuser' in str(e).lower():
                        flash("Superuser access issue detected.", "error")

        logger.debug(f"Rendering ilom/edit_alert.html with alert={alert}")
        try:
            return render_template(
                'ilom/edit_alert.html',
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
                'ilom/edit_alert.html',
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
            flash(f"SSH connection failed: {str(e)}", "error")
            session['flashed_ssh_errors'] = flashed_ssh_errors
            session['flashed_ssh_errors'][ssh_error_key] = True
        logger.error(f"SSH connection failed for {ilom_ip} by {current_user.id}: {str(e)}")
        return redirect(url_for('ilom.host_detail', hostname=hostname))
    except Exception as e:
        logger.error(f"Unexpected error in edit_alert: {str(e)}", exc_info=True)
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
        return redirect(url_for('ilom.ilom_index'))
    finally:
        ssh.close()
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
