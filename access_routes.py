# Filename: access_route.py
# Version: 2026-03-30 v1.0.6
# Changes: Minor version bump + comment added documenting the modern dark UI overhaul (template + JS now match User Management exactly). No functional change to backend logic.
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
import oracledb
from maa_libraries import get_db_pool_connection, release_db_connection, get_components, fetch_access_credentials, get_credential, encrypt_data, logger
from datetime import datetime
# Define the Blueprint
access_bp = Blueprint('access', __name__, template_folder='templates/access')
# Local helper function to add a credential
def add_credential_helper(cursor, component_type, component_name, username, password, key, created_by):
    encrypted_password = encrypt_data(password) if password else None
    encrypted_key = encrypt_data(key) if key else None
    created_date = datetime.now()
    try:
        query = """
            INSERT INTO MAAMD.ACCESS_CREDENTIALS
            (COMPONENT_TYPE, COMPONENT_NAME, USERNAME, ENCRYPTED_PASSWORD, ENCRYPTED_KEY, CREATED_BY, CREATED_DATE)
            VALUES (:1, :2, :3, :4, :5, :6, :7)
        """
        cursor.execute(query, (component_type, component_name, username, encrypted_password, encrypted_key, created_by, created_date))
        logger.info(f"Added credential for {component_type}:{component_name}:{username} by {created_by}")
    except oracledb.Error as e:
        logger.error(f"Error adding credential for {component_type}:{component_name}:{username}: {e}")
        raise
@access_bp.route('/', methods=['GET'])
@login_required
def access():
    logger.info(f"Incoming request: method=GET, path=/access, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        # Get filter parameters from GET request
        component_type = request.args.get('component_type', '').strip()
        component_name = request.args.get('component_name', '').strip()
        username = request.args.get('username', '').strip()
        # Build the query with filters
        query = """
            SELECT COMPONENT_TYPE, COMPONENT_NAME, USERNAME
            FROM MAAMD.ACCESS_CREDENTIALS
            WHERE 1=1
        """
        params = []
        if component_type:
            query += " AND LOWER(COMPONENT_TYPE) LIKE LOWER(:1)"
            params.append(f"%{component_type}%")
        if component_name:
            query += " AND LOWER(COMPONENT_NAME) LIKE LOWER(:2)"
            params.append(f"%{component_name}%")
        if username:
            query += " AND LOWER(USERNAME) LIKE LOWER(:3)"
            params.append(f"%{username}%")
        query += " ORDER BY COMPONENT_TYPE, COMPONENT_NAME, USERNAME"
        cursor.execute(query, params)
        credentials = cursor.fetchall()
        components = get_components(cursor)
        logger.debug(f"Fetched {len(credentials)} credentials and {len(components)} components")
        # Pass filters back to template for input values
        filters = {
            'component_type': component_type,
            'component_name': component_name,
            'username': username
        }
        try:
            return render_template(
                'access/index.html',
                credentials=credentials,
                components=components,
                filters=filters,
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
        except Exception as e:
            logger.error(f"Template rendering error in access: {str(e)}", exc_info=True)
            flash(f"Template rendering error: {str(e)}", "error")
            if 'superuser' in str(e).lower():
                flash("Superuser template issue detected.", "error")
            return render_template(
                'access/index.html',
                credentials=[],
                components=[],
                filters={},
                logo_base64=current_app.ORACLE_LOGO_BASE64,
                oracle_red=current_app.ORACLE_RED,
                username=current_user.id
            )
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
@access_bp.route('/get_credential', methods=['POST'])
@login_required
def get_credential_route():
    logger.info(f"Incoming request: method=POST, path=/access/get_credential, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        data = request.json
        component_type = data.get('component_type')
        component_name = data.get('component_name')
        username = data.get('username')
        credential_type = data.get('credential_type', 'password')
        logger.debug(f"Received get_credential request: component_type='{component_type}', component_name='{component_name}', username='{username}', credential_type='{credential_type}'")
        if not all([component_type, component_name, username]):
            logger.warning("Missing required parameters in get_credential request")
            return jsonify({'error': 'Missing required parameters'}), 400
        credential = get_credential(cursor, component_type, component_name, username, credential_type)
        if credential:
            return jsonify({'credential': credential})
        else:
            return jsonify({'error': f'No {credential_type} found for {component_type}:{component_name}:{username}'}), 200
    except oracledb.Error as e:
        logger.error(f"Database error retrieving {credential_type} for {component_type}:{component_name}:{username}: {e}")
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in get_credential_route: {str(e)}", exc_info=True)
        return jsonify({'error': 'Unexpected error'}), 500
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
@access_bp.route('/add_credential', methods=['POST'])
@login_required
def add_credential_route():
    logger.info(f"Incoming request: method=POST, path=/access/add_credential, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        component_type = request.form.get('component_type')
        component_name = request.form.get('component_name')
        username = request.form.get('username')
        password = request.form.get('password')
        key = request.form.get('key')
        if not all([component_type, component_name, username]):
            flash('Missing required fields', 'error')
            return redirect(url_for('access.access'))
        add_credential_helper(cursor, component_type, component_name, username, password, key, current_user.id)
        conn.commit()
        flash('Credential added successfully!', 'success')
    except oracledb.Error as e:
        logger.error(f"Error adding credential: {e}")
        conn.rollback()
        flash('Error adding credential', 'error')
    except Exception as e:
        logger.error(f"Unexpected error in add_credential_route: {str(e)}", exc_info=True)
        conn.rollback()
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
    return redirect(url_for('access.access'))
@access_bp.route('/update_credential', methods=['POST'])
@login_required
def update_credential():
    logger.info(f"Incoming request: method=POST, path=/access/update_credential, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        component_type = request.form.get('component_type')
        component_name = request.form.get('component_name')
        username = request.form.get('username')
        password = request.form.get('password')
        key = request.form.get('key')
        logger.debug(f"Received update_credential request: component_type='{component_type}', component_name='{component_name}', username='{username}'")
        if not all([component_type, component_name, username]):
            logger.warning("Missing required parameters in update_credential request")
            flash('Missing required fields', 'error')
            return redirect(url_for('access.access'))
        params = {}
        query_parts = []
        if password:
            params['encrypted_password'] = encrypt_data(password)
            query_parts.append("ENCRYPTED_PASSWORD = :encrypted_password")
        if key:
            params['encrypted_key'] = encrypt_data(key)
            query_parts.append("ENCRYPTED_KEY = :encrypted_key")
        else:
            params['encrypted_key'] = None
            query_parts.append("ENCRYPTED_KEY = :encrypted_key")
        if not query_parts:
            flash('No changes to update', 'info')
            return redirect(url_for('access.access'))
        params['last_updated_by'] = current_user.id
        params['component_type'] = component_type
        params['component_name'] = component_name
        params['username'] = username
        query = f"""
            UPDATE MAAMD.ACCESS_CREDENTIALS
            SET {', '.join(query_parts)},
                LAST_UPDATED_BY = :last_updated_by,
                LAST_UPDATED_DATE = SYSDATE
            WHERE LOWER(COMPONENT_TYPE) = LOWER(:component_type)
            AND LOWER(COMPONENT_NAME) = LOWER(:component_name)
            AND LOWER(USERNAME) = LOWER(:username)
        """
        cursor.execute(query, params)
        conn.commit()
        logger.info(f"Updated credential: {component_type}:{component_name}:{username} by {current_user.id}")
        flash('Credential updated successfully!', 'success')
    except oracledb.Error as e:
        logger.error(f"Error updating credential: {e}")
        conn.rollback()
        flash('Error updating credential', 'error')
    except Exception as e:
        logger.error(f"Unexpected error in update_credential: {str(e)}", exc_info=True)
        conn.rollback()
        flash(f"Unexpected error: {str(e)}", "error")
        if 'superuser' in str(e).lower():
            flash("Superuser access issue detected.", "error")
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
    return redirect(url_for('access.access'))
@access_bp.route('/delete_credential', methods=['POST'])
@login_required
def delete_credential():
    logger.info(f"Incoming request: method=POST, path=/access/delete_credential, user={current_user.id}")
    conn = get_db_pool_connection(current_app.config['DB_POOL'])
    cursor = conn.cursor()
    try:
        data = request.json
        credentials = data.get('credentials', [])
        if not credentials:
            logger.warning("No credentials selected for deletion")
            return jsonify({'error': 'No credentials selected'}), 400
        for cred in credentials:
            component_type = cred.get('component_type')
            component_name = cred.get('component_name')
            username = cred.get('username')
            logger.debug(f"Deleting credential: {component_type}:{component_name}:{username}")
            cursor.execute("""
                DELETE FROM MAAMD.ACCESS_CREDENTIALS
                WHERE LOWER(COMPONENT_TYPE) = LOWER(:1)
                AND LOWER(COMPONENT_NAME) = LOWER(:2)
                AND LOWER(USERNAME) = LOWER(:3)
            """, (component_type, component_name, username))
            logger.info(f"Deleted credential: {component_type}:{component_name}:{username} by {current_user.id}")
        conn.commit()
        return jsonify({'success': True})
    except oracledb.Error as e:
        logger.error(f"Error deleting credentials: {e}")
        conn.rollback()
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in delete_credential: {str(e)}", exc_info=True)
        if 'superuser' in str(e).lower():
            logger.error("Superuser access issue detected in delete_credential")
            return jsonify({'error': 'Superuser access issue'}), 403
        return jsonify({'error': 'Unexpected error'}), 500
    finally:
        cursor.close()
        release_db_connection(conn, current_app.config['DB_POOL'])
