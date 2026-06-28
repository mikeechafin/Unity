#!/usr/bin/env python3
# Version: 2026-06-02 v2.68
# Changes: Added missing app.register_blueprint(migration_bp, url_prefix='/migration') + updated logger line. This was the direct cause of the persistent 404 on /migration/results.

import logging
import sys
import re
import oracledb
import base64
from PIL import Image
import os
import json
import argparse
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, current_app, make_response, has_request_context
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import traceback
import uuid
import fcntl
import psutil
import atexit
from datetime import timezone
from flask_socketio import SocketIO, emit, join_room, leave_room
from setup_routes import execution_logs, log_lock, get_component_type, run_script_background, run_group_patch_background
from environment_setup_functions import pre_patch_shutdown_dbserver, execute_function, copy_latest_patches, get_functions_for_type
from collections import defaultdict
from fault_routes import fault_bp
from werkzeug.exceptions import BadRequest
from celery import Celery
import hashlib
from maa_email import send_welcome_email
from maa_scheduler import start_scheduler
from maa_scheduler import scheduler, run_script
from contextlib import contextmanager
from maa_db_pool import init_db_pool, get_db_pool_connection, release_db_pool_connection, db_pool_context
from topology_routes import topology_bp
from oedacli_routes import oedacli_bp
from rti_routes import rti_bp
from migration_routes import migration_bp

celery = Celery('maa', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

INITIALIZATION_LOCK = threading.Lock()
MODULE_INITIALIZED = False

logger = logging.getLogger('MAA_Unified')
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s,%(msecs)03d %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)

class SocketIOHandler(logging.Handler):
    def __init__(self, sid, task_id):
        super().__init__()
        self.sid = sid
        self.task_id = task_id
    def emit(self, record):
        try:
            log_line = self.format(record)
            current_app.socketio.emit('message', {
                'task_id': self.task_id,
                'line': f"[{record.levelname}] {log_line}",
                'status': 'running'
            }, room=self.sid)
        except Exception:
            self.handleError(record)

app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app, async_mode='threading')
app.socketio = socketio
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'temporary-secure-key-1234567890')
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['TEMPLATES_AUTO_RELOAD'] = False

@socketio.on('join')
def handle_join(data):
    room = data.get('room') if isinstance(data, dict) else data
    if room:
        join_room(room)
        logger.info(f"[SocketIO] Client joined room: {room}")

@socketio.on('join_fault_room')
def handle_join_fault(room):
    join_room(room)

@socketio.on('leave_fault_room')
def handle_leave(room):
    leave_room(room)

@socketio.on('subscribe_rti')
def handle_subscribe_rti(data):
    """Client subscribes to specific RTI hosts for filtered real-time updates.
    Expects data = { "servers": ["HOST1", "HOST2", ...] }
    """
    try:
        servers = []
        if isinstance(data, dict):
            servers = data.get('servers', []) or []
        elif isinstance(data, list):
            servers = data
        for srv in servers:
            if srv:
                room = f"rti_{srv.upper()}"
                join_room(room)
                logger.info(f"[SocketIO][RTI] Client joined room: {room}")
        emit('rti_subscribed', {'servers': [s.upper() for s in servers if s], 'status': 'ok'})
    except Exception as e:
        logger.warning(f"[SocketIO][RTI] subscribe_rti error: {e}")

with log_lock:
    execution_logs.clear()
logger.info("Cleared stale execution_logs on startup")

app.logger.handlers = []
app.logger.propagate = False
app.logger.addHandler(console_handler)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, role='operator'):
        self.id = id
        self.role = role
        self.is_superuser = id == 'maamd'
    def has_role(self, required_role):
        if self.is_superuser:
            return True
        hierarchy = {'admin': 3, 'operator': 2, 'viewer': 1}
        return hierarchy.get(self.role, 0) >= hierarchy.get(required_role, 0)

@login_manager.user_loader
def load_user(user_id):
    logger.debug("Loading user with ID: %s", user_id)
    try:
        with db_pool_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ROLE FROM MAAMD.APP_USERS WHERE USERNAME = :1", (user_id,))
            row = cursor.fetchone()
            role = row[0] if row else 'operator'
            logger.debug(f"User {user_id} loaded with role {role}")
            return User(user_id, role)
    except Exception as e:
        logger.error("Error loading user %s: %s", user_id, str(e))
        return User(user_id)

def audit_action(username, action, details=None, status='SUCCESS'):
    try:
        with db_pool_context() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO MAAMD.AUDIT_LOG (USERNAME, ACTION, DETAILS, IP_ADDRESS, STATUS)
                VALUES (:1, :2, :3, :4, :5)
            """, (username, action, json.dumps(details or {}), request.remote_addr if has_request_context() else None, status))
            conn.commit()
    except Exception as e:
        logger.warning(f"Audit failed: {e}")

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_role(required_role):
                flash("Insufficient permissions for this action", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.before_request
def before_request_audit():
    if current_user.is_authenticated and request.endpoint and not request.endpoint.startswith('static'):
        audit_action(current_user.id, f"ACCESS_{request.endpoint.upper()}", {'method': request.method})

def get_pool_stats():
    try:
        p = app.config.get('DB_POOL')
        if p:
            return f"open={p.opened}, busy={p.busy}, idle={p.idle}"
        return "unknown"
    except:
        return "error"

def get_db_connection(username, password, dsn):
    try:
        if '@' in username:
            quoted_user = f'"{username}"'
        else:
            quoted_user = username
        conn = oracledb.connect(user=quoted_user, password=password, dsn=dsn)
        return conn
    except oracledb.Error as e:
        logger.error("Failed to establish database connection for user %s: %s", username, str(e))
        raise

def initialize_app():
    global MODULE_INITIALIZED
    with INITIALIZATION_LOCK:
        if MODULE_INITIALIZED:
            return
        logger.info("Starting MAA Unified App version 2.68")
        logger.info("System clock: %s, UTC clock: %s", datetime.now(), datetime.now(timezone.utc))

        oracle_logo_path = os.path.join(app.root_path, 'static', 'oracle_logo.png')
        oracle_logo_trimmed_path = os.path.join(app.root_path, 'static', 'oracle_logo_trimmed.png')
        if os.path.exists(oracle_logo_path):
            try:
                with Image.open(oracle_logo_path) as img:
                    if img.mode != 'RGBA':
                        img = img.convert('RGBA')
                    alpha = img.split()[3]
                    alpha_threshold = alpha.point(lambda p: 255 if p > 200 else 0)
                    bbox = alpha_threshold.getbbox()
                    if bbox:
                        img = img.crop(bbox)
                        original_width, original_height = img.size
                        aspect_ratio = original_width / original_height
                        new_height = 78
                        new_width = int(new_height * aspect_ratio)
                        img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                        img.save(oracle_logo_trimmed_path, format='PNG')
                        logger.info("Trimmed and resized oracle_logo.png to %dx%d", new_width, new_height)
            except Exception as e:
                logger.error("Failed to trim logo: %s", str(e))

        app.config['DB_CONFIG'] = {
            'dsn': "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))",
            'superuser': 'maamd'
        }
        try:
            app.config['DB_POOL'] = init_db_pool()
            logger.info("Database connection pool created from central maa_db_pool (v1.0.2)")
        except Exception as e:
            logger.error("Failed to create database connection pool: %s", str(e))
            sys.exit(1)

        app.ORACLE_LOGO_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYSURBVDhPY0CC/1GBgYGBoYGBgYGBgQEALQ4DXa4bBEsAAAAASUVORK5CYII="
        app.ORACLE_RED = '#FF0000'
        MODULE_INITIALIZED = True

if 'maa_unified_app' not in sys.modules:
    sys.modules['maa_unified_app'] = sys.modules[__name__]

initialize_app()

LOCK_FILE = "/tmp/maa_unified_app_new.lock"
PID_FILE = "/tmp/maa_unified_app_new.pid"
INSTANCE_LOCKED = False

def acquire_instance_lock():
    global INSTANCE_LOCKED
    current_pid = os.getpid()
    if INSTANCE_LOCKED:
        return None
    try:
        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE) as f:
                    old_pid = int(f.read().strip())
                if old_pid != current_pid and psutil.pid_exists(old_pid):
                    logger.error("Another MAA Unified instance is running (PID %s). Exiting.", old_pid)
                    sys.exit(1)
            except (ValueError, OSError):
                pass
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with open(LOCK_FILE, 'w') as f:
            f.write(str(current_pid))
        with open(PID_FILE, 'w') as f:
            f.write(str(current_pid))
        INSTANCE_LOCKED = True
        return lock_fd
    except Exception:
        sys.exit(1)

@app.route('/')
@login_required
def index():
    from dashboard_routes import dashboard_index
    return dashboard_index()

@app.route('/api/token', methods=['POST'])
@login_required
def generate_token():
    try:
        from maa_libraries import encrypt_data
        token_data = f"{current_user.id}|||{datetime.now(timezone.utc).isoformat()}|||720h"
        encrypted = encrypt_data(token_data)
        token_hash = hashlib.sha256(encrypted).hexdigest()
        with db_pool_context() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO MAAMD.API_TOKENS (USERNAME, TOKEN_HASH, TOKEN_NAME, EXPIRY_DATE)
                VALUES (:1, :2, :3, SYSDATE + 30)
            """, (current_user.id, token_hash, request.form.get('name', 'Default Token')))
            conn.commit()
        audit_action(current_user.id, 'TOKEN_GENERATED', {'name': request.form.get('name')})
        return jsonify({'token': base64.b64encode(encrypted).decode(), 'type': 'Bearer', 'expires': '30 days'})
    except Exception as e:
        audit_action(current_user.id, 'TOKEN_GENERATED', {'error': str(e)}, 'FAILED')
        return jsonify({'error': str(e)}), 500

@app.route('/login/token', methods=['GET'])
def login_with_token():
    token = request.args.get('token')
    if not token:
        flash("Missing token.", "error")
        return redirect(url_for('login'))
    try:
        from maa_libraries import decrypt_data
        decrypted = decrypt_data(base64.b64decode(token.encode()))
        parts = decrypted.split("|||") if "|||" in decrypted else decrypted.split(":")
        username, timestamp_str, duration = parts
        timestamp = datetime.fromisoformat(timestamp_str)
        if (datetime.now(timezone.utc) - timestamp) > timedelta(days=30):
            flash("Token has expired.", "error")
            return redirect(url_for('login'))
        user = User(username)
        login_user(user)
        session['db_user'] = username
        session.permanent = True
        with db_pool_context() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE MAAMD.APP_USERS SET LAST_LOGIN = SYSDATE WHERE USERNAME = :1", (username,))
            conn.commit()
        audit_action(username, 'LOGIN_TOKEN', {'method': 'token'})
        flash(f"Logged in successfully with token as {username}!", "success")
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"Invalid or expired token: {str(e)}", "error")
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            conn = get_db_connection(username, password, app.config['DB_CONFIG']['dsn'])
            conn.close()
            with db_pool_context() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ROLE FROM MAAMD.APP_USERS WHERE USERNAME = :1", (username,))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO MAAMD.APP_USERS (USERNAME, ROLE, CREATED_BY) VALUES (:1, 'operator', 'SYSTEM')", (username,))
                conn.commit()
                cursor.execute("SELECT LAST_LOGIN FROM MAAMD.APP_USERS WHERE USERNAME = :1", (username,))
                last_login_row = cursor.fetchone()
                is_first_login = last_login_row is None or last_login_row[0] is None
                cursor.execute("UPDATE MAAMD.APP_USERS SET LAST_LOGIN = SYSDATE WHERE USERNAME = :1", (username,))
                conn.commit()
            user = User(username)
            login_user(user)
            session['db_user'] = username
            session.permanent = True
            audit_action(username, 'LOGIN', {'success': True, 'first_login': is_first_login})
            flash('Login successful! Use /api/token for passwordless access.', 'success')
            if is_first_login:
                flash('This is your first login. Please change your password now for security.', 'info')
                return redirect(url_for('change_password'))
            next_page = request.args.get('next', url_for('index'))
            return redirect(next_page)
        except oracledb.Error as e:
            flash(f"Login failed: {str(e)}", 'error')
            return redirect(url_for('login'))
    return render_template('login.html', logo_base64=app.ORACLE_LOGO_BASE64, oracle_red=app.ORACLE_RED)

@app.route('/logout')
@login_required
def logout():
    audit_action(current_user.id, 'LOGOUT')
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login', timestamp=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')))

@app.route('/favicon.ico')
def favicon():
    favicon_path = os.path.join(app.root_path, 'static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    return '', 204

@app.route('/confluence', methods=['GET'])
@login_required
def confluence():
    if 'confluence_flash_shown' not in session:
        flash("Please ensure you are on the Oracle network to access Confluence links.", "info")
        session['confluence_flash_shown'] = True
    return render_template('confluence.html', username=current_user.id, logo_base64=app.ORACLE_LOGO_BASE64, oracle_red=app.ORACLE_RED)

@app.route('/allocations', methods=['GET', 'POST'])
@login_required
def allocations():
    response = make_response()
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    try:
        if request.method == 'POST' and not current_user.has_role('admin'):
            flash("Only admins can modify allocations", "error")
            return redirect(url_for('allocations'))
        with db_pool_context() as conn:
            cursor = conn.cursor()
            if request.method == 'POST':
                action = request.form.get('action')
                system_name = request.form.get('system_name', '').strip()
                if action == 'add':
                    cursor.execute("""
                        INSERT INTO MAAMD.SYSTEM_ALLOCATIONS
                        (SYSTEM_NAME, CURRENT_ALLOCATION, END_DATE, OWNER_GROUP, NOTES, MANUAL_OVERRIDE, SOURCE)
                        VALUES (:1, :2, :3, :4, :5, 'Y', 'MANUAL')
                    """, (system_name, request.form.get('current_allocation'),
                          request.form.get('end_date'), request.form.get('owner_group', 'Unassigned'),
                          request.form.get('notes', '')))
                    conn.commit()
                    flash(f"Added {system_name} manually (protected from refresh)", "success")
                elif action == 'edit':
                    current_allocation = request.form.get('current_allocation')
                    end_date = request.form.get('end_date')
                    owner_group = request.form.get('owner_group')
                    notes = request.form.get('notes')
                    cursor.execute("""
                        UPDATE MAAMD.SYSTEM_ALLOCATIONS
                        SET CURRENT_ALLOCATION = :1,
                            END_DATE = :2,
                            OWNER_GROUP = :3,
                            NOTES = :4,
                            LAST_UPDATED = SYSDATE,
                            MANUAL_OVERRIDE = 'Y',
                            SOURCE = 'MANUAL'
                        WHERE SYSTEM_NAME = :5
                    """, (current_allocation, end_date, owner_group, notes, system_name))
                    conn.commit()
                    flash(f"SAVED {system_name}", "success")
                elif action == 'delete':
                    cursor.execute("DELETE FROM MAAMD.SYSTEM_ALLOCATIONS WHERE SYSTEM_NAME = :1", (system_name,))
                    conn.commit()
                    flash(f"Deleted {system_name}", "success")
                return redirect(url_for('allocations', t=int(time.time())))
            rack = request.args.get('rack', '')
            search = request.args.get('search', '').lower()
            query = """
                SELECT SYSTEM_NAME, ILOM_NAME, CURRENT_ALLOCATION, END_DATE, OWNER_GROUP, NOTES,
                       SOURCE, LAST_UPDATED,
                       CASE
                         WHEN END_DATE IS NULL THEN 'green'
                         WHEN END_DATE < SYSDATE + 30 THEN 'red'
                         WHEN END_DATE < SYSDATE + 90 THEN 'yellow'
                         ELSE 'green'
                       END as color
                FROM MAAMD.SYSTEM_ALLOCATIONS
                WHERE 1=1
            """
            params = {}
            if rack:
                query += " AND RACK_NAME = :rack"
                params['rack'] = rack
            if search:
                query += " AND (LOWER(SYSTEM_NAME) LIKE :s OR LOWER(OWNER_GROUP) LIKE :s OR LOWER(NOTES) LIKE :s)"
                params['s'] = f"%{search}%"
            query += " ORDER BY SYSTEM_NAME"
            cursor.execute(query, params)
            allocations_data = cursor.fetchall()
        with db_pool_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT RACK_NAME FROM MAAMD.SYSTEM_ALLOCATIONS WHERE RACK_NAME IS NOT NULL ORDER BY 1")
            racks = [r[0] for r in cursor.fetchall()]
        filters = {'rack': rack, 'search': search}
        response = make_response(render_template(
            'allocations.html',
            allocations_data=allocations_data,
            racks=racks,
            filters=filters,
            username=current_user.id,
            logo_base64=app.ORACLE_LOGO_BASE64,
            oracle_red=app.ORACLE_RED
        ))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        logger.error("Error in allocations: %s", str(e))
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/users', methods=['GET', 'POST'])
@role_required('admin')
def users():
    with db_pool_context() as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                username = request.form.get('username')
                password = request.form.get('password')
                role = request.form.get('role', 'operator')
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_regex, username):
                    flash("Username must be a valid email address", "error")
                elif not password:
                    flash("Password is required", "error")
                else:
                    try:
                        cursor.execute("SELECT COUNT(*) FROM ALL_USERS WHERE USERNAME = UPPER(:uname)", {'uname': username})
                        if cursor.fetchone()[0] > 0:
                            flash(f"Oracle user {username} already exists. Updating APP_USERS entry.", "warning")
                        else:
                            cursor.execute("""
                                BEGIN
                                    EXECUTE IMMEDIATE 'CREATE USER "' || :uname || '" IDENTIFIED BY "' || :pwd || '" ACCOUNT UNLOCK';
                                    EXECUTE IMMEDIATE 'GRANT CONNECT, CREATE SESSION TO "' || :uname || '"';
                                    EXECUTE IMMEDIATE 'GRANT SELECT ON MAAMD.APP_USERS TO "' || :uname || '"';
                                    EXECUTE IMMEDIATE 'GRANT SELECT ON MAAMD.AUDIT_LOG TO "' || :uname || '"';
                                    EXECUTE IMMEDIATE 'GRANT SELECT ON MAAMD.SYSTEM_ALLOCATIONS TO "' || :uname || '"';
                                    EXECUTE IMMEDIATE 'GRANT SELECT ON MAAMD.CERTIFICATION_PROJECTS TO "' || :uname || '"';
                                    EXECUTE IMMEDIATE 'GRANT SELECT ON MAAMD.API_TOKENS TO "' || :uname || '"';
                                END;
                            """, {'uname': username, 'pwd': password})
                            conn.commit()
                            logger.info(f"Created new Oracle user {username}")
                        cursor.execute("""
                            MERGE INTO MAAMD.APP_USERS t
                            USING (SELECT :uname AS USERNAME FROM DUAL) s
                            ON (t.USERNAME = s.USERNAME)
                            WHEN MATCHED THEN
                                UPDATE SET ROLE = :role, LAST_UPDATED_DATE = SYSDATE
                            WHEN NOT MATCHED THEN
                                INSERT (USERNAME, ROLE, CREATED_BY)
                                VALUES (:uname, :role, :created_by)
                        """, {'uname': username, 'role': role, 'created_by': current_user.id})
                        conn.commit()
                        send_welcome_email(username, username)
                        audit_action(current_user.id, 'USER_CREATED', {'username': username, 'role': role})
                        flash(f"User {username} is now active!", "success")
                    except oracledb.Error as e:
                        flash(f"Failed to create Oracle user: {str(e)}", "error")
            elif action == 'edit':
                username = request.form.get('username')
                role = request.form.get('role')
                is_active = request.form.get('is_active', 'Y')
                cursor.execute("""
                    UPDATE MAAMD.APP_USERS
                    SET ROLE = :1, IS_ACTIVE = :2, LAST_UPDATED_DATE = SYSDATE
                    WHERE USERNAME = :3
                """, (role, is_active, username))
                conn.commit()
                audit_action(current_user.id, 'USER_UPDATED', {'username': username, 'role': role, 'active': is_active})
                flash(f"User {username} updated successfully", "success")
            elif action == 'delete':
                username = request.form.get('username')
                if username == 'maamd':
                    flash("Cannot delete the maamd superuser", "error")
                else:
                    try:
                        cursor.execute("""
                            BEGIN
                                EXECUTE IMMEDIATE 'DROP USER "' || :uname || '" CASCADE';
                            END;
                        """, {'uname': username})
                        conn.commit()
                        cursor.execute("DELETE FROM MAAMD.APP_USERS WHERE USERNAME = :1", (username,))
                        conn.commit()
                        audit_action(current_user.id, 'USER_DELETED', {'username': username})
                        flash(f"User {username} deleted", "success")
                    except oracledb.Error as e:
                        flash(f"Failed to delete user: {str(e)}", "error")
            elif action == 'reset_password':
                username = request.form.get('username')
                new_password = request.form.get('new_password')
                if username == 'maamd':
                    flash("Cannot reset maamd password from UI", "error")
                elif not new_password:
                    flash("New password is required", "error")
                else:
                    try:
                        cursor.execute("""
                            BEGIN
                                EXECUTE IMMEDIATE 'ALTER USER "' || :uname || '" IDENTIFIED BY "' || :pwd || '" ACCOUNT UNLOCK';
                            END;
                        """, {'uname': username, 'pwd': new_password})
                        conn.commit()
                        audit_action(current_user.id, 'PASSWORD_RESET', {'username': username})
                        flash(f"Password for {username} reset", "success")
                    except oracledb.Error as e:
                        flash(f"Failed to reset password: {str(e)}", "error")
            elif action == 'token':
                username = request.form.get('username')
                from maa_libraries import encrypt_data
                token_data = f"{username}|||{datetime.now(timezone.utc).isoformat()}|||720h"
                encrypted = encrypt_data(token_data)
                token_hash = hashlib.sha256(encrypted).hexdigest()
                cursor.execute("""
                    INSERT INTO MAAMD.API_TOKENS (USERNAME, TOKEN_HASH, TOKEN_NAME, EXPIRY_DATE)
                    VALUES (:1, :2, 'Admin Generated', SYSDATE + 30)
                """, (username, token_hash))
                conn.commit()
                audit_action(current_user.id, 'TOKEN_GENERATED_FOR_USER', {'for_user': username})
                flash(f"Token generated for {username}", "success")
        cursor.execute("""
            SELECT USERNAME, ROLE, IS_ACTIVE, CREATED_DATE, LAST_LOGIN, LAST_UPDATED_DATE
            FROM MAAMD.APP_USERS
            ORDER BY USERNAME
        """)
        users_data = cursor.fetchall()
    return render_template(
        'users.html',
        users_data=users_data,
        username=current_user.id,
        logo_base64=app.ORACLE_LOGO_BASE64,
        oracle_red=app.ORACLE_RED
    )

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return redirect(url_for('change_password'))
        try:
            conn = get_db_connection(current_user.id, old_password, app.config['DB_CONFIG']['dsn'])
            conn.close()
            with db_pool_context() as pool_conn:
                cursor = pool_conn.cursor()
                cursor.execute("""
                    BEGIN
                        EXECUTE IMMEDIATE 'ALTER USER "' || :uname || '" IDENTIFIED BY "' || :pwd || '"';
                    END;
                """, {'uname': current_user.id, 'pwd': new_password})
                cursor.execute("""
                    UPDATE MAAMD.APP_USERS
                    SET LAST_LOGIN = SYSDATE
                    WHERE USERNAME = :1
                """, (current_user.id,))
                pool_conn.commit()
            audit_action(current_user.id, 'PASSWORD_CHANGED')
            flash("Password changed successfully!", "success")
            return redirect(url_for('index'))
        except oracledb.Error as e:
            flash(f"Old password incorrect or change failed: {str(e)}", "error")
            return redirect(url_for('change_password'))
    return render_template('change_password.html', username=current_user.id, logo_base64=app.ORACLE_LOGO_BASE64, oracle_red=app.ORACLE_RED)

from access_routes import access_bp
from agent_routes import agent_bp
from asrm_routes import asrm_bp
from ilom_routes import ilom_bp
from switches_routes import switches_bp
from job_routes import job_bp
from setup_routes import setup_bp
from fault_routes import fault_bp
app.register_blueprint(access_bp, url_prefix='/access')
app.register_blueprint(agent_bp, url_prefix='/agent')
app.register_blueprint(asrm_bp, url_prefix='/asrm')
app.register_blueprint(ilom_bp, url_prefix='/ilom')
app.register_blueprint(switches_bp, url_prefix='/switches')
app.register_blueprint(job_bp, url_prefix='/jobs')
app.register_blueprint(setup_bp, url_prefix='/setup')
app.register_blueprint(fault_bp)
app.register_blueprint(topology_bp)
app.register_blueprint(oedacli_bp, url_prefix='/oedacli')
app.register_blueprint(rti_bp, url_prefix='/rti')
app.register_blueprint(migration_bp, url_prefix='/migration')
logger.info("Registered blueprints: access, agent, asrm, ilom, switches, jobs, setup, topology, oedacli, rti, migration")

if __name__ == '__main__':
    from logging import getLogger
    log = getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    parser = argparse.ArgumentParser(description='MAA Unified Application')
    parser.add_argument('--host', default='0.0.0.0', help='Host to run the Flask app on')
    parser.add_argument('--port', type=int, default=6003, help='Port to run the Flask app on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    try:
        ssl_context = ('server.crt', 'server.key')
        with app.app_context():
            start_scheduler()
        socketio.run(app, host=args.host, port=args.port, use_reloader=False, allow_unsafe_werkzeug=True, ssl_context=ssl_context)
    except Exception as e:
        logger.error("Failed to run Flask")
