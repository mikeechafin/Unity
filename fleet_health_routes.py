#!/usr/bin/env python3
from flask import Blueprint, render_template, jsonify, current_app
from flask_login import login_required, current_user
from fleet_health_functions import get_fleet_health_summary

fleet_health_bp = Blueprint('fleet_health', __name__, url_prefix='/fleet-health')


@fleet_health_bp.route('/')
@login_required
def dashboard():
    data = get_fleet_health_summary()
    return render_template(
        'fleet_health.html',
        data=data,
        username=current_user.id,
        logo_base64=current_app.ORACLE_LOGO_BASE64,
        oracle_red=current_app.ORACLE_RED,
    )


@fleet_health_bp.route('/api/summary')
@login_required
def api_summary():
    return jsonify(get_fleet_health_summary())