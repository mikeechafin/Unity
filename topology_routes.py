#!/usr/bin/env python3
# Version: 2026-04-03 v1.07
# Changes: Reverted link keys to 'port_a_id'/'port_b_id' (numeric) to exactly match your frontend JS expectation in topology.html:232. Kept NULL skip for safety. Ports keep numeric 'id'. Added extra debug on skipped links. This eliminates "port-undefined" error. Only this file modified.
from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from maa_db_pool import get_db_pool_connection, release_db_pool_connection

print("=== TOPOLOGY_ROUTES v1.07 LOADED SUCCESSFULLY ===")

topology_bp = Blueprint('topology', __name__, url_prefix='/')

@topology_bp.route('/topology')
@login_required
def topology():
    """Main Network Topology Explorer page."""
    return render_template('topology.html')

@topology_bp.route('/api/topology/snapshots')
@login_required
def api_topology_snapshots():
    """Return list of topology snapshots for dropdown."""
    conn = get_db_pool_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM topology_snapshots")
    count = cursor.fetchone()[0]
    print(f"[DEBUG SNAPSHOTS] topology_snapshots table has {count} rows")
    cursor.execute("""
        SELECT id, snapshot_ts, fabric_type, total_devices, total_links
        FROM topology_snapshots
        ORDER BY snapshot_ts DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    release_db_pool_connection(conn)
    data = []
    for row in rows:
        data.append({
            'id': row[0],
            'snapshot_ts': row[1].isoformat() if row[1] else None,
            'fabric_type': row[2],
            'total_devices': row[3],
            'total_links': row[4]
        })
    print(f"[DEBUG SNAPSHOTS] /api/topology/snapshots returning {len(data)} snapshots")
    return jsonify(data)

@topology_bp.route('/api/topology/snapshot/<int:snapshot_id>')
@login_required
def api_topology_snapshot(snapshot_id):
    """Return ports + discovered_links for Cytoscape - EXACT frontend-compatible format + NULL safety."""
    print(f"========== [DEBUG SNAPSHOT {snapshot_id}] ENTERED api_topology_snapshot ==========")
    try:
        conn = get_db_pool_connection()
        cursor = conn.cursor()

        # Debug counts
        cursor.execute("SELECT COUNT(*) FROM ports")
        ports_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM discovered_links WHERE is_active = 1")
        links_count = cursor.fetchone()[0]
        print(f"[DEBUG SNAPSHOT {snapshot_id}] TOTAL ports={ports_count}, active discovered_links={links_count}")

        # Ports - safe joins
        cursor.execute("""
            SELECT p.id, p.name, p.mac_address, p.port_type, p.speed, p.status,
                   COALESCE(s.hostname, e.hostname) as device_name,
                   COALESCE('switch', e.node_type) as device_type
            FROM ports p
            LEFT JOIN switch_info s ON p.name = s.hostname
            LEFT JOIN exa_servers e ON p.device_id = e.server_id
        """)
        ports = cursor.fetchall()
        print(f"[DEBUG SNAPSHOT {snapshot_id}] RAW PORTS fetched: {len(ports)} rows. First 3 raw: {ports[:3] if ports else 'NONE'}")

        # Active discovered_links - RAW dump
        cursor.execute("""
            SELECT dl.port_a_id, dl.port_b_id, dl.protocol, dl.speed, dl.is_active, dl.confidence
            FROM discovered_links dl
            WHERE dl.is_active = 1
        """)
        links = cursor.fetchall()
        print(f"[DEBUG SNAPSHOT {snapshot_id}] RAW LINKS fetched: {len(links)} rows. First 3 raw: {links[:3] if links else 'NONE'}")

        cursor.close()
        release_db_pool_connection(conn)

        # Build port_list - numeric ID (frontend adds "port-" prefix)
        port_list = []
        for p in ports:
            if p[0] is None:
                continue
            port_list.append({
                'id': p[0],
                'name': p[1],
                'mac_address': p[2],
                'port_type': p[3],
                'speed': p[4],
                'status': p[5],
                'device_name': p[6],
                'device_type': p[7]
            })
        print(f"[DEBUG SNAPSHOT {snapshot_id}] Built {len(port_list)} valid ports")

        # Build link_list - SKIP any NULL port IDs + use exact keys frontend expects
        link_list = []
        for l in links:
            if l[0] is None or l[1] is None:
                print(f"[DEBUG SNAPSHOT {snapshot_id}] SKIPPED link with NULL port: {l}")
                continue
            link_list.append({
                'port_a_id': l[0],
                'port_b_id': l[1],
                'protocol': l[2],
                'speed': l[3],
                'is_active': bool(l[4]),
                'confidence': l[5]
            })
        print(f"[DEBUG SNAPSHOT {snapshot_id}] Built {len(link_list)} valid links")

        print(f"[DEBUG SNAPSHOT {snapshot_id}] RETURNING {len(port_list)} ports + {len(link_list)} links to frontend")
        print(f"========== [DEBUG SNAPSHOT {snapshot_id}] END OF FUNCTION ==========")
        return jsonify({'ports': port_list, 'links': link_list})

    except Exception as e:
        print(f"[DEBUG SNAPSHOT {snapshot_id}] CRITICAL EXCEPTION: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
