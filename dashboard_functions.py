# Version: 2026-03-30 v1.10
# Changes: Added the 6 performance KPI keys (db_cpu_percent, buffer_cache_hit, library_cache_hit, aas, physical_reads_sec, top_wait_event) to get_oracle_db_state() with realistic values so the Oracle Database tile populates correctly. All other functions unchanged.
import logging

logger = logging.getLogger('MAA_Dashboard')

def get_kpi_stats(db_pool):
    stats = {'total_systems': 293, 'active_users': 5, 'active_issues': 3, 'healthy_pct': 92, 'agents_online': 87, 'iloms_monitored': 124, 'active_jobs': 14}
    try:
        conn = db_pool.acquire()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM MAAMD.SYSTEM_ALLOCATIONS")
        stats['total_systems'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM MAAMD.APP_USERS WHERE IS_ACTIVE = 'Y'")
        stats['active_users'] = cursor.fetchone()[0]
        cursor.close()
        db_pool.release(conn)
    except Exception as e:
        logger.error(f"KPI error: {e}")
    return stats

def get_component_health():
    return [
        {"name": "Access Credentials", "icon": "🔑", "status": "Healthy", "color": "#10b981", "issues": 0, "last_check": "just now", "link": "/access/"},
        {"name": "System Allocations", "icon": "📦", "status": "Warning", "color": "#f59e0b", "issues": 2, "last_check": "3m ago", "link": "/allocations"},
        {"name": "Agent Management", "icon": "🤖", "status": "Healthy", "color": "#10b981", "issues": 0, "last_check": "1m ago", "link": "/agent/"},
        {"name": "ASRM", "icon": "📡", "status": "Healthy", "color": "#10b981", "issues": 0, "last_check": "5m ago", "link": "/asrm/"},
        {"name": "ILOM", "icon": "🖥️", "status": "Healthy", "color": "#10b981", "issues": 1, "last_check": "8m ago", "link": "/ilom/"},
        {"name": "Switches", "icon": "🔀", "status": "Healthy", "color": "#10b981", "issues": 0, "last_check": "12m ago", "link": "/switches/"},
        {"name": "Environment Setup", "icon": "⚙️", "status": "Healthy", "color": "#10b981", "issues": 0, "last_check": "15m ago", "link": "/setup/setup_environment"},
        {"name": "Jobs", "icon": "📋", "status": "Healthy", "color": "#10b981", "issues": 0, "last_check": "2m ago", "link": "/jobs/scheduled_jobs"},
        {"name": "Fleet Health", "icon": "📈", "status": "Monitor", "color": "#6366f1", "issues": 0, "last_check": "live", "link": "/fleet-health/"},
    ]

def get_recent_issues():
    return [
        {"component": "ILOM", "description": "2 hosts unreachable (scaqaa04cel12vm03)", "severity": "Warning", "severity_color": "#f59e0b", "time": "14 min ago"},
        {"component": "Allocations", "description": "End date approaching for 3 systems", "severity": "Info", "severity_color": "#3b82f6", "time": "37 min ago"},
        {"component": "Agent", "description": "Parser status query error on 4 agents", "severity": "Warning", "severity_color": "#f59e0b", "time": "2h ago"},
    ]

def get_recent_jobs():
    return [
        {"name": "get_allocation_data.py", "status": "Success", "time": "just now", "color": "#10b981"},
        {"name": "collect_ilom_data.py", "status": "Warning", "time": "11 min ago", "color": "#f59e0b"},
        {"name": "refresh_agent_status.py", "status": "Success", "time": "47 min ago", "color": "#10b981"},
    ]

def get_system_performance():
    return {"cpu": 67, "memory": 54, "disk": 81, "network": 23}

def get_cpu_details():
    return [
        {"core": "CPU0", "user": 45, "system": 12, "idle": 43},
        {"core": "CPU1", "user": 32, "system": 18, "idle": 50},
        {"core": "CPU2", "user": 28, "system": 15, "idle": 57},
        {"core": "CPU3", "user": 52, "system": 22, "idle": 26},
        {"core": "CPU4", "user": 41, "system": 19, "idle": 40},
        {"core": "CPU5", "user": 29, "system": 14, "idle": 57},
        {"core": "CPU6", "user": 48, "system": 23, "idle": 29},
        {"core": "CPU7", "user": 35, "system": 17, "idle": 48},
        {"core": "CPU8", "user": 39, "system": 21, "idle": 40},
        {"core": "CPU9", "user": 33, "system": 16, "idle": 51},
        {"core": "CPU10", "user": 44, "system": 18, "idle": 38},
        {"core": "CPU11", "user": 37, "system": 20, "idle": 43},
    ]

def get_disk_details():
    return [
        {"device": "sda", "util": 81, "await": 12.4, "r_s": 45, "w_s": 132},
        {"device": "nvme0n1", "util": 34, "await": 0.8, "r_s": 320, "w_s": 890},
        {"device": "sdb", "util": 92, "await": 28.7, "r_s": 12, "w_s": 67},
        {"device": "sdc", "util": 27, "await": 5.2, "r_s": 89, "w_s": 245},
        {"device": "dev252-0", "util": 10, "await": 2.3, "r_s": 34, "w_s": 67},
        {"device": "dev252-4", "util": 21, "await": 1.4, "r_s": 71, "w_s": 115},
        {"device": "dev8-16", "util": 55, "await": 3.3, "r_s": 179, "w_s": 164},
        {"device": "dev252-1", "util": 3, "await": 4.0, "r_s": 7, "w_s": 14},
    ]

def get_memory_details():
    return {
        "total": 95901,
        "used": 65157,
        "free": 1101,
        "shared": 306,
        "buff_cache": 29643,
        "available": 28945,
        "swap_used": 12287,
        "swap_total": 12287
    }

def get_oracle_db_state():
    return {
        "service_name": "maapdb_devel.us.oracle.com",
        "version": "19.21.0.0.0",
        "role": "PRIMARY",
        "status": "OPEN",
        "active_sessions": 12,
        "pool_current": 18,
        "pool_max": 30,
        "uptime_days": 47,
        "uptime_hours": 3,
        "asm_status": "ONLINE",
        "last_startup": "2026-02-11 09:15",
        "db_cpu_percent": 18,
        "buffer_cache_hit": 98,
        "library_cache_hit": 99,
        "aas": 2.3,
        "physical_reads_sec": 45,
        "top_wait_event": "db file sequential read"
    }

def get_chart_data():
    return {
        "health_labels": ["Healthy", "Warning", "Critical"],
        "health_values": [6, 1, 1],
        "job_labels": ["Success", "Failed", "Running"],
        "job_values": [18, 3, 4]
    }
