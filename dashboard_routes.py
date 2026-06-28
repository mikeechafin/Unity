# Version: 2026-03-30 v1.09
# Changes: Pass oracle_db_state for the redesigned Database State tile (Oracle-specific critical metrics).
from flask import render_template, current_app
from flask_login import login_required, current_user
from dashboard_functions import get_kpi_stats, get_component_health, get_recent_issues, get_recent_jobs, get_system_performance, get_cpu_details, get_disk_details, get_memory_details, get_oracle_db_state, get_chart_data

@login_required
def dashboard_index():
    db_pool = current_app.config['DB_POOL']
    kpis = get_kpi_stats(db_pool)
    components = get_component_health()
    issues = get_recent_issues()
    jobs = get_recent_jobs()
    perf = get_system_performance()
    cpu_details = get_cpu_details()
    disk_details = get_disk_details()
    memory_details = get_memory_details()
    oracle_db_state = get_oracle_db_state()
    chart = get_chart_data()
    
    return render_template('index.html',
        kpis=kpis,
        components=components,
        issues=issues,
        recent_jobs=jobs,
        system_perf=perf,
        cpu_details=cpu_details,
        disk_details=disk_details,
        memory_details=memory_details,
        oracle_db_state=oracle_db_state,
        health_labels=chart["health_labels"],
        health_values=chart["health_values"],
        job_labels=chart["job_labels"],
        job_values=chart["job_values"],
        username=current_user.id,
        logo_base64=current_app.ORACLE_LOGO_BASE64,
        oracle_red=current_app.ORACLE_RED
    )
