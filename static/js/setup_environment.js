// Version: 2026-04-08 v1.08
// Changes: Removed the fake spinner tab for discover_dbmachine (caused duplicate tabs and stuck yellow tab). Live progress messages from the plugin now appear directly in the single real tab. HTML table still renders perfectly.
const socket = io();
let logs = {};
let activeTab = null;
let tabElements = {};
let tabStatuses = {};
let hasRunAnyFunction = false;
function resetLogPanel() {
    activeTab = null;
    const output = document.getElementById('log-output');
    if (output) {
        output.textContent = 'No active execution logs.\nRun a function to begin logging.';
    }
}
function restoreLogsFromStorage() {
    const savedLogs = localStorage.getItem('maa_execution_logs');
    if (savedLogs) {
        const data = JSON.parse(savedLogs);
        logs = data.logs || {};
        tabStatuses = data.tabStatuses || {};
        Object.keys(logs).forEach(taskId => {
            if (taskId.toLowerCase().includes('debug')) return;
            const label = taskId.split('_').slice(0, -1).join(' – ') || taskId;
            createTab(taskId, label);
            if (!activeTab) switchTab(taskId);
        });
    }
}
function saveLogsToStorage() {
    localStorage.setItem('maa_execution_logs', JSON.stringify({
        logs: logs,
        tabStatuses: tabStatuses
    }));
}
function createTab(taskId, label) {
    if (taskId.toLowerCase().includes('debug')) return;
    const tabs = document.getElementById('log-tabs');
    if (!tabs) return;
    const tab = document.createElement('div');
    tab.style.display = 'inline-flex';
    tab.style.alignItems = 'center';
    tab.style.background = '#ffd700';
    tab.style.padding = '5px 10px';
    tab.style.borderRadius = '4px';
    tab.style.marginRight = '5px';
    tab.style.cursor = 'pointer';
    tab.style.border = '1px solid #ccc';
    const labelSpan = document.createElement('span');
    labelSpan.textContent = label;
    labelSpan.style.marginRight = '8px';
    const closeBtn = document.createElement('span');
    closeBtn.textContent = '×';
    closeBtn.style.fontWeight = 'bold';
    closeBtn.style.fontSize = '18px';
    closeBtn.style.cursor = 'pointer';
    closeBtn.style.color = '#999';
    closeBtn.onmouseover = () => closeBtn.style.color = '#000';
    closeBtn.onmouseout = () => closeBtn.style.color = '#999';
    closeBtn.onclick = (e) => {
        e.stopPropagation();
        closeTab(taskId);
    };
    tab.appendChild(labelSpan);
    tab.appendChild(closeBtn);
    tab.onclick = (e) => {
        if (e.target !== closeBtn) switchTab(taskId);
    };
    tabs.appendChild(tab);
    tabElements[taskId] = tab;
    tabStatuses[taskId] = 'running';
    updateTabColor(taskId);
    document.getElementById('log-panel').style.display = 'block';
    saveLogsToStorage();
}
function updateTabColor(taskId) {
    const tab = tabElements[taskId];
    if (!tab) return;
    const status = tabStatuses[taskId];
    tab.style.background = status === 'running' ? '#ffd700' : status === 'success' ? '#4caf50' : '#f44336';
}
function switchTab(taskId) {
    if (!logs[taskId]) return;
    activeTab = taskId;
    const output = document.getElementById('log-output');
    if (output) {
        output.innerHTML = logs[taskId].join('<br>');
        output.scrollTop = output.scrollHeight;
    }
    Object.values(tabElements).forEach(btn => btn.querySelector('span').style.fontWeight = 'normal');
    if (tabElements[taskId]) {
        tabElements[taskId].querySelector('span').style.fontWeight = 'bold';
    }
    updateTabColor(taskId);
}
function closeTab(taskId) {
    if (!tabElements[taskId]) return;
    tabElements[taskId].remove();
    delete tabElements[taskId];
    delete logs[taskId];
    delete tabStatuses[taskId];
    saveLogsToStorage();
    if (activeTab === taskId) {
        const remaining = Object.keys(logs).filter(id => !id.toLowerCase().includes('debug'));
        if (remaining.length > 0) {
            switchTab(remaining[0]);
        } else {
            resetLogPanel();
        }
    }
}
function clearCompletedTabs() {
    const completed = Object.keys(tabStatuses).filter(taskId => tabStatuses[taskId] !== 'running');
    completed.forEach(taskId => closeTab(taskId));
    if (activeTab && !tabElements[activeTab]) {
        const remaining = Object.keys(logs).filter(id => !id.toLowerCase().includes('debug'));
        if (remaining.length > 0) {
            switchTab(remaining[0]);
        } else {
            resetLogPanel();
        }
    }
}
function toggleCheckboxes(name, checked, className) {
    document.querySelectorAll(`input[name="${name}"]`).forEach(cb => {
        if (!className || cb.closest('tr').classList.contains(className)) cb.checked = checked;
    });
}
document.addEventListener('change', function(e) {
    if (e.target.classList.contains('function-checkbox')) {
        const row = e.target.closest('tr');
        const paramCell = row.querySelector('.param-cell');
        if (paramCell) paramCell.style.display = e.target.checked ? 'table-cell' : 'none';
    }
});
function hideSwitchesFromWrongColumns() {
    document.querySelectorAll('.setup-column').forEach(column => {
        const header = column.querySelector('.section-header').textContent.trim();
        const isSwitchColumn = header.includes('Switch');
        const rows = column.querySelectorAll('tr');
        rows.forEach(row => {
            const hostnameCell = row.querySelector('.hostname-cell');
            if (hostnameCell) {
                const hostname = hostnameCell.textContent.trim().toLowerCase();
                if (!isSwitchColumn && (hostname.includes('sw-') || hostname.includes('switch'))) {
                    row.style.display = 'none';
                }
            }
        });
    });
}
let filterTimeout;
function liveFilter(value) {
    clearTimeout(filterTimeout);
    filterTimeout = setTimeout(() => {
        const term = value.toLowerCase().trim();
        document.querySelectorAll('.component-table tbody tr').forEach(row => {
            const hostnameCell = row.querySelector('.hostname-cell');
            if (hostnameCell) {
                const hostname = hostnameCell.textContent.toLowerCase();
                row.style.display = (term === '' || hostname.includes(term)) ? '' : 'none';
            }
        });
    }, 150);
}
document.addEventListener('DOMContentLoaded', function() {
    restoreLogsFromStorage();
    document.querySelectorAll('.param-cell').forEach(cell => cell.style.display = 'none');
    document.querySelectorAll('.function-checkbox:checked').forEach(cb => {
        const row = cb.closest('tr');
        const paramCell = row.querySelector('.param-cell');
        if (paramCell) paramCell.style.display = 'table-cell';
    });
    loadADE_Series();
    hideSwitchesFromWrongColumns();
    const infoIcons = document.querySelectorAll('.info-icon');
    infoIcons.forEach(icon => {
        icon.addEventListener('click', function(e) {
            e.stopPropagation();
            const existing = document.querySelector('.dynamic-tooltip');
            if (existing) existing.remove();
            const tooltip = document.createElement('div');
            tooltip.className = 'dynamic-tooltip';
            tooltip.textContent = icon.getAttribute('title');
            tooltip.style.position = 'absolute';
            tooltip.style.background = '#333';
            tooltip.style.color = 'white';
            tooltip.style.padding = '8px 12px';
            tooltip.style.borderRadius = '4px';
            tooltip.style.fontSize = '13px';
            tooltip.style.maxWidth = '300px';
            tooltip.style.zIndex = '10002';
            tooltip.style.boxShadow = '0 2px 8px rgba(0,0,0,0.3)';
            tooltip.style.pointerEvents = 'none';
            tooltip.style.whiteSpace = 'pre-wrap';
            document.body.appendChild(tooltip);
            const rect = icon.getBoundingClientRect();
            let top = rect.bottom + window.scrollY + 8;
            let left = rect.left + window.scrollX + (rect.width / 2) - (tooltip.offsetWidth / 2);
            if (top + tooltip.offsetHeight > window.innerHeight + window.scrollY) {
                top = rect.top + window.scrollY - tooltip.offsetHeight - 8;
            }
            if (left < 10) left = 10;
            if (left + tooltip.offsetWidth > window.innerWidth - 10) {
                left = window.innerWidth - tooltip.offsetWidth - 10;
            }
            tooltip.style.top = top + 'px';
            tooltip.style.left = left + 'px';
            setTimeout(() => {
                if (tooltip.parentNode) tooltip.remove();
            }, 5000);
        });
    });
    document.addEventListener('click', function(e) {
        const tooltip = document.querySelector('.dynamic-tooltip');
        if (tooltip && !e.target.closest('.info-icon')) {
            tooltip.remove();
        }
    });
    const fixStyle = document.createElement('style');
    fixStyle.textContent = `
        button[onclick*="runCustomCommand"],
        .small-action-button[onclick*="runCustomCommand"] {
            width: 145px !important;
            min-width: 145px !important;
            max-width: 145px !important;
            padding: 10px 18px !important;
            font-size: 13px !important;
            white-space: normal !important;
            word-wrap: break-word !important;
            line-height: 1.4 !important;
            height: auto !important;
            display: block !important;
            margin: 0 auto !important;
        }
        #log-output table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        #log-output th, #log-output td { padding: 8px; border: 1px solid #555; text-align: left; }
        #log-output thead tr { background: #333; color: white; }
    `;
    document.head.appendChild(fixStyle);
});
function runSelectedFunctions(event) {
    if (event) event.preventDefault();
    const runBtn = document.getElementById('run-button');
    if (runBtn) {
        runBtn.disabled = true;
        runBtn.style.opacity = '0.6';
        runBtn.innerHTML = '⏳';
    }
    const components = Array.from(document.querySelectorAll('input[name="component_names"]:checked'))
                           .map(cb => cb.value);
    const functions_per_type = {};
    document.querySelectorAll('.function-checkbox:checked').forEach(cb => {
        let typ = cb.dataset.type;
        let funcName = cb.value;
        const knownGlobal = ['discover_dbmachine', 'copy_latest_patches', 'setup_exascale_monitoring'];
        if (knownGlobal.includes(funcName)) {
            typ = 'Global';
        }
        if (!functions_per_type[typ]) functions_per_type[typ] = [];
        functions_per_type[typ].push(funcName);
    });
    const knownGlobal = ['discover_dbmachine', 'copy_latest_patches', 'setup_exascale_monitoring'];
    for (let typ in functions_per_type) {
        if (typ !== 'Global') {
            functions_per_type[typ] = functions_per_type[typ].filter(f => !knownGlobal.includes(f));
            if (functions_per_type[typ].length === 0) {
                delete functions_per_type[typ];
            }
        }
    }
    if (functions_per_type['Global'] && functions_per_type['Global'].length > 0 && components.length === 0) {
        components.push('global');
    }
    const params = {};
    document.querySelectorAll('input[name^="params_"], select[name^="params_"]').forEach(input => {
        if (input.value.trim()) params[input.name] = input.value.trim();
    });
    if (Object.keys(functions_per_type).length === 0 || (components.length === 0 && !functions_per_type['Global'])) {
        alert('Select components and functions');
        resetProcessing();
        return;
    }
    if (functions_per_type['Global'] && functions_per_type['Global'].includes('setup_exascale_monitoring')) {
        const restEndpoint = params['params_Global_setup_exascale_monitoring_rest_endpoint'] || '';
        const guestCount = components.filter(c => get_component_type(c) === 'Guest').length;
        const nonVirtualDbCount = components.filter(c => get_component_type(c) === 'Database Server' && !is_hypervisor(c)).length;
        const storageCount = components.filter(c => get_component_type(c) === 'Storage Server').length;
        const hasValidHost = (guestCount + nonVirtualDbCount) >= 1 && storageCount >= 3;
        if (!hasValidHost) {
            alert('Setup Exascale Monitoring requires:\n• At least 1 Guest or 1 non-virtual Database Server\n• At least 3 Storage Servers');
            resetProcessing();
            return;
        }
        const task_id = `setup_exascale_monitoring_${Date.now()}`;
        socket.emit('setup_exascale_monitoring', { components, params: { rest_endpoint: restEndpoint }, task_id });
        if (!logs[task_id]) {
            logs[task_id] = [];
            createTab(task_id, 'Setup Exascale Monitoring');
            switchTab(task_id);
        }
        logs[task_id].push('[Exascale] Starting monitoring setup...');
        const output = document.getElementById('log-output');
        if (output) {
            output.textContent = logs[task_id].join('\n');
            output.scrollTop = output.scrollHeight;
        }
        console.log('[DEBUG] Exascale task started — initial message forced in tab');
        document.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        document.querySelectorAll('input[name^="params_"], select[name^="params_"]').forEach(el => el.value = '');
        resetProcessing();
        return;
    }
    console.log('=== PAYLOAD TO BACKEND (v1.08) ===');
    console.log('components:', JSON.stringify(components));
    console.log('functions_per_type:', JSON.stringify(functions_per_type));
    console.log('params keys:', Object.keys(params));
    socket.emit('run_functions', { components, functions_per_type, params });
    resetProcessing();
    document.getElementById('log-panel').style.display = 'block';
    document.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
    document.querySelectorAll('input[name^="params_"], select[name^="params_"]').forEach(el => el.value = '');
}
function is_hypervisor(hostname) {
    return hostname.toLowerCase().includes('vm') || hostname.toLowerCase().includes('hypervisor');
}
function resetProcessing() {
    const runBtn = document.getElementById('run-button');
    if (runBtn) {
        runBtn.disabled = false;
        runBtn.style.opacity = '1';
        runBtn.innerHTML = '▶';
    }
}
function get_component_type(hostname) {
    if (hostname === 'global') return 'Global';
    const hostname_lower = hostname.toLowerCase();
    if (hostname_lower.endsWith('-ilom.us.oracle.com') || hostname_lower.endsWith('-c.us.oracle.com')) {
        const base = hostname_lower.replace('-ilom.us.oracle.com', '').replace('-c.us.oracle.com', '');
        if (base.includes('celadm')) return 'Storage Server ILOM';
        if (base.includes('adm')) return 'Database Server ILOM';
    }
    if (hostname_lower.includes('celadm') || hostname_lower.includes('cell')) return 'Storage Server';
    if (hostname_lower.includes('vm') || hostname_lower.includes('client')) return 'Guest';
    if (hostname_lower.includes('adm')) return 'Database Server';
    if (hostname_lower.includes('sw-') || hostname_lower.includes('switch')) return 'Switch';
    return 'Unknown';
}
function getSelectedComponentsForType(ctype) {
    const selected = Array.from(document.querySelectorAll('input[name="component_names"]:checked'))
        .filter(cb => get_component_type(cb.value) === ctype)
        .map(cb => cb.value);
    return selected;
}
function toggleCustomShell(header) {
    const content = header.nextElementSibling;
    content.style.display = content.style.display === 'block' ? 'none' : 'block';
    header.textContent = header.textContent.includes('▶') ? header.textContent.replace('▶', '▼') : header.textContent.replace('▼', '▶');
}
function toggleGlobalFunctions(header) {
    const content = header.nextElementSibling;
    content.style.display = content.style.display === 'none' ? 'block' : 'none';
    header.textContent = header.textContent.includes('▶') ? header.textContent.replace('▶', '▼') : header.textContent.replace('▼', '▶');
}
function runCustomCommand(ctype) {
    const id = `custom_cmd_${ctype.replace(/ /g, '_')}`;
    const textarea = document.getElementById(id);
    if (!textarea) {
        alert('Custom command textarea not found for ' + ctype + '. Expand the section first.');
        return;
    }
    const cmd = textarea.value.trim();
    if (!cmd) {
        alert('Enter a command');
        return;
    }
    const content = textarea.parentElement;
    if (content.style.display === 'none') content.style.display = 'block';
    const components = getSelectedComponentsForType(ctype);
    if (components.length === 0) {
        alert(`No ${ctype} hosts selected!`);
        return;
    }
    const lowerCmd = cmd.toLowerCase();
    if (lowerCmd.includes('more ') || lowerCmd.includes('less ') || lowerCmd.includes('vi ') || lowerCmd.includes('nano ') || lowerCmd.includes('top ')) {
        if (!confirm('WARNING: This command appears interactive (more/less/vi/etc.) and will likely hang the SSH session.\n\nProceed anyway?')) return;
    }
    if (!confirm(`Run as root on selected ${ctype} hosts?\nCommand: ${cmd}`)) return;
    const task_id = `custom_cmd_${Date.now()}`;
    socket.emit('run_custom_command', { ctype, cmd, components, task_id });
}
function showUploadModal() {
    document.getElementById('upload-modal').style.display = 'flex';
}
function hideUploadModal() {
    document.getElementById('upload-modal').style.display = 'none';
}
document.getElementById('upload-form')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    fetch('/setup/environment', {
        method: 'POST',
        body: formData
    })
    .then(r => r.text())
    .then(html => {
        if (html.includes('Uploaded')) {
            alert('Upload successful! Refreshing page...');
            location.reload();
        } else {
            alert('Upload failed. Check console.');
        }
    });
});
function loadADE_Series() {
    const seriesSelect = document.getElementById('global-series-select');
    seriesSelect.innerHTML = '<option value="">-- LOADING ADE SERIES... --</option>';
    fetch('/setup/api/series')
        .then(r => {
            if (!r.ok) throw new Error(`HTTP error! status: ${r.status}`);
            return r.json();
        })
        .then(data => {
            seriesSelect.innerHTML = '<option value="">-- Select Series --</option>';
            if (data.series && data.series.length > 0) {
                data.series.forEach(s => {
                    const opt = document.createElement('option');
                    opt.value = s;
                    opt.textContent = s;
                    seriesSelect.appendChild(opt);
                });
            } else {
                seriesSelect.innerHTML = '<option value="">-- No series found --</option>';
            }
        })
        .catch(err => {
            console.error('Series fetch failed:', err);
            seriesSelect.innerHTML = `<option value="">ERROR: ${err.message}</option>`;
            alert(`Failed to load ADE series:\n${err.message}\nCheck journalctl -u maa_unified_app -f for details.`);
        });
}
function loadLabelsForSeries(series) {
    const labelSelect = document.getElementById('global-label-select');
    if (!series) {
        labelSelect.innerHTML = '<option value="">-- Select Label (after choosing Series) --</option>';
        return;
    }
    labelSelect.innerHTML = '<option value="">-- LOADING LABELS... --</option>';
    fetch(`/setup/api/labels?series=${encodeURIComponent(series)}`)
        .then(r => {
            if (!r.ok) throw new Error(`HTTP error! status: ${r.status}`);
            return r.text();
        })
        .then(text => {
            let data;
            try {
                data = JSON.parse(text);
            } catch (e) {
                throw new Error('Invalid JSON from /api/labels: ' + text.substring(0, 200));
            }
            labelSelect.innerHTML = '<option value="">-- Select Label --</option>';
            if (data.labels && data.labels.length > 0) {
                data.labels.forEach(label => {
                    const opt = document.createElement('option');
                    opt.value = label;
                    opt.textContent = label;
                    labelSelect.appendChild(opt);
                });
            } else {
                labelSelect.innerHTML = '<option value="">No labels found for this series</option>';
            }
        })
        .catch(err => {
            console.error('Labels fetch failed:', err);
            labelSelect.innerHTML = `<option value="">ERROR: ${err.message}</option>`;
            alert(`Failed to load labels:\n${err.message}\nCheck journalctl -u maa_unified_app -f for details.`);
        });
}
socket.on('refresh_cache', () => {
    console.log('=== REFRESH_CACHE received - reloading series for all patching dropdowns ===');
    loadADE_Series();
});
socket.on('connect', () => console.log('SocketIO connected, sid = ' + socket.id));
socket.on('message', data => {
    hasRunAnyFunction = true;
    if (!data.task_id || data.task_id.toLowerCase().includes('debug')) return;
    if (!logs[data.task_id]) {
        logs[data.task_id] = [];
        const label = data.task_id.split('_').slice(0, -1).join(' – ') || data.task_id;
        createTab(data.task_id, label);
        if (!activeTab) switchTab(data.task_id);
    }
    if (!logs[data.task_id].includes(data.line)) logs[data.task_id].push(data.line);
    if (data.status === 'success' || data.status === 'error' || data.status === 'failed') {
        resetProcessing();
        tabStatuses[data.task_id] = data.status;
        updateTabColor(data.task_id);
        saveLogsToStorage();
    } else {
        tabStatuses[data.task_id] = 'running';
    }
    updateTabColor(data.task_id);
    if (activeTab === data.task_id) {
        const output = document.getElementById('log-output');
        output.innerHTML = logs[data.task_id].join('<br>');
        output.scrollTop = output.scrollHeight;
    }
    saveLogsToStorage();
});
socket.on('show_logs', () => {
    document.getElementById('log-panel').style.display = 'block';
});
