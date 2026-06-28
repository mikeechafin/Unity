// Filename: static/access.js
// Version: 2026-03-30 v1.14
// Changes: Added green FAB menu toggle logic + improved modal handling for wider screens. Brighter button styles already in HTML. No other logic changes.
console.log("access.js v1.14 FAB ready");
function filterCredentials() {
    const term = document.getElementById('credentialSearch').value.toLowerCase().trim();
    const rows = document.querySelectorAll('#credentialsTableBody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
    });
}
function toggleFabMenu() {
    const menu = document.getElementById('fabMenu');
    menu.style.display = (menu.style.display === 'block') ? 'none' : 'block';
}
function openAddCredentialModal() {
    document.getElementById('addCredentialModal').style.display = 'flex';
}
function closeAddCredentialModal() {
    document.getElementById('addCredentialModal').style.display = 'none';
}
function openEditCredentialModal(componentType, componentName, username) {
    document.getElementById('edit_component_type').value = componentType;
    document.getElementById('edit_component_name').value = componentName;
    document.getElementById('edit_username').value = username;
    document.getElementById('editCredentialModal').style.display = 'flex';
}
function closeEditCredentialModal() {
    document.getElementById('editCredentialModal').style.display = 'none';
}
function getCredential(componentType, componentName, username, credentialType) {
    fetch('/access/get_credential', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ component_type: componentType, component_name: componentName, username: username, credential_type: credentialType })
    })
    .then(r => r.json())
    .then(data => {
        const content = document.getElementById('credentialContent');
        const modal = document.getElementById('credentialModal');
        if (data.error) {
            alert(data.error);
        } else {
            content.textContent = data.credential || 'No value';
            modal.style.display = 'flex';
        }
    })
    .catch(err => alert('Error: ' + err.message));
}
function closeCredentialModal() {
    document.getElementById('credentialModal').style.display = 'none';
}
function copyToClipboard() {
    const text = document.getElementById('credentialContent').textContent;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => alert('✅ Copied!'));
    } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        alert('✅ Copied!');
    }
}
function deleteSelectedCredentials() {
    const checked = document.querySelectorAll('.credential-checkbox:checked');
    if (checked.length === 0) {
        alert('Select at least one credential');
        return;
    }
    if (!confirm(`Delete ${checked.length} credential(s)?`)) return;
    const creds = Array.from(checked).map(cb => ({
        component_type: cb.dataset.type,
        component_name: cb.dataset.name,
        username: cb.dataset.username
    }));
    fetch('/access/delete_credential', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credentials: creds })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            alert('✅ Deleted');
            location.reload();
        } else {
            alert(data.error || 'Failed');
        }
    });
}
// Close FAB when clicking outside
document.addEventListener('click', function(e) {
    const menu = document.getElementById('fabMenu');
    const fab = document.getElementById('fabButton');
    if (menu && menu.style.display === 'block' && !fab.contains(e.target) && !menu.contains(e.target)) {
        menu.style.display = 'none';
    }
});
// ESC support
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        ['addCredentialModal','editCredentialModal','credentialModal'].forEach(id => {
            const m = document.getElementById(id);
            if (m && m.style.display === 'flex') m.style.display = 'none';
        });
        const fabMenu = document.getElementById('fabMenu');
        if (fabMenu) fabMenu.style.display = 'none';
    }
});
