console.log("access.js loaded");

// Global error handler
window.onerror = function (message, source, lineno, colno, error) {
    console.error(`Global error: ${message} at ${source}:${lineno}:${colno}`, error);
};

// Modal functions
function openAddCredentialModal() {
    console.log("openAddCredentialModal called");
    const modal = document.getElementById('addCredentialModal');
    if (modal) {
        modal.style.display = 'block';
        console.log("Modal display set to block");
    } else {
        console.error("Add Credential Modal not found");
    }
}

function closeAddCredentialModal() {
    console.log("closeAddCredentialModal called");
    const modal = document.getElementById('addCredentialModal');
    if (modal) {
        modal.style.display = 'none';
    } else {
        console.error("Add Credential Modal not found");
    }
}

function getCredential(componentType, componentName, username, credentialType) {
    console.log("getCredential called with:", componentType, componentName, username, credentialType);
    fetch('/access/get_credential', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            component_type: componentType,
            component_name: componentName,
            username: username,
            credential_type: credentialType
        })
    })
    .then(response => {
        console.log("Fetch response status:", response.status);
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.error || 'Failed to fetch credential');
            });
        }
        return response.json();
    })
    .then(data => {
        console.log("Fetch response data:", data);
        if (data.error) {
            alert(data.error);
        } else {
            document.getElementById('credentialContent').textContent = data.credential;
            document.getElementById('credentialModal').style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error fetching credential:', error);
        alert('Error: ' + error.message);
    });
}

function closeCredentialModal() {
    console.log("closeCredentialModal called");
    document.getElementById('credentialModal').style.display = 'none';
}

function deleteSelectedCredentials() {
    console.log("deleteSelectedCredentials called");
    const checkboxes = document.querySelectorAll('.credential-checkbox:checked');
    const credentials = Array.from(checkboxes).map(checkbox => ({
        component_type: checkbox.getAttribute('data-type'),
        component_name: checkbox.getAttribute('data-name'),
        username: checkbox.getAttribute('data-username')
    }));

    if (credentials.length === 0) {
        alert('Please select at least one credential to delete.');
        return;
    }

    if (confirm('Are you sure you want to delete the selected credentials?')) {
        fetch('/access/delete_credential', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ credentials: credentials })
        })
        .then(response => {
            console.log("Delete response status:", response.status);
            if (!response.ok) {
                throw new Error('Failed to delete credentials');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                alert('Credentials deleted successfully!');
                location.reload();
            } else {
                alert(data.error || 'Error deleting credentials');
            }
        })
        .catch(error => {
            console.error('Error deleting credentials:', error);
            alert('Error deleting credentials: ' + error.message);
        });
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function () {
    console.log("DOM fully loaded");
    const addButton = document.getElementById('addCredentialButton');
    const deleteButton = document.getElementById('deleteCredentialButton');

    if (addButton) {
        console.log("Add Credential button found");
        addButton.addEventListener('click', function (event) {
            console.log("Add Credential button clicked");
            openAddCredentialModal();
        });
    } else {
        console.error("Add Credential button not found");
    }

    if (deleteButton) {
        console.log("Delete Credential button found");
        deleteButton.addEventListener('click', function (event) {
            console.log("Delete Credential button clicked");
            deleteSelectedCredentials();
        });
    } else {
        console.error("Delete Credential button not found");
    }
});

// Close modals when clicking outside
window.onclick = function (event) {
    if (event.target.className === 'modal') {
        closeAddCredentialModal();
        closeCredentialModal();
    }
};
