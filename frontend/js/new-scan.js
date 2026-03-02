// API Configuration
const API_URL = 'http://localhost:5000/api/v1';

// Form elements
const scanForm = document.getElementById('scan-form');
const scanTypeSelect = document.getElementById('scan-type');
const scanTypeInfo = document.getElementById('scan-type-info');
const submitBtn = document.getElementById('submit-btn');
const successMessage = document.getElementById('success-message');
const errorMessage = document.getElementById('error-message');
const errorText = document.getElementById('error-text');

// Show scan type information when selected
scanTypeSelect.addEventListener('change', function() {
    const scanType = this.value;
    
    // Hide all info boxes
    document.querySelectorAll('.scan-info').forEach(info => {
        info.style.display = 'none';
    });
    
    if (scanType) {
        scanTypeInfo.style.display = 'block';
        const infoBox = document.getElementById(`${scanType}-info`);
        if (infoBox) {
            infoBox.style.display = 'block';
        }
    } else {
        scanTypeInfo.style.display = 'none';
    }
});

// Handle form submission
scanForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Get form values
    const scanName = document.getElementById('scan-name').value.trim();
    const target = document.getElementById('target').value.trim();
    const scanType = document.getElementById('scan-type').value;
    const authorized = document.getElementById('authorization').checked;
    
    // Validate
    if (!scanName || !target || !scanType) {
        showError('Please fill in all required fields');
        return;
    }
    
    if (!authorized) {
        showError('You must confirm authorization to proceed');
        return;
    }
    
    // Disable form
    submitBtn.disabled = true;
    submitBtn.innerHTML = '⏳ Starting Scan...';
    hideMessages();
    
    // Send request to API
    try {
        const response = await fetch(`${API_URL}/scans`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                scan_name: scanName,
                target: target,
                scan_type: scanType,
                project_id: 1
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Success
            showSuccess(data);
            scanForm.style.display = 'none';
        } else {
            // Error from API
            showError(data.error || 'Failed to start scan');
            submitBtn.disabled = false;
            submitBtn.innerHTML = '🚀 Start Scan';
        }
        
    } catch (error) {
        console.error('Error:', error);
        showError('Cannot connect to API server. Make sure it is running on http://localhost:5000');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '🚀 Start Scan';
    }
});

// Show success message
function showSuccess(data) {
    successMessage.style.display = 'block';
    successMessage.innerHTML = `
        <strong>✅ Scan Started Successfully!</strong>
        <p>Scan ID: <strong>#${data.scan_id}</strong></p>
        <p>${data.message}</p>
        <div style="margin-top: 1rem;">
            <a href="scan-details.html?id=${data.scan_id}" class="btn btn-primary btn-small">View Scan Progress</a>
            <a href="index.html" class="btn btn-secondary btn-small">Back to Dashboard</a>
        </div>
    `;
    
    // Scroll to message
    successMessage.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Show error message
function showError(message) {
    errorMessage.style.display = 'block';
    errorText.textContent = message;
    
    // Scroll to message
    errorMessage.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Hide all messages
function hideMessages() {
    successMessage.style.display = 'none';
    errorMessage.style.display = 'none';
}