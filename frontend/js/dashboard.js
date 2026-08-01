// API Configuration
const API_URL = 'http://localhost:5000/api/v1';

// Load dashboard data when page loads
document.addEventListener('DOMContentLoaded', function() {
    loadDashboard();
    // Refresh every 10 seconds
    setInterval(loadDashboard, 10000);
});

// Main function to load dashboard data
async function loadDashboard() {
    try {
        // Fetch dashboard statistics
        const response = await fetch(`${API_URL}/dashboard`);
        const data = await response.json();
        
        // Update statistics cards
        updateStatistics(data);
        
        // Update recent scans table
        updateRecentScans(data.recent_scans);
        
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showError('Failed to load dashboard data. Make sure the API server is running.');
    }
}

// Update statistics cards
function updateStatistics(data) {
    document.getElementById('total-scans').textContent = data.total_scans || 0;
    
    const vulns = data.vulnerabilities || {};
    document.getElementById('critical-vulns').textContent = vulns.critical || 0;
    document.getElementById('high-vulns').textContent = vulns.high || 0;
    document.getElementById('medium-vulns').textContent = vulns.medium || 0;
}

// Update recent scans table
function updateRecentScans(scans) {
    const tbody = document.getElementById('scans-tbody');
    const loading = document.getElementById('recent-scans-loading');
    const table = document.getElementById('recent-scans-table');
    const noScans = document.getElementById('no-scans');
    
    // Hide loading
    loading.style.display = 'none';
    
    if (!scans || scans.length === 0) {
        table.style.display = 'none';
        noScans.style.display = 'block';
        return;
    }
    
    // Show table
    table.style.display = 'block';
    noScans.style.display = 'none';
    
    // Clear existing rows
    tbody.innerHTML = '';
    
    // Add new rows
    scans.forEach(scan => {
        const row = createScanRow(scan);
        tbody.appendChild(row);
    });
}

// Create a table row for a scan
function createScanRow(scan) {
    const tr = document.createElement('tr');
    
    // Scan name
    const tdName = document.createElement('td');
    tdName.textContent = scan.scan_name;
    tr.appendChild(tdName);
    
    // Target
    const tdTarget = document.createElement('td');
    tdTarget.textContent = scan.target;
    tr.appendChild(tdTarget);
    
    // Status
    const tdStatus = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = `badge ${getStatusClass(scan.status)}`;
    statusBadge.textContent = scan.status.toUpperCase();
    tdStatus.appendChild(statusBadge);
    tr.appendChild(tdStatus);
    
    // Hosts
    const tdHosts = document.createElement('td');
    tdHosts.textContent = scan.total_hosts || 0;
    tr.appendChild(tdHosts);
    
    // Vulnerabilities
    const tdVulns = document.createElement('td');
    const vulnCount = scan.total_vulnerabilities || 0;
    tdVulns.innerHTML = getVulnerabilityBadge(vulnCount, scan);
    tr.appendChild(tdVulns);
    
    // Date
    const tdDate = document.createElement('td');
    tdDate.textContent = formatDate(scan.started_at || scan.created_at);
    tr.appendChild(tdDate);
    
    // Actions
    const tdActions = document.createElement('td');
    tdActions.style.display = 'flex';
    tdActions.style.gap = '0.5rem';

    // View button
    const viewBtn = document.createElement('a');
    viewBtn.href = `scan-details.html?id=${scan.id}`;
    viewBtn.className = 'btn btn-secondary btn-small';
    viewBtn.textContent = 'View';
    tdActions.appendChild(viewBtn);

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-danger btn-small';
    deleteBtn.textContent = 'DEL';
    deleteBtn.title = 'Delete scan';
    deleteBtn.onclick = () => deleteScan(scan.id);
    tdActions.appendChild(deleteBtn);

    tr.appendChild(tdActions);
        
    return tr;
}

// Get CSS class for status badge
function getStatusClass(status) {
    const statusMap = {
        'completed': 'badge-success',
        'running': 'badge-info',
        'pending': 'badge-warning',
        'failed': 'badge-danger'
    };
    return statusMap[status] || 'badge-info';
}

// Create vulnerability badge with breakdown
function getVulnerabilityBadge(count, scan) {
    if (count === 0) {
        return '<span class="badge badge-success">0</span>';
    }
    
    let html = `<strong>${count}</strong>`;
    
    if (scan.critical_count > 0) {
        html += ` <span class="badge badge-danger">[C ${scan.critical_count}]</span>`;
    }
    if (scan.high_count > 0) {
        html += ` <span class="badge badge-warning">[H ${scan.high_count}]</span>`;
    }
    if (scan.medium_count > 0) {
        html += ` <span class="badge badge-info">[M ${scan.medium_count}]</span>`;
    }
    
    return html;
}

// Format date/time
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

// Show error message
function showError(message) {
    const tbody = document.getElementById('scans-tbody');
    tbody.innerHTML = `
        <tr>
            <td colspan="7" style="text-align: center; color: #ff3b4e; padding: 2rem;">
                [!] ${message}
            </td>
        </tr>
    `;
}

// Delete scan function
async function deleteScan(scanId) {
    // Confirm deletion
    const confirmed = confirm(
        `[!] DELETE CONFIRMATION\n\n` +
        `Are you sure you want to delete this scan?\n\n` +
        `This will permanently delete:\n` +
        `- Scan data\n` +
        `- All discovered hosts and ports\n` +
        `- All vulnerabilities\n` +
        `- All scan logs\n\n` +
        `This action cannot be undone!`
    );
    
    if (!confirmed) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Show success message
            alert('[OK] Scan deleted successfully!');
            
            // Reload dashboard
            loadDashboard();
        } else {
            alert(`[FAIL] Error: ${data.error}`);
        }
        
    } catch (error) {
        console.error('Error deleting scan:', error);
        alert('[FAIL] Failed to delete scan. Make sure the API server is running.');
    }
}