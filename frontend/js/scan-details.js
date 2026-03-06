// API Configuration
const API_URL = 'http://localhost:5000/api/v1';

// Get scan ID from URL
const urlParams = new URLSearchParams(window.location.search);
const scanId = urlParams.get('id');

// State elements
const loadingState = document.getElementById('loading-state');
const errorState = document.getElementById('error-state');
const content = document.getElementById('content');

// Load scan details when page loads
document.addEventListener('DOMContentLoaded', function() {
    if (!scanId) {
        showError('No scan ID provided');
        return;
    }
    
    loadScanDetails();
    
    // Auto-refresh if scan is running
    const refreshInterval = setInterval(() => {
        const status = document.getElementById('scan-status-badge').textContent.toLowerCase();
        if (status === 'running' || status === 'pending') {
            loadScanDetails();
        } else {
            clearInterval(refreshInterval);
        }
    }, 5000);
});

// Load scan details and vulnerabilities
// Load scan details and vulnerabilities
async function loadScanDetails() {
    try {
        // Fetch scan details
        const scanResponse = await fetch(`${API_URL}/scans/${scanId}`);
        if (!scanResponse.ok) {
            throw new Error('Scan not found');
        }
        const scan = await scanResponse.json();
        
        // Fetch vulnerabilities
        const vulnResponse = await fetch(`${API_URL}/scans/${scanId}/vulnerabilities`);
        const vulnData = await vulnResponse.json();
        
        // NEW: Fetch ports
        const portsResponse = await fetch(`${API_URL}/scans/${scanId}/ports`);
        const portsData = await portsResponse.json();
        
        // Hide loading, show content
        loadingState.style.display = 'none';
        content.style.display = 'block';
        
        // Update page with scan data
        updateScanInfo(scan);
        updatePorts(portsData.ports || []); // NEW: Display ports
        updateVulnerabilities(vulnData.vulnerabilities || []);
        
    } catch (error) {
        console.error('Error loading scan:', error);
        showError('Failed to load scan details. The scan may not exist or the API server may be down.');
    }
}

// Update scan information
function updateScanInfo(scan) {
    document.getElementById('scan-name').textContent = scan.scan_name;
    document.getElementById('scan-target').textContent = `Target: ${scan.target} | Type: ${scan.scan_type}`;
    
    // Status badge
    const statusBadge = document.getElementById('scan-status-badge');
    statusBadge.textContent = scan.status.toUpperCase();
    statusBadge.className = `badge ${getStatusClass(scan.status)}`;
    
    // Statistics
    document.getElementById('total-hosts').textContent = scan.total_hosts || 0;
    document.getElementById('total-ports').textContent = scan.total_ports || 0;
    document.getElementById('total-vulns').textContent = scan.total_vulnerabilities || 0;
    document.getElementById('critical-vulns').textContent = scan.critical_count || 0;
}

// Update vulnerabilities display
function updateVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilities-container');
    const noVulns = document.getElementById('no-vulnerabilities');
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        container.style.display = 'none';
        noVulns.style.display = 'block';
        return;
    }
    
    container.style.display = 'block';
    noVulns.style.display = 'none';
    container.innerHTML = '';
    
    // Group by severity
    const grouped = groupBySeverity(vulnerabilities);
    
    // Display each severity group
    ['critical', 'high', 'medium', 'low'].forEach(severity => {
        if (grouped[severity] && grouped[severity].length > 0) {
            const section = createSeveritySection(severity, grouped[severity]);
            container.appendChild(section);
        }
    });
}

// Group vulnerabilities by severity
function groupBySeverity(vulnerabilities) {
    const grouped = {
        critical: [],
        high: [],
        medium: [],
        low: []
    };
    
    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity.toLowerCase();
        if (grouped[severity]) {
            grouped[severity].push(vuln);
        }
    });
    
    return grouped;
}

// Create severity section
function createSeveritySection(severity, vulnerabilities) {
    const section = document.createElement('div');
    section.style.marginBottom = '2rem';
    
    // Section header
    const header = document.createElement('h3');
    header.style.marginBottom = '1rem';
    header.style.color = 'white';
    header.innerHTML = `${getSeverityEmoji(severity)} ${severity.toUpperCase()} Severity (${vulnerabilities.length})`;
    section.appendChild(header);
    
    // Vulnerability cards
    vulnerabilities.forEach(vuln => {
        const card = createVulnerabilityCard(vuln);
        section.appendChild(card);
    });
    
    return section;
}

// Create vulnerability card
// Create vulnerability card
function createVulnerabilityCard(vuln) {
    const card = document.createElement('div');
    card.className = 'vulnerability-card';
    card.style.marginBottom = '1rem';
    card.style.borderLeft = `4px solid ${getSeverityColor(vuln.severity)}`;
    
    card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem; gap: 1rem;">
            <div style="flex: 1;">
                <h4 style="margin: 0 0 0.5rem 0; color: #333;">
                    ${vuln.cve_id || 'Unknown CVE'}
                </h4>
                <div style="color: #666; font-size: 0.9rem;">
                    <strong>Host:</strong> ${vuln.ip_address} ${vuln.hostname ? `(${vuln.hostname})` : ''}
                    ${vuln.port ? ` | <strong>Port:</strong> ${vuln.port}` : ''}
                    ${vuln.service ? ` | <strong>Service:</strong> ${vuln.service}` : ''}
                </div>
            </div>
            <div style="display: flex; gap: 0.5rem; align-items: center; flex-shrink: 0;">
                <span class="badge ${getSeverityBadgeClass(vuln.severity)}" style="white-space: nowrap;">
                    ${vuln.severity.toUpperCase()}
                    ${vuln.cvss_score ? ` (${vuln.cvss_score})` : ''}
                </span>
                ${vuln.cve_id ? `
                <button 
                    class="btn btn-danger btn-small exploit-btn" 
                    onclick="testExploit(${vuln.id}, '${vuln.cve_id}')"
                    title="Test exploitation with Metasploit"
                    style="white-space: nowrap;"
                >
                    🎯 Test Exploit
                </button>
                ` : ''}
            </div>
        </div>
        
        <div style="margin-bottom: 1rem;">
            <strong style="color: #555;">Description:</strong>
            <p style="margin: 0.5rem 0; color: #666;">${vuln.description || 'No description available'}</p>
        </div>
        
        ${vuln.remediation ? `
            <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                <strong style="color: #28a745;">💡 Remediation:</strong>
                <p style="margin: 0.5rem 0 0 0; color: #666;">${vuln.remediation}</p>
            </div>
        ` : ''}
        
        ${vuln.references ? `
            <details style="margin-top: 1rem;">
                <summary style="cursor: pointer; color: #667eea; font-weight: 500;">
                    📚 References
                </summary>
                <div style="margin-top: 0.5rem; padding-left: 1rem;">
                    ${vuln.references.split(',').map(ref => 
                        `<a href="${ref.trim()}" target="_blank" style="display: block; color: #667eea; margin: 0.25rem 0;">${ref.trim()}</a>`
                    ).join('')}
                </div>
            </details>
        ` : ''}
    `;
    
    return card;
}

// Helper functions
function getStatusClass(status) {
    const statusMap = {
        'completed': 'badge-success',
        'running': 'badge-info',
        'pending': 'badge-warning',
        'failed': 'badge-danger'
    };
    return statusMap[status] || 'badge-info';
}

function getSeverityEmoji(severity) {
    const emojiMap = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    };
    return emojiMap[severity] || '⚪';
}

function getSeverityColor(severity) {
    const colorMap = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745'
    };
    return colorMap[severity.toLowerCase()] || '#6c757d';
}

function getSeverityBadgeClass(severity) {
    const classMap = {
        'critical': 'badge-danger',
        'high': 'badge-warning',
        'medium': 'badge-warning',
        'low': 'badge-success'
    };
    return classMap[severity.toLowerCase()] || 'badge-info';
}

function showError(message) {
    loadingState.style.display = 'none';
    errorState.style.display = 'block';
    document.getElementById('error-message-text').textContent = message;
}

// Toggle download menu
document.getElementById('download-btn').addEventListener('click', function() {
    const menu = document.getElementById('download-menu');
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
});

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
    const dropdown = document.querySelector('.dropdown');
    if (dropdown && !dropdown.contains(event.target)) {
        document.getElementById('download-menu').style.display = 'none';
    }
});

// Generate and download report
async function generateReport(reportType) {
    try {
        // Hide menu
        document.getElementById('download-menu').style.display = 'none';
        
        // Show loading
        const btn = document.getElementById('download-btn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '⏳ Generating...';
        btn.disabled = true;
        
        // Generate report
        const response = await fetch(`${API_URL}/scans/${scanId}/reports/${reportType}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Download the report
            const downloadUrl = `${API_URL.replace('/api/v1', '')}/api/v1/reports/${data.filename}`;
            
            // Create temporary link and click it
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = data.filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            // Show success message
            alert(`✅ ${reportType.toUpperCase()} report downloaded successfully!`);
        } else {
            alert(`❌ Error: ${data.error}`);
        }
        
        // Restore button
        btn.innerHTML = originalText;
        btn.disabled = false;
        
    } catch (error) {
        console.error('Error generating report:', error);
        alert('❌ Failed to generate report. Make sure the API server is running.');
        
        // Restore button
        const btn = document.getElementById('download-btn');
        btn.innerHTML = '📥 Download Report';
        btn.disabled = false;
    }
}

// ==================== EXPLOITATION FUNCTIONS ====================

// Test exploitation of a vulnerability
async function testExploit(vulnId, cveId) {
    // First confirmation with strong warnings
    const confirmed = confirm(
        `⚠️ CRITICAL WARNING ⚠️\n\n` +
        `You are about to attempt REAL EXPLOITATION of:\n` +
        `${cveId}\n\n` +
        `This will:\n` +
        `✓ Execute actual exploit code against the target\n` +
        `✓ Attempt to compromise the system\n` +
        `✓ May cause system instability or crashes\n` +
        `✓ All activity will be logged\n\n` +
        `LEGAL REQUIREMENTS:\n` +
        `✓ You MUST own this system, OR\n` +
        `✓ Have WRITTEN authorization to test it\n\n` +
        `Unauthorized hacking is ILLEGAL and punishable by:\n` +
        `- Criminal prosecution\n` +
        `- Heavy fines\n` +
        `- Imprisonment\n\n` +
        `Do you have authorization and wish to proceed?`
    );
    
    if (!confirmed) {
        return;
    }
    
    // Second confirmation
    const doubleConfirm = confirm(
        `FINAL CONFIRMATION\n\n` +
        `I confirm that:\n` +
        `✓ I have authorization to test this system\n` +
        `✓ I understand the legal implications\n` +
        `✓ I accept full responsibility\n\n` +
        `Proceed with exploitation?`
    );
    
    if (!doubleConfirm) {
        return;
    }
    
    try {
        // Create and show loading message
        const loadingMsg = document.createElement('div');
        loadingMsg.className = 'alert alert-info';
        loadingMsg.id = 'exploit-loading';
        loadingMsg.innerHTML = `
            <strong>⏳ Exploitation in Progress...</strong>
            <p>🔍 Searching Metasploit database for matching exploit module...</p>
            <p>⚙️ Configuring target parameters and payload...</p>
            <p>🚀 Executing exploit against target system...</p>
            <p><small>This may take 30-60 seconds. Please wait...</small></p>
        `;
        
        const container = document.getElementById('vulnerabilities-container');
        container.insertBefore(loadingMsg, container.firstChild);
        
        // Scroll to loading message
        loadingMsg.scrollIntoView({ behavior: 'smooth', block: 'center' });
        
        // Call API to exploit vulnerability
        const response = await fetch(`${API_URL}/vulnerabilities/${vulnId}/exploit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });
        
        const result = await response.json();
        
        // Remove loading message
        loadingMsg.remove();
        
        // Show result
        const resultMsg = document.createElement('div');
        resultMsg.id = 'exploit-result';
        
        if (result.success) {
            // Success - exploitation worked!
            resultMsg.className = 'alert alert-success';
            resultMsg.innerHTML = `
                <strong>✅ EXPLOITATION SUCCESSFUL!</strong>
                <p style="margin: 0.5rem 0;"><strong>Session Created:</strong> #${result.session_id}</p>
                <p style="margin: 0.5rem 0;"><strong>Session Type:</strong> ${result.session_type}</p>
                <p style="margin: 0.5rem 0;"><strong>Exploit Used:</strong> ${result.exploit_used}</p>
                <p style="margin: 0.5rem 0;"><strong>Message:</strong> ${result.message}</p>
                <div style="margin-top: 1rem; padding: 1rem; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                    <strong>⚠️ What This Means:</strong>
                    <p style="margin: 0.5rem 0 0 0;">You now have remote access to the target system. This proves the vulnerability is real and exploitable. Document this finding and close the session when done testing.</p>
                </div>
                <div style="margin-top: 1rem;">
                    <button onclick="viewSessions()" class="btn btn-primary btn-small">
                        📋 View Active Sessions
                    </button>
                    <button onclick="document.getElementById('exploit-result').remove()" class="btn btn-secondary btn-small">
                        Close
                    </button>
                </div>
            `;
        } else {
            // Failed - exploitation didn't work
            resultMsg.className = 'alert alert-danger';
            resultMsg.innerHTML = `
                <strong>❌ Exploitation Failed</strong>
                <p style="margin: 0.5rem 0;"><strong>Reason:</strong> ${result.message || result.error}</p>
                ${result.exploit_used ? `<p style="margin: 0.5rem 0;"><strong>Exploit Attempted:</strong> ${result.exploit_used}</p>` : ''}
                <div style="margin: 1rem 0;">
                    <strong>Possible Reasons:</strong>
                    <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                        <li>Target system is patched or updated</li>
                        <li>Firewall or IDS blocking the exploit</li>
                        <li>Service version is not actually vulnerable</li>
                        <li>Exploit module requires different configuration</li>
                        <li>Network connectivity issues</li>
                    </ul>
                </div>
                <div style="margin-top: 1rem; padding: 1rem; background: #d4edda; border-left: 4px solid #28a745; border-radius: 4px;">
                    <strong>✅ Good News:</strong>
                    <p style="margin: 0.5rem 0 0 0;">The target appears to be secure against this exploit. This is what you want to see in a security assessment!</p>
                </div>
                <div style="margin-top: 1rem;">
                    <button onclick="document.getElementById('exploit-result').remove()" class="btn btn-secondary btn-small">
                        Close
                    </button>
                </div>
            `;
        }
        
        container.insertBefore(resultMsg, container.firstChild);
        resultMsg.scrollIntoView({ behavior: 'smooth', block: 'center' });
        
    } catch (error) {
        // Network or API error
        console.error('Exploitation error:', error);
        
        // Remove loading message if it exists
        const loading = document.getElementById('exploit-loading');
        if (loading) loading.remove();
        
        // Show error
        const errorMsg = document.createElement('div');
        errorMsg.className = 'alert alert-danger';
        errorMsg.innerHTML = `
            <strong>❌ Error</strong>
            <p>Cannot connect to API server. Make sure:</p>
            <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                <li>Backend server is running (http://localhost:5000)</li>
                <li>Metasploit RPC server is running</li>
                <li>Network connection is working</li>
            </ul>
            <p style="margin-top: 0.5rem;"><small>Error: ${error.message}</small></p>
            <button onclick="this.parentElement.remove()" class="btn btn-secondary btn-small" style="margin-top: 0.5rem;">
                Close
            </button>
        `;
        
        const container = document.getElementById('vulnerabilities-container');
        container.insertBefore(errorMsg, container.firstChild);
        errorMsg.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

// View active sessions (future feature)
function viewSessions() {
    // For now, just show alert
    alert('Session management interface coming soon!\n\nFor now, you can view sessions at:\nhttp://localhost:5000/api/v1/sessions');
}

// Update ports display
function updatePorts(ports) {
    const container = document.getElementById('ports-container');
    const noPorts = document.getElementById('no-ports');
    
    if (!ports || ports.length === 0) {
        container.style.display = 'none';
        noPorts.style.display = 'block';
        return;
    }
    
    container.style.display = 'block';
    noPorts.style.display = 'none';
    container.innerHTML = '';
    
    // Sort ports by port number
    const sortedPorts = [...ports].sort((a, b) => a.port - b.port);
    
    // Create table view for ports
    const table = document.createElement('div');
    table.className = 'ports-table';
    
    table.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Product</th>
                </tr>
            </thead>
            <tbody id="ports-tbody">
            </tbody>
        </table>
    `;
    
    container.appendChild(table);
    
    const tbody = document.getElementById('ports-tbody');
    
    // Add each port as a table row
    sortedPorts.forEach(port => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>
                <strong style="font-size: 1.2rem; color: #667eea;">${port.port}</strong>
            </td>
            <td>
                <span class="port-protocol">${port.protocol || 'tcp'}</span>
            </td>
            <td>
                <span class="port-state ${port.state}">${port.state || 'open'}</span>
            </td>
            <td>
                <strong>${port.service || 'unknown'}</strong>
            </td>
            <td>
                ${port.version || 'N/A'}
            </td>
            <td>
                ${port.product || 'N/A'}
            </td>
        `;
        
        tbody.appendChild(row);
    });
    
    // Also create card view (optional - can be toggled)
    createPortsCardView(sortedPorts, container);
}

// Toggle between table and card view for ports
let portsViewMode = 'table'; // 'table' or 'cards'

document.getElementById('toggle-ports-view').addEventListener('click', function() {
    const table = document.querySelector('.ports-table');
    const cards = document.getElementById('ports-cards');
    const button = document.getElementById('toggle-ports-view');
    
    if (portsViewMode === 'table') {
        // Switch to cards
        table.style.display = 'none';
        cards.style.display = 'grid';
        button.textContent = '📋 Switch to Table View';
        portsViewMode = 'cards';
    } else {
        // Switch to table
        table.style.display = 'block';
        cards.style.display = 'none';
        button.textContent = '📊 Switch to Card View';
        portsViewMode = 'table';
    }
});

// Make port rows clickable to show full details
function createPortRow(port) {
    const row = document.createElement('tr');
    row.style.cursor = 'pointer';
    
    row.innerHTML = `
        <td><strong style="font-size: 1.2rem; color: #667eea;">${port.port}</strong></td>
        <td><span class="port-protocol">${port.protocol || 'tcp'}</span></td>
        <td><span class="port-state ${port.state}">${port.state || 'open'}</span></td>
        <td><strong>${port.service || 'unknown'}</strong></td>
        <td>${port.version || 'N/A'}</td>
        <td>${port.product || 'N/A'}</td>
    `;
    
    // Click to show detailed modal
    row.addEventListener('click', () => {
        showPortDetails(port);
    });
    
    return row;
}

function showPortDetails(port) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 600px; background: white; padding: 2rem; border-radius: 8px; position: relative;">
            <button onclick="this.parentElement.parentElement.remove()" style="position: absolute; top: 1rem; right: 1rem; border: none; background: none; font-size: 1.5rem; cursor: pointer;">&times;</button>
            
            <h2 style="color: #667eea; margin-bottom: 1rem;">Port ${port.port} Details</h2>
            
            <div style="line-height: 2;">
                <p><strong>Port Number:</strong> ${port.port}</p>
                <p><strong>Protocol:</strong> ${port.protocol || 'tcp'}</p>
                <p><strong>State:</strong> <span class="port-state ${port.state}">${port.state || 'open'}</span></p>
                <p><strong>Service:</strong> ${port.service || 'Unknown'}</p>
                <p><strong>Product:</strong> ${port.product || 'N/A'}</p>
                <p><strong>Version:</strong> ${port.version || 'N/A'}</p>
                ${port.extra_info ? `<p><strong>Extra Info:</strong> ${port.extra_info}</p>` : ''}
                <p><strong>Host:</strong> ${port.ip_address} ${port.hostname ? `(${port.hostname})` : ''}</p>
            </div>
            
            <div style="margin-top: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 4px;">
                <strong>Security Note:</strong>
                <p style="margin-top: 0.5rem; color: #666; font-size: 0.9rem;">
                    This port is currently accessible. Review if this service should be exposed and ensure it's properly secured.
                </p>
            </div>
            
            <button onclick="this.parentElement.parentElement.remove()" class="btn btn-primary" style="margin-top: 1rem; width: 100%;">
                Close
            </button>
        </div>
    `;
    
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
    `;
    
    document.body.appendChild(modal);
}

// Alternative: Card view for ports
function createPortsCardView(ports, container) {
    const cardsContainer = document.createElement('div');
    cardsContainer.className = 'ports-grid';
    cardsContainer.style.display = 'none'; // Hidden by default, can add toggle button
    cardsContainer.id = 'ports-cards';
    
    ports.forEach(port => {
        const card = document.createElement('div');
        card.className = 'port-card';
        
        card.innerHTML = `
            <div class="port-number">${port.port}/${port.protocol || 'tcp'}</div>
            <div class="port-service">${port.service || 'Unknown Service'}</div>
            <div class="port-details">
                ${port.product ? `<strong>Product:</strong> ${port.product}<br>` : ''}
                ${port.version ? `<strong>Version:</strong> ${port.version}<br>` : ''}
                ${port.extra_info ? `<strong>Info:</strong> ${port.extra_info}<br>` : ''}
                <span class="port-state ${port.state}">${(port.state || 'open').toUpperCase()}</span>
            </div>
        `;
        
        cardsContainer.appendChild(card);
    });
    
    container.appendChild(cardsContainer);
}