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
async function loadScanDetails() {
    try {
        console.log(`Loading scan details for ID: ${scanId}`);
        
        // Fetch scan details
        const scanResponse = await fetch(`${API_URL}/scans/${scanId}`);
        if (!scanResponse.ok) {
            throw new Error(`Scan not found (HTTP ${scanResponse.status})`);
        }
        const scan = await scanResponse.json();
        console.log('Scan data loaded:', scan);
        
        // Fetch vulnerabilities
        const vulnResponse = await fetch(`${API_URL}/scans/${scanId}/vulnerabilities`);
        const vulnData = await vulnResponse.json();
        console.log(`Loaded ${vulnData.vulnerabilities?.length || 0} vulnerabilities`);
        
        // Fetch ports
        const portsResponse = await fetch(`${API_URL}/scans/${scanId}/ports`);
        const portsData = await portsResponse.json();
        console.log(`Loaded ${portsData.ports?.length || 0} ports`);
        
        // Hide loading, show content
        if (loadingState) loadingState.style.display = 'none';
        if (content) content.style.display = 'block';
        
        // Update page sections
        updateScanInfo(scan);
        updatePorts(portsData.ports || []);
        updateVulnerabilities(vulnData.vulnerabilities || []);
        
        // NEW: Load attack results immediately if they exist
        setTimeout(() => {
            loadAttackResults();
        }, 1000);
        
        console.log('✅ Scan details loaded successfully');
        
    } catch (error) {
        console.error('❌ Error loading scan:', error);
        
        if (loadingState) loadingState.style.display = 'none';
        if (content) {
            content.innerHTML = `
                <div class="alert alert-danger">
                    <strong>❌ Error Loading Scan</strong>
                    <p>${error.message}</p>
                    <a href="index.html" class="btn btn-primary">Back to Dashboard</a>
                </div>
            `;
        }
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

// ==================== ATTACK SIMULATION ====================

function showAttackSimulationDialog() {
    console.log(`showAttackSimulationDialog called with scanId: ${scanId}`);
    
    if (!scanId) {
        alert('Error: No scan ID available for attack simulation');
        console.error('Cannot show attack dialog: scanId is null/undefined');
        return;
    }
    
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.innerHTML = `
        <div class="modal-content" style="max-width: 700px;">
            <h2 style="color: #dc3545; margin-bottom: 1rem;">⚠️ Attack Simulation Warning</h2>
            
            <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                <strong>⚠️ CRITICAL WARNING</strong>
                <p style="margin: 0.5rem 0;">This will perform REAL attacks on the target system!</p>
                <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                    <li>SQL Injection attempts</li>
                    <li>XSS injection attempts</li>
                    <li>Directory traversal attacks</li>
                    <li>Bruteforce attempts</li>
                    <li>Service enumeration</li>
                </ul>
                <p style="margin: 0.5rem 0 0 0; color: #856404;">
                    <strong>ONLY use on systems you own or have written authorization to test!</strong>
                </p>
            </div>
            
            <h3 style="margin-top: 1.5rem;">Select Attack Types:</h3>
            
            <div style="margin: 1rem 0; max-height: 300px; overflow-y: auto;">
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="port_scan_detection" checked> 
                    <strong>Port Scan Detection Test</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests if rapid scanning triggers IDS/IPS</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="sql_injection"> 
                    <strong>SQL Injection Test</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests database security with common SQL payloads</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="xss"> 
                    <strong>Cross-Site Scripting (XSS)</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests input sanitization with JavaScript payloads</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="directory_traversal"> 
                    <strong>Directory Traversal</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests file access controls</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="http_methods"> 
                    <strong>HTTP Methods Test</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Checks for dangerous HTTP methods (PUT, DELETE)</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="directory_bruteforce"> 
                    <strong>Directory Bruteforce</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Discovers hidden directories</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="ssh_bruteforce"> 
                    <strong>SSH Bruteforce Test</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests SSH with common credentials</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; cursor: pointer;">
                    <input type="checkbox" value="ftp_anonymous"> 
                    <strong>FTP Anonymous Access</strong>
                    <span style="color: #666; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests FTP configuration</span>
                </label>
            </div>
            
            <div style="margin-top: 1.5rem; display: flex; gap: 1rem;">
                <button onclick="window.startAttackSimulation(this.parentElement.parentElement.parentElement)" class="btn btn-danger" style="flex: 1;">
                    ⚔️ Start Attack Simulation
                </button>
                <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn btn-secondary" style="flex: 1;">
                    Cancel
                </button>
            </div>
        </div>
    `;
    
    dialog.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
    `;
    
    document.body.appendChild(dialog);
    console.log('✅ Attack simulation dialog displayed');
}

async function startAttackSimulation(dialogElement) {
    console.log(`startAttackSimulation called with scanId: ${scanId}`);
    
    if (!scanId) {
        alert('Error: No scan ID available');
        console.error('Cannot start attack: scanId is null/undefined');
        return;
    }
    
    // Get selected attack types
    const checkboxes = dialogElement.querySelectorAll('input[type="checkbox"]:checked');
    const attackTypes = Array.from(checkboxes).map(cb => cb.value);
    
    console.log('Selected attack types:', attackTypes);
    
    if (attackTypes.length === 0) {
        alert('Please select at least one attack type');
        return;
    }
    
    // Close dialog
    dialogElement.remove();
    
    // Show progress
    const container = document.getElementById('attack-simulation-container');
    if (container) {
        container.innerHTML = `
            <div class="card" style="margin-bottom: 2rem;">
                <div style="padding: 1.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px;">
                    <h3 style="margin: 0 0 1rem 0; color: white;">⚔️ Attack Simulation in Progress</h3>
                    <p style="margin: 0.5rem 0;">Running ${attackTypes.length} attack simulation(s)</p>
                    <p style="margin: 0.5rem 0;">Scan ID: ${scanId}</p>
                    <p style="margin: 0.5rem 0;">Attack types: ${attackTypes.join(', ')}</p>
                    <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">⏱️ Checking for results...</p>
                    <div class="spinner" style="margin-top: 1rem;"></div>
                </div>
            </div>
        `;
    }
    
    try {
        console.log(`Sending attack simulation request to: ${API_URL}/scans/${scanId}/simulate-attacks`);
        
        const response = await fetch(`${API_URL}/scans/${scanId}/simulate-attacks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_types: attackTypes })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('✅ Attack simulation started:', data);
            
            if (container) {
                container.innerHTML = `
                    <div class="card" style="margin-bottom: 2rem;">
                        <div style="padding: 1.5rem; background: #d4edda; border-left: 4px solid #28a745; border-radius: 4px;">
                            <h3 style="margin: 0 0 0.5rem 0; color: #155724;">✅ Attack Simulation Running</h3>
                            <p style="margin: 0.5rem 0; color: #155724;">${data.message || 'Attack simulation is running'}</p>
                            <p style="margin: 0.5rem 0 0 0; color: #155724;">⏳ Loading results...</p>
                        </div>
                    </div>
                `;
            }
            
            // IMPROVED: Poll multiple times at shorter intervals
            // Try immediately, then after 2s, 5s, 10s, 15s
            pollAttackResults(0);
            
        } else {
            throw new Error(data.error || 'Attack simulation request failed');
        }
        
    } catch (error) {
        console.error('❌ Attack simulation error:', error);
        
        if (container) {
            container.innerHTML = `
                <div class="card" style="margin-bottom: 2rem;">
                    <div style="padding: 1.5rem; background: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;">
                        <h3 style="margin: 0 0 0.5rem 0; color: #721c24;">❌ Attack Simulation Error</h3>
                        <p style="margin: 0; color: #721c24;">${error.message}</p>
                    </div>
                </div>
            `;
        }
    }
}

// NEW: Improved polling function
let pollAttempts = 0;
const maxPollAttempts = 10;

function pollAttackResults(delay) {
    setTimeout(async () => {
        pollAttempts++;
        console.log(`Poll attempt ${pollAttempts}/${maxPollAttempts}`);
        
        try {
            const response = await fetch(`${API_URL}/scans/${scanId}/attack-results`);
            const data = await response.json();
            
            if (data.results && data.results.length > 0) {
                console.log(`✅ Found ${data.results.length} attack results`);
                displayAttackResults(data.results);
                pollAttempts = 0; // Reset for next time
            } else {
                console.log('No results yet...');
                
                // Keep polling if we haven't exceeded max attempts
                if (pollAttempts < maxPollAttempts) {
                    // Exponential backoff: 2s, 2s, 3s, 5s, 5s, 5s...
                    const nextDelay = pollAttempts < 3 ? 2000 : 5000;
                    pollAttackResults(nextDelay);
                } else {
                    // Give up after max attempts
                    console.warn('Max poll attempts reached');
                    const container = document.getElementById('attack-simulation-container');
                    if (container) {
                        container.innerHTML = `
                            <div class="card" style="margin-bottom: 2rem;">
                                <div style="padding: 1.5rem; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                                    <h3 style="margin: 0 0 0.5rem 0; color: #856404;">⚠️ Results Not Found</h3>
                                    <p style="margin: 0; color: #856404;">Attack simulation may still be running. Refresh the page in a moment.</p>
                                </div>
                            </div>
                        `;
                    }
                    pollAttempts = 0;
                }
            }
        } catch (error) {
            console.error('Error polling results:', error);
            
            // Retry on error
            if (pollAttempts < maxPollAttempts) {
                pollAttackResults(3000);
            }
        }
    }, delay);
}

// Keep the old function for backward compatibility
async function loadAttackResults() {
    console.log(`Loading attack results for scan ${scanId}`);
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}/attack-results`);
        const data = await response.json();
        
        if (data.results && data.results.length > 0) {
            console.log(`✅ Loaded ${data.results.length} attack results`);
            displayAttackResults(data.results);
        } else {
            console.log('No attack results found yet');
        }
    } catch (error) {
        console.error('❌ Error loading attack results:', error);
    }
}

// async function loadAttackResults() {
//     console.log(`Loading attack results for scan ${scanId}`);
    
//     try {
//         const response = await fetch(`${API_URL}/scans/${scanId}/attack-results`);
//         const data = await response.json();
        
//         if (data.results && data.results.length > 0) {
//             console.log(`✅ Loaded ${data.results.length} attack results`);
//             displayAttackResults(data.results);
//         } else {
//             console.log('No attack results found yet');
//         }
//     } catch (error) {
//         console.error('❌ Error loading attack results:', error);
//     }
// }

async function downloadAttackReport() {
    console.log(`Generating attack report PDF for scan ${scanId}`);
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}/attack-report/pdf`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok && data.filename) {
            console.log(`✅ Attack report generated: ${data.filename}`);
            
            // Download the report
            const downloadUrl = `${API_URL}/reports/${data.filename}`;
            window.location.href = downloadUrl;
            
            // Show success message
            alert('✅ Attack report PDF generated successfully!');
        } else {
            throw new Error(data.error || 'Failed to generate report');
        }
    } catch (error) {
        console.error(`❌ Error generating attack report:`, error);
        alert(`Error generating attack report:\n\n${error.message}`);
    }
}

// Make globally available
window.downloadAttackReport = downloadAttackReport;


function displayAttackResults(results) {
    const container = document.getElementById('attack-results-container');
    if (!container) {
        console.error('Attack results container not found');
        return;
    }
    
    // Clear the "in progress" message
    const progressContainer = document.getElementById('attack-simulation-container');
    if (progressContainer) {
        progressContainer.innerHTML = '';
    }
    
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    let html = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin: 2rem 0 1rem 0;">
            <h3 style="margin: 0; color: #333;">📊 Attack Simulation Results (${results.length} tests)</h3>
            <div style="display: flex; gap: 0.5rem;">
                <button onclick="downloadAttackReport()" class="btn btn-primary">
                    📥 Download PDF Report
                </button>
                <button onclick="deleteAllAttackResults()" class="btn btn-danger">
                    🗑️ Delete All Results
                </button>
            </div>
        </div>
    `;
    
    // Calculate summary
    let vulnerableCount = 0;
    let validResults = [];
    
    // Pre-process results to handle JSON parsing
    results.forEach(result => {
        try {
            let resultData;
            if (typeof result.result === 'string') {
                resultData = JSON.parse(result.result);
            } else {
                resultData = result.result;
            }
            
            validResults.push({
                ...result,
                parsedData: resultData
            });
            
            if (result.vulnerable) {
                vulnerableCount++;
            }
        } catch (e) {
            console.error('⚠️ Error parsing result:', e, result);
            validResults.push({
                ...result,
                parsedData: { 
                    error: 'Failed to parse result',
                    raw: result.result 
                }
            });
        }
    });
    
    const secureCount = validResults.length - vulnerableCount;
    const securityScore = validResults.length > 0 ? Math.round((secureCount / validResults.length) * 100) : 0;
    
    // Add summary card
    html += `
        <div class="card" style="margin-bottom: 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <div style="padding: 1.5rem;">
                <h3 style="margin: 0 0 1rem 0; color: white;">Security Assessment Summary</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold;">${validResults.length}</div>
                        <div style="opacity: 0.9;">Total Tests</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold; color: #ffc107;">${vulnerableCount}</div>
                        <div style="opacity: 0.9;">Vulnerable</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold; color: #4caf50;">${secureCount}</div>
                        <div style="opacity: 0.9;">Secure</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold;">${securityScore}%</div>
                        <div style="opacity: 0.9;">Security Score</div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Display each result
    validResults.forEach((result, index) => {
        const resultData = result.parsedData;
        const borderColor = result.vulnerable ? '#dc3545' : '#28a745';
        const bgColor = result.vulnerable ? '#f8d7da' : '#d4edda';
        const textColor = result.vulnerable ? '#721c24' : '#155724';
        const icon = result.vulnerable ? '❌' : '✅';
        
        html += `
            <div class="card" style="margin-bottom: 1.5rem; border-left: 4px solid ${borderColor};">
                <div style="padding: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                        <h4 style="margin: 0; color: #333;">${icon} ${result.attack_type}</h4>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            ${result.severity ? `<span class="severity-badge ${result.severity.toLowerCase()}">${result.severity}</span>` : ''}
                            <button onclick="deleteAttackResult(${result.id})" class="btn btn-danger btn-small" title="Delete this result">
                                Delete
                            </button>
                        </div>
                    </div>
                    
                    <div style="background: ${bgColor}; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
                        <p style="margin: 0; color: ${textColor}; font-weight: 600;">
                            ${result.vulnerable ? '❌ VULNERABLE - Security Issue Detected' : '✅ SECURE - No Issues Found'}
                        </p>
                    </div>
                    
                    <div style="margin-bottom: 1rem;">
                        <p style="margin: 0.5rem 0;"><strong>🎯 Target:</strong> ${resultData.target || 'N/A'}</p>
                        <p style="margin: 0.5rem 0;"><strong>🕐 Timestamp:</strong> ${new Date(result.timestamp).toLocaleString()}</p>
                        ${resultData.verdict ? `<p style="margin: 0.5rem 0;"><strong>📋 Verdict:</strong> ${resultData.verdict}</p>` : ''}
                        ${resultData.scan_duration ? `<p style="margin: 0.5rem 0;"><strong>⏱️ Duration:</strong> ${resultData.scan_duration}</p>` : ''}
                        ${resultData.ports_scanned ? `<p style="margin: 0.5rem 0;"><strong>🔌 Ports Scanned:</strong> ${resultData.ports_scanned}</p>` : ''}
                        ${resultData.scan_rate ? `<p style="margin: 0.5rem 0;"><strong>⚡ Scan Rate:</strong> ${resultData.scan_rate}</p>` : ''}
                    </div>
                    
                    ${resultData.recommendation ? `
                        <div style="background: #e7f3ff; padding: 0.75rem; border-left: 3px solid #2196f3; margin-top: 1rem; border-radius: 4px;">
                            <strong>💡 Recommendation:</strong>
                            <p style="margin: 0.5rem 0 0 0;">${resultData.recommendation}</p>
                        </div>
                    ` : ''}
                    
                    ${resultData.error ? `
                        <div style="background: #fff3cd; padding: 0.75rem; border-left: 3px solid #ffc107; margin-top: 1rem; border-radius: 4px;">
                            <strong>⚠️ Error:</strong>
                            <p style="margin: 0.5rem 0 0 0; color: #856404;">${resultData.error}</p>
                        </div>
                    ` : ''}
                    
                    <details style="margin-top: 1rem;">
                        <summary style="cursor: pointer; color: #667eea; font-weight: 600; padding: 0.5rem 0;">
                            📋 View Full Technical Details
                        </summary>
                        <pre style="background: #f8f9fa; padding: 1rem; margin-top: 0.5rem; overflow-x: auto; border-radius: 4px; font-size: 0.85rem; border: 1px solid #dee2e6;">${JSON.stringify(resultData, null, 2)}</pre>
                    </details>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
    console.log('✅ Attack results displayed successfully');
}

// Delete all attack results for current scan
async function deleteAllAttackResults() {
    // Confirmation dialog
    const confirmed = confirm(
        '⚠️ Delete All Attack Results?\n\n' +
        'This will permanently delete ALL attack simulation results for this scan.\n\n' +
        'This action cannot be undone!\n\n' +
        'Are you sure you want to continue?'
    );
    
    if (!confirmed) {
        return;
    }
    
    try {
        console.log(`Deleting all attack results for scan ${scanId}`);
        
        const response = await fetch(`${API_URL}/scans/${scanId}/attack-results`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log(`✅ Deleted ${data.deleted_count} attack results`);
            
            // Hide results container
            const container = document.getElementById('attack-results-container');
            if (container) {
                container.style.display = 'none';
                container.innerHTML = '';
            }
            
            // Show success message
            const simContainer = document.getElementById('attack-simulation-container');
            if (simContainer) {
                simContainer.innerHTML = `
                    <div class="card" style="margin-bottom: 2rem;">
                        <div style="padding: 1.5rem; background: #d4edda; border-left: 4px solid #28a745; border-radius: 4px;">
                            <h3 style="margin: 0 0 0.5rem 0; color: #155724;">✅ Results Deleted</h3>
                            <p style="margin: 0; color: #155724;">
                                Successfully deleted ${data.deleted_count} attack simulation result(s).
                            </p>
                        </div>
                    </div>
                `;
            }
            
            // Show alert
            alert(`✅ Successfully deleted ${data.deleted_count} attack result(s)`);
            
        } else {
            throw new Error(data.error || 'Failed to delete attack results');
        }
        
    } catch (error) {
        console.error('❌ Error deleting attack results:', error);
        alert(`❌ Error deleting attack results:\n\n${error.message}`);
    }
}

// Delete single attack result
async function deleteAttackResult(resultId) {
    // Confirmation dialog
    const confirmed = confirm(
        '⚠️ Delete This Attack Result?\n\n' +
        'This will permanently delete this attack simulation result.\n\n' +
        'Are you sure?'
    );
    
    if (!confirmed) {
        return;
    }
    
    try {
        console.log(`Deleting attack result ${resultId}`);
        
        const response = await fetch(`${API_URL}/attack-results/${resultId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log(`✅ Deleted attack result ${resultId}`);
            
            // Reload attack results to refresh the display
            await loadAttackResults();
            
            // Show success message
            alert('✅ Attack result deleted successfully');
            
        } else {
            throw new Error(data.error || 'Failed to delete attack result');
        }
        
    } catch (error) {
        console.error('❌ Error deleting attack result:', error);
        alert(`❌ Error deleting attack result:\n\n${error.message}`);
    }
}

// Make functions globally available
window.deleteAllAttackResults = deleteAllAttackResults;
window.deleteAttackResult = deleteAttackResult;


// Set up event listener when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    const simulateBtn = document.getElementById('simulate-attacks-btn');
    if (simulateBtn) {
        console.log('✅ Attack simulation button found, adding listener');
        simulateBtn.addEventListener('click', showAttackSimulationDialog);
    } else {
        console.warn('⚠️ Attack simulation button NOT found in DOM');
    }
});

// Make functions globally available
window.showAttackSimulationDialog = showAttackSimulationDialog;
window.startAttackSimulation = startAttackSimulation;

async function testLoadResults() {
    console.log('TEST: Manually loading results...');
    
    const response = await fetch(`${API_URL}/scans/${scanId}/attack-results`);
    const data = await response.json();
    
    console.log('TEST: Response data:', data);
    console.log('TEST: Results count:', data.results?.length || 0);
    
    if (data.results && data.results.length > 0) {
        alert(`Found ${data.results.length} results!`);
        displayAttackResults(data.results);
    } else {
        alert('No results found in database');
    }
}

window.testLoadResults = testLoadResults;