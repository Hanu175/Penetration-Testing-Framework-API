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
        
        console.log(' Scan details loaded successfully');
        
    } catch (error) {
        console.error(' Error loading scan:', error);
        
        if (loadingState) loadingState.style.display = 'none';
        if (content) {
            content.innerHTML = `
                <div class="alert alert-danger">
                    <strong>[FAIL] Error Loading Scan</strong>
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
    header.style.color = '#e6eef6';
    header.innerHTML = `[${severity.toUpperCase()}] Severity (${vulnerabilities.length})`;
    section.appendChild(header);
    
    // Vulnerability cards
    vulnerabilities.forEach(vuln => {
        const card = createVulnerabilityCard(vuln);
        section.appendChild(card);
    });
    
    return section;
}

// Create vulnerability card
function createVulnerabilityCard(vuln) {
    const card = document.createElement('div');
    card.className = 'vulnerability-card';
    card.style.marginBottom = '1rem';
    card.style.borderLeft = `4px solid ${getSeverityColor(vuln.severity)}`;
    
    card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem; gap: 1rem;">
            <div style="flex: 1;">
                <h4 style="margin: 0 0 0.5rem 0; color: #e6eef6;">
                    ${vuln.cve_id || 'Unknown CVE'}
                </h4>
                <div style="color: #b8c6d4; font-size: 0.9rem;">
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
                    TEST EXPLOIT
                </button>
                ` : ''}
            </div>
        </div>
        
        <div style="margin-bottom: 1rem;">
            <strong style="color: #e6eef6;">Description:</strong>
            <p style="margin: 0.5rem 0; color: #b8c6d4;">${vuln.description || 'No description available'}</p>
        </div>
        
        ${vuln.remediation ? `
            <div style="background: #141c28; padding: 1rem; border-radius: 2px; margin-bottom: 1rem; border-left: 3px solid #00ff88;">
                <strong style="color: #00ff88;">[FIX] Remediation:</strong>
                <p style="margin: 0.5rem 0 0 0; color: #b8c6d4;">${vuln.remediation}</p>
            </div>
        ` : ''}
        
        ${vuln.references ? `
            <details style="margin-top: 1rem;">
                <summary style="cursor: pointer; color: #00ff88; font-weight: 500;">
                    [REF] References
                </summary>
                <div style="margin-top: 0.5rem; padding-left: 1rem;">
                    ${vuln.references.split(',').map(ref => 
                        `<a href="${ref.trim()}" target="_blank" style="display: block; color: #00ff88; margin: 0.25rem 0;">${ref.trim()}</a>`
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

function getSeverityColor(severity) {
    const colorMap = {
        'critical': '#ff3b4e',
        'high': '#ffb020',
        'medium': '#ffd04b',
        'low': '#00ff88'
    };
    return colorMap[severity.toLowerCase()] || '#6b7a8c';
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
        btn.innerHTML = '>_ Generating...';
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
            alert(`[OK] ${reportType.toUpperCase()} report downloaded successfully!`);
        } else {
            alert(`[FAIL] Error: ${data.error}`);
        }
        
        // Restore button
        btn.innerHTML = originalText;
        btn.disabled = false;
        
    } catch (error) {
        console.error('Error generating report:', error);
        alert('[FAIL] Failed to generate report. Make sure the API server is running.');
        
        // Restore button
        const btn = document.getElementById('download-btn');
        btn.innerHTML = '>_ Download Report';
        btn.disabled = false;
    }
}

// ==================== EXPLOITATION FUNCTIONS ====================

// Test exploitation of a vulnerability
async function testExploit(vulnId, cveId) {
    // First confirmation with strong warnings
    const confirmed = confirm(
        `[!] CRITICAL WARNING\n\n` +
        `You are about to attempt REAL EXPLOITATION of:\n` +
        `${cveId}\n\n` +
        `This will:\n` +
        `- Execute actual exploit code against the target\n` +
        `- Attempt to compromise the system\n` +
        `- May cause system instability or crashes\n` +
        `- All activity will be logged\n\n` +
        `LEGAL REQUIREMENTS:\n` +
        `- You MUST own this system, OR\n` +
        `- Have WRITTEN authorization to test it\n\n` +
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
        `- I have authorization to test this system\n` +
        `- I understand the legal implications\n` +
        `- I accept full responsibility\n\n` +
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
            <strong>[..] Exploitation in Progress...</strong>
            <p>[*] Searching Metasploit database for matching exploit module...</p>
            <p>[*] Configuring target parameters and payload...</p>
            <p>[*] Executing exploit against target system...</p>
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
                <strong>[+] EXPLOITATION SUCCESSFUL!</strong>
                <p style="margin: 0.5rem 0;"><strong>Session Created:</strong> #${result.session_id}</p>
                <p style="margin: 0.5rem 0;"><strong>Session Type:</strong> ${result.session_type}</p>
                <p style="margin: 0.5rem 0;"><strong>Exploit Used:</strong> ${result.exploit_used}</p>
                <p style="margin: 0.5rem 0;"><strong>Message:</strong> ${result.message}</p>
                <div style="margin-top: 1rem; padding: 1rem; background: rgba(255, 176, 32, 0.06); border-left: 4px solid #ffb020; border-radius: 2px;">
                    <strong style="color: #ffb020;">[!] What This Means:</strong>
                    <p style="margin: 0.5rem 0 0 0;">You now have remote access to the target system. This proves the vulnerability is real and exploitable. Document this finding and close the session when done testing.</p>
                </div>
                <div style="margin-top: 1rem;">
                    <button onclick="viewSessions()" class="btn btn-primary btn-small">
                        VIEW SESSIONS
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
                <strong>[-] Exploitation Failed</strong>
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
                <div style="margin-top: 1rem; padding: 1rem; background: rgba(0, 255, 136, 0.06); border-left: 4px solid #00ff88; border-radius: 2px;">
                    <strong style="color: #00ff88;">[+] Good News:</strong>
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
            <strong>[FAIL] Error</strong>
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
                <strong style="font-size: 1.2rem; color: #00ff88;">${port.port}</strong>
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
        button.textContent = '[+] TABLE VIEW';
        portsViewMode = 'cards';
    } else {
        // Switch to table
        table.style.display = 'block';
        cards.style.display = 'none';
        button.textContent = '[+] CARD VIEW';
        portsViewMode = 'table';
    }
});

// Make port rows clickable to show full details
function createPortRow(port) {
    const row = document.createElement('tr');
    row.style.cursor = 'pointer';
    
    row.innerHTML = `
        <td><strong style="font-size: 1.2rem; color: #00ff88;">${port.port}</strong></td>
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
        <div class="modal-content" style="max-width: 600px; padding: 2rem; position: relative;">
            <button onclick="this.parentElement.parentElement.remove()" style="position: absolute; top: 1rem; right: 1rem; border: none; background: none; font-size: 1.2rem; cursor: pointer; color: #00ff88;">[x]</button>
            
            <h2 style="color: #00ff88; margin-bottom: 1rem;">Port ${port.port} Details</h2>
            
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
            
            <div style="margin-top: 1.5rem; padding: 1rem; background: #141c28; border-radius: 2px;">
                <strong>Security Note:</strong>
                <p style="margin-top: 0.5rem; color: #b8c6d4; font-size: 0.9rem;">
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
            <h2 style="color: #ff3b4e; margin-bottom: 1rem;">[!] Attack Simulation Warning</h2>
            
            <div style="background: rgba(255, 176, 32, 0.06); padding: 1rem; border-radius: 2px; margin-bottom: 1rem; border-left: 3px solid #ffb020;">
                <strong style="color: #ffb020;">[!] CRITICAL WARNING</strong>
                <p style="margin: 0.5rem 0;">This will perform REAL attacks on the target system!</p>
                <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                    <li>SQL Injection attempts</li>
                    <li>XSS injection attempts</li>
                    <li>Directory traversal attacks</li>
                    <li>Bruteforce attempts</li>
                    <li>Service enumeration</li>
                </ul>
                <p style="margin: 0.5rem 0 0 0; color: #ffb020;">
                    <strong>ONLY use on systems you own or have written authorization to test!</strong>
                </p>
            </div>
            
            <h3 style="margin-top: 1.5rem; color: #e6eef6;">[*] Select Attack Types:</h3>
            
            <div style="margin: 1rem 0; max-height: 300px; overflow-y: auto;">
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="port_scan_detection" checked> 
                    <strong>Port Scan Detection Test</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests if rapid scanning triggers IDS/IPS</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="sql_injection"> 
                    <strong>SQL Injection Test</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests database security with common SQL payloads</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="xss"> 
                    <strong>Cross-Site Scripting (XSS)</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests input sanitization with JavaScript payloads</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="directory_traversal"> 
                    <strong>Directory Traversal</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests file access controls</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="http_methods"> 
                    <strong>HTTP Methods Test</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Checks for dangerous HTTP methods (PUT, DELETE)</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="directory_bruteforce"> 
                    <strong>Directory Bruteforce</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Discovers hidden directories</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="ssh_bruteforce"> 
                    <strong>SSH Bruteforce Test</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests SSH with common credentials</span>
                </label>
                
                <label style="display: block; margin: 0.5rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px; cursor: pointer;">
                    <input type="checkbox" value="ftp_anonymous"> 
                    <strong>FTP Anonymous Access</strong>
                    <span style="color: #b8c6d4; font-size: 0.9rem; display: block; margin-left: 1.5rem;">Tests FTP configuration</span>
                </label>
            </div>
            
            <div style="margin-top: 1.5rem; display: flex; gap: 1rem;">
                <button onclick="window.startAttackSimulation(this.parentElement.parentElement.parentElement)" class="btn btn-danger" style="flex: 1;">
                    [&gt;] START ATTACK SIMULATION
                </button>
                <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn btn-secondary" style="flex: 1;">
                    [x] CANCEL
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
    console.log(' Attack simulation dialog displayed');
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
                <div style="padding: 1.5rem; background: linear-gradient(135deg, #0e141d 0%, #1a2432 100%); border: 1px solid #ffb020; border-radius: 2px;">
                    <h3 style="margin: 0 0 1rem 0; color: #ffb020;">[..] Attack Simulation in Progress</h3>
                    <p style="margin: 0.5rem 0;">[*] Running ${attackTypes.length} attack simulation(s)</p>
                    <p style="margin: 0.5rem 0;">[*] Scan ID: ${scanId}</p>
                    <p style="margin: 0.5rem 0;">[*] Attack types: ${attackTypes.join(', ')}</p>
                    <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">[*] Checking for results...</p>
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
            console.log(' Attack simulation started:', data);
            
            if (container) {
                container.innerHTML = `
                    <div class="card" style="margin-bottom: 2rem;">
                        <div style="padding: 1.5rem; background: rgba(0, 255, 136, 0.06); border-left: 4px solid #00ff88; border-radius: 2px;">
                            <h3 style="margin: 0 0 0.5rem 0; color: #00ff88;">[+] Attack Simulation Running</h3>
                            <p style="margin: 0.5rem 0; color: #00ff88;">${data.message || 'Attack simulation is running'}</p>
                            <p style="margin: 0.5rem 0 0 0; color: #00ff88;">[*] Loading results...</p>
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
        console.error(' Attack simulation error:', error);
        
        if (container) {
            container.innerHTML = `
                <div class="card" style="margin-bottom: 2rem;">
                    <div style="padding: 1.5rem; background: rgba(255, 59, 78, 0.06); border-left: 4px solid #ff3b4e; border-radius: 2px;">
                        <h3 style="margin: 0 0 0.5rem 0; color: #ff3b4e;">[FAIL] Attack Simulation Error</h3>
                        <p style="margin: 0; color: #ff3b4e;">${error.message}</p>
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
                console.log(` Found ${data.results.length} attack results`);
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
                                <div style="padding: 1.5rem; background: rgba(255, 176, 32, 0.06); border-left: 4px solid #ffb020; border-radius: 2px;">
                                    <h3 style="margin: 0 0 0.5rem 0; color: #ffb020;">[!] Results Not Found</h3>
                                    <p style="margin: 0; color: #ffb020;">Attack simulation may still be running. Refresh the page in a moment.</p>
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
            console.log(` Loaded ${data.results.length} attack results`);
            displayAttackResults(data.results);
        } else {
            console.log('No attack results found yet');
        }
    } catch (error) {
        console.error(' Error loading attack results:', error);
    }
}


async function downloadAttackReport() {
    console.log(`Generating attack report PDF for scan ${scanId}`);
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}/attack-report/pdf`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok && data.filename) {
            console.log(` Attack report generated: ${data.filename}`);
            
            // Download the report
            const downloadUrl = `${API_URL}/reports/${data.filename}`;
            window.location.href = downloadUrl;
            
            // Show success message
            alert('[OK] Attack report PDF generated successfully!');
        } else {
            throw new Error(data.error || 'Failed to generate report');
        }
    } catch (error) {
        console.error(` Error generating attack report:`, error);
        alert(`Error generating attack report:\n\n${error.message}`);
    }
}

// Make globally available
window.downloadAttackReport = downloadAttackReport;

async function downloadUnifiedReport() {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Generating...';
    btn.disabled = true;

    try {
        const response = await fetch(
            `${API_URL}/scans/${scanId}/unified-report/pdf`,
            { method: 'POST' }
        );

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Failed to generate report');
        }

        // Trigger browser download
        const blob = await response.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `pentest_report_scan${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        alert('[OK] Unified PDF report downloaded successfully!');

    } catch (error) {
        console.error('Report error:', error);
        alert(`[FAIL] Error: ${error.message}`);
    } finally {
        btn.textContent = orig;
        btn.disabled = false;
    }
}

window.downloadUnifiedReport = downloadUnifiedReport;



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
    
    let html = '';

        html += `
            <div style="display:flex; justify-content:space-between; align-items:center; margin:2rem 0 1rem 0;">
                <h3 style="margin:0; color:#e6eef6;">
                    [*] Attack Simulation Results (${results.length} tests)
                </h3>
                <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                    <button onclick="downloadUnifiedReport()" class="btn btn-primary">
                        Download Full PDF Report
                    </button>
                    <button onclick="downloadAttackReport()" class="btn btn-secondary">
                        Attacks Only PDF
                    </button>
                    <button onclick="deleteAllAttackResults()" class="btn btn-danger">
                        Delete All Results
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
            console.error(' Error parsing result:', e, result);
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
        <div class="card" style="margin-bottom: 2rem; background: linear-gradient(135deg, #0e141d 0%, #1a2432 100%);">
            <div style="padding: 1.5rem;">
                <h3 style="margin: 0 0 1rem 0; color: #00ff88; text-transform: uppercase; letter-spacing: 1px;">Security Assessment Summary</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold; color: #e6eef6;">${validResults.length}</div>
                        <div style="opacity: 0.9;">Total Tests</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold; color: #ff3b4e;">${vulnerableCount}</div>
                        <div style="opacity: 0.9;">Vulnerable</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold; color: #00ff88;">${secureCount}</div>
                        <div style="opacity: 0.9;">Secure</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; font-weight: bold; color: #ffb020;">${securityScore}%</div>
                        <div style="opacity: 0.9;">Security Score</div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Display each result
    validResults.forEach((result, index) => {
        const resultData = result.parsedData;
        const borderColor = result.vulnerable ? '#ff3b4e' : '#00ff88';
        const bgColor = result.vulnerable ? 'rgba(255, 59, 78, 0.06)' : 'rgba(0, 255, 136, 0.06)';
        const textColor = result.vulnerable ? '#ff3b4e' : '#00ff88';
        const icon = result.vulnerable ? '[!]' : '[+]';
        
        html += `
            <div class="card" style="margin-bottom: 1.5rem; border-left: 4px solid ${borderColor};">
                <div style="padding: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                        <h4 style="margin: 0; color: #e6eef6;">${icon} ${result.attack_type}</h4>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            ${result.severity ? `<span class="severity-badge ${result.severity.toLowerCase()}">${result.severity}</span>` : ''}
                            <button onclick="deleteAttackResult(${result.id})" class="btn btn-danger btn-small" title="Delete this result">
                                DELETE
                            </button>
                        </div>
                    </div>
                    
                    <div style="background: ${bgColor}; padding: 0.75rem; border-radius: 2px; margin-bottom: 1rem;">
                        <p style="margin: 0; color: ${textColor}; font-weight: 600;">
                            ${result.vulnerable ? '[!] VULNERABLE - Security Issue Detected' : '[+] SECURE - No Issues Found'}
                        </p>
                    </div>
                    
                    <div style="margin-bottom: 1rem;">
                        <p style="margin: 0.5rem 0;"><strong>[*] Target:</strong> ${resultData.target || 'N/A'}</p>
                        <p style="margin: 0.5rem 0;"><strong>[*] Timestamp:</strong> ${new Date(result.timestamp).toLocaleString()}</p>
                        ${resultData.verdict ? `<p style="margin: 0.5rem 0;"><strong>[*] Verdict:</strong> ${resultData.verdict}</p>` : ''}
                        ${resultData.scan_duration ? `<p style="margin: 0.5rem 0;"><strong>[*] Duration:</strong> ${resultData.scan_duration}</p>` : ''}
                        ${resultData.ports_scanned ? `<p style="margin: 0.5rem 0;"><strong>[*] Ports Scanned:</strong> ${resultData.ports_scanned}</p>` : ''}
                        ${resultData.scan_rate ? `<p style="margin: 0.5rem 0;"><strong>[*] Scan Rate:</strong> ${resultData.scan_rate}</p>` : ''}
                    </div>
                    
                    ${resultData.recommendation ? `
                        <div style="background: rgba(0, 212, 255, 0.06); padding: 0.75rem; border-left: 3px solid #00d4ff; margin-top: 1rem; border-radius: 2px;">
                            <strong>[+] Recommendation:</strong>
                            <p style="margin: 0.5rem 0 0 0;">${resultData.recommendation}</p>
                        </div>
                    ` : ''}
                    
                    ${resultData.error ? `
                        <div style="background: rgba(255, 176, 32, 0.06); padding: 0.75rem; border-left: 3px solid #ffb020; margin-top: 1rem; border-radius: 2px;">
                            <strong style="color: #ffb020;">[!] Error:</strong>
                            <p style="margin: 0.5rem 0 0 0; color: #ffb020;">${resultData.error}</p>
                        </div>
                    ` : ''}
                    
                    <details style="margin-top: 1rem;">
                        <summary style="cursor: pointer; color: #00ff88; font-weight: 600; padding: 0.5rem 0;">
                            [~] View Full Technical Details
                        </summary>
                        <pre style="background: #141c28; padding: 1rem; margin-top: 0.5rem; overflow-x: auto; border-radius: 2px; font-size: 0.85rem; border: 1px solid #2c3d52; color: #b8c6d4;">${JSON.stringify(resultData, null, 2)}</pre>
                    </details>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
    console.log(' Attack results displayed successfully');
}

// Delete all attack results for current scan
async function deleteAllAttackResults() {
    // Confirmation dialog
    const confirmed = confirm(
        '[!] Delete All Attack Results?\n\n' +
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
            console.log(` Deleted ${data.deleted_count} attack results`);
            
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
                        <div style="padding: 1.5rem; background: rgba(0, 255, 136, 0.06); border-left: 4px solid #00ff88; border-radius: 2px;">
                            <h3 style="margin: 0 0 0.5rem 0; color: #00ff88;">[+] Results Deleted</h3>
                            <p style="margin: 0; color: #00ff88;">
                                Successfully deleted ${data.deleted_count} attack simulation result(s).
                            </p>
                        </div>
                    </div>
                `;
            }
            
            // Show alert
            alert(`[OK] Successfully deleted ${data.deleted_count} attack result(s)`);
            
        } else {
            throw new Error(data.error || 'Failed to delete attack results');
        }
        
    } catch (error) {
        console.error(' Error deleting attack results:', error);
        alert(`[FAIL] Error deleting attack results:\n\n${error.message}`);
    }
}

// Delete single attack result
async function deleteAttackResult(resultId) {
    // Confirmation dialog
    const confirmed = confirm(
        '[!] Delete This Attack Result?\n\n' +
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
            console.log(` Deleted attack result ${resultId}`);
            
            // Reload attack results to refresh the display
            await loadAttackResults();
            
            // Show success message
            alert('[OK] Attack result deleted successfully');
            
        } else {
            throw new Error(data.error || 'Failed to delete attack result');
        }
        
    } catch (error) {
        console.error(' Error deleting attack result:', error);
        alert(`[FAIL] Error deleting attack result:\n\n${error.message}`);
    }
}

// Make functions globally available
window.deleteAllAttackResults = deleteAllAttackResults;
window.deleteAttackResult = deleteAttackResult;


// Set up event listener when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    const simulateBtn = document.getElementById('simulate-attacks-btn');
    if (simulateBtn) {
        console.log(' Attack simulation button found, adding listener');
        simulateBtn.addEventListener('click', showAttackSimulationDialog);
    } else {
        console.warn(' Attack simulation button NOT found in DOM');
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

// ==================== HASHCAT FUNCTIONS ====================

function showHashcatDialog() {
    console.log(`showHashcatDialog called with scanId: ${scanId}`);
    
    if (!scanId) {
        alert('Error: No scan ID available for Hashcat');
        return;
    }
    
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.innerHTML = `
        <div class="modal-content" style="max-width: 700px;">
            <h2 style="color: #ff3b4e; margin-bottom: 1rem;">[HASHCAT] Password Hash Cracking</h2>
            
            <div style="color: #ff3b4e; background: rgba(255, 176, 32, 0.06); padding: 1rem; border-left: 3px solid #ffb020; border-radius: 2px; margin-bottom: 1rem;">
                <strong>[!] LEGAL WARNING</strong>
                <p style="margin: 0.5rem 0;">This will attempt to crack password hashes using GPU acceleration!</p>
                <p style="margin: 0.5rem 0 0 0; color: #ffb020;">
                    <strong>Only crack hashes from authorized security assessments!</strong>
                </p>
            </div>
            
            <h3 style="color: #ff3b4e; margin-top: 1.5rem;">[+] Password Hashes:</h3>
            <h4 style="color: #ff3b4e; font-size: 0.9rem; margin: 0.5rem 0;">Enter one hash per line</h4>
            <textarea id="hashcat-hashes" class="form-input" rows="5" 
                      placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;e10adc3949ba59abbe56e057f20f883e&#10;098f6bcd4621d373cade4e832627b4f6"
                      style="width: 100%; padding: 0.75rem; border: 1px solid #2c3d52; border-radius: 2px; margin-bottom: 1rem; font-family: monospace; font-size: 0.9rem;"></textarea>
            
            <h3 style="color: #ff3b4e; margin-top: 1rem;">[*] Hash Type:</h3>
            <select id="hashcat-type" class="form-input" style="width: 100%; padding: 0.75rem; border: 1px solid #2c3d52; border-radius: 2px; margin-bottom: 1rem;">
                <option value="0">MD5</option>
                <option value="100">SHA1</option>
                <option value="1400">SHA256</option>
                <option value="1700">SHA512</option>
                <option value="1000">NTLM (Windows)</option>
                <option value="3200">bcrypt</option>
                <option value="500">MD5 Crypt (Unix)</option>
                <option value="1800">sha512crypt (Unix)</option>
            </select>
            
            <h3 style="color: #ff3b4e; margin-top: 1rem;">[*] Attack Mode:</h3>
            <select id="hashcat-attack" class="form-input" style="width: 100%; padding: 0.75rem; border: 1px solid #2c3d52; border-radius: 2px; margin-bottom: 1rem;">
                <option value="0">Dictionary Attack (Fast, common passwords)</option>
                <option value="3">Bruteforce (Slow, tries all combinations)</option>
            </select>
            
            <div style="background: rgba(0, 212, 255, 0.06); padding: 1rem; border-radius: 2px; margin: 1rem 0;">
                <strong>NOTE:</strong>
                <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">
                    Dictionary attack uses a wordlist of common passwords (~100 passwords).
                    Bruteforce is much slower but tries all possible combinations.
                </p>
            </div>
            
            <div style="color: #ff3b4e; margin-top: 1.5rem; display: flex; gap: 1rem;">
                <button onclick="window.startHashcatCrack(this.parentElement.parentElement.parentElement)" class="btn btn-danger" style="flex: 1;">
                    [>] START CRACKING
                </button>
                <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn btn-secondary" style="flex: 1;">
                    [x] CANCEL
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
        overflow-y: auto;
    `;
    
    document.body.appendChild(dialog);
    console.log(' Hashcat dialog displayed');
}

async function startHashcatCrack(dialogElement) {
    console.log(`startHashcatCrack called with scanId: ${scanId}`);
    
    if (!scanId) {
        alert('Error: No scan ID available');
        return;
    }
    
    // Get input values
    const hashesText = document.getElementById('hashcat-hashes').value.trim();
    const hashType = parseInt(document.getElementById('hashcat-type').value);
    const attackMode = parseInt(document.getElementById('hashcat-attack').value);
    
    if (!hashesText) {
        alert('Please enter at least one password hash');
        return;
    }
    
    // Parse hashes (one per line)
    const hashes = hashesText.split('\n')
        .map(h => h.trim())
        .filter(h => h.length > 0);
    
    if (hashes.length === 0) {
        alert('Please enter valid password hashes');
        return;
    }
    
    // Close dialog
    if (dialogElement) dialogElement.remove();
    
    // Show progress
    const container = document.getElementById('hashcat-container');
    if (container) {
        container.innerHTML = `
            <div class="card" style="margin-bottom: 2rem;">
                <div style="padding: 1.5rem; background: linear-gradient(135deg, #0e141d 0%, #1a2432 100%); border-radius: 2px;">
                    <h3 style="margin: 0 0 1rem 0; color: #00ff88;">[>] Hashcat Cracking in Progress</h3>
                    <p style="margin: 0.5rem 0;">[*] Hashes: ${hashes.length}</p>
                    <p style="margin: 0.5rem 0;">[*] Hash Type: ${getHashTypeName(hashType)}</p>
                    <p style="margin: 0.5rem 0;">[*] Attack Mode: ${attackMode === 0 ? 'Dictionary' : 'Bruteforce'}</p>
                    <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">[*] This may take 1-5 minutes...</p>
                    <div class="spinner" style="margin-top: 1rem;"></div>
                </div>
            </div>
        `;
        container.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}/hashcat-crack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                hashes: hashes,
                hash_type: hashType,
                attack_mode: attackMode
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log(' Hashcat cracking started:', data);
            
            if (container) {
                container.innerHTML = `
                    <div class="card" style="margin-bottom: 2rem;">
                        <div style="padding: 1.5rem; background: rgba(0, 255, 136, 0.06); border-left: 4px solid #00ff88; border-radius: 2px;">
                            <h3 style="margin: 0 0 0.5rem 0; color: #00ff88;">[+] Hashcat Cracking Started</h3>
                            <p style="margin: 0.5rem 0; color: #00ff88;">[*] ${data.message || 'Cracking job is running in background'}</p>
                            <p style="margin: 0.5rem 0 0 0; color: #00ff88;">[*] Checking for results every 10 seconds...</p>
                        </div>
                    </div>
                `;
            }
            
            // Poll for results
            pollHashcatResults();
            
        } else {
            throw new Error(data.error || 'Hashcat request failed');
        }
        
    } catch (error) {
        console.error(' Hashcat error:', error);
        
        if (container) {
            container.innerHTML = `
                <div class="card" style="margin-bottom: 2rem;">
                    <div style="padding: 1.5rem; background: rgba(255, 59, 78, 0.06); border-left: 4px solid #ff3b4e; border-radius: 2px;">
                        <h3 style="margin: 0 0 0.5rem 0; color: #ff3b4e;">[-] Hashcat Error</h3>
                        <p style="margin: 0; color: #ff3b4e;">${error.message}</p>
                    </div>
                </div>
            `;
        }
    }
}

function getHashTypeName(type) {
    const types = {
        0: 'MD5',
        100: 'SHA1',
        1400: 'SHA256',
        1700: 'SHA512',
        1000: 'NTLM',
        3200: 'bcrypt',
        500: 'MD5 Crypt',
        1800: 'sha512crypt'
    };
    return types[type] || `Type ${type}`;
}
let hashcatPollAttempts = 0;
const maxHashcatPollAttempts = 30;

function pollHashcatResults() {
    setTimeout(async () => {
        hashcatPollAttempts++;
        console.log(`Hashcat poll attempt ${hashcatPollAttempts}/${maxHashcatPollAttempts}`);

        try {
            const response = await fetch(`${API_URL}/scans/${scanId}/hashcat-results`);
            const data = await response.json();

            console.log('Poll response:', data);

            // if (data.results && data.results.length > 0) {
            //     // Check if the latest result is done (not still running)
            //     // const latest = data.results[0];
            //     const latest = data.results[data.results.length - 1];
            //     const isDone = latest.status === 'success' ||
            //                    latest.status === 'no_cracks' ||
            //                    latest.status === 'error' ||
            //                    latest.status === 'timeout';

            //     if (isDone) {
            //         console.log('Hashcat job finished, displaying results');
            //         displayHashcatResults(data.results);
            //         hashcatPollAttempts = 0;
            //         return; // Stop polling
            //     }
            // }


            if (data.results) {
                console.log("Displaying results:", data.results);

                // ALWAYS render
                displayHashcatResults(data.results);

                // Use LAST item (latest)
                const latest = data.results[data.results.length - 1];

                const isDone = latest.status === 'success' ||
                            latest.status === 'no_cracks' ||
                            latest.status === 'error' ||
                            latest.status === 'timeout';

                if (isDone) {
                    console.log("Stopping polling, job finished");
                    hashcatPollAttempts = 0;
                    return;
                }
            }

            // Keep polling if not done
            if (hashcatPollAttempts < maxHashcatPollAttempts) {
                pollHashcatResults();
            } else {
                const container = document.getElementById('hashcat-container');
                if (container) {
                    container.innerHTML = `
                        <div style="padding:1rem; background:rgba(255, 176, 32, 0.06); border-left: 3px solid #ffb020; border-radius:2px;">
                            <strong>Hashcat taking longer than expected.</strong>
                            <button onclick="loadHashcatResults()" 
                                    style="margin-left:10px; padding:5px 10px; cursor:pointer;">
                                Refresh Results
                            </button>
                        </div>`;
                }
                hashcatPollAttempts = 0;
            }

        } catch (error) {
            console.error('Poll error:', error);
            if (hashcatPollAttempts < maxHashcatPollAttempts) {
                pollHashcatResults();
            }
        }
    }, 3000); // Poll every 3 seconds instead of 10
}

function displayHashcatResults(results) {
    const container = document.getElementById('hashcat-results-container');
    
    if (!container) {
        console.error('hashcat-results-container element not found');
        return;
    }
    
    if (!results || results.length === 0) {
        container.innerHTML = '<p style="color: #b8c6d4;">No password cracking jobs run yet.</p>';
        return;
    }
    
    let html = '';
    
    results.forEach((job, index) => {
        // Parse cracked_hashes if it's a string
        let crackedHashes = job.cracked_hashes;
        if (typeof crackedHashes === 'string') {
            try {
                crackedHashes = JSON.parse(crackedHashes);
            } catch(e) {
                crackedHashes = [];
            }
        }
        crackedHashes = crackedHashes || [];
        
        const success = job.status === 'success' && crackedHashes.length > 0;
        
        html += `
        <div style="border: 1px solid ${success ? '#00ff88' : '#ff3b4e'}; 
                    border-radius: 2px; padding: 15px; margin: 10px 0;
                    background: ${success ? 'rgba(0, 255, 136, 0.06)' : 'rgba(255, 59, 78, 0.06)'};">
            
            <h4 style="margin: 0 0 10px 0; color: ${success ? '#00ff88' : '#ff3b4e'};">
                ${success ? '[OK]' : '[FAIL]'} Password Cracking Job #${index + 1}
            </h4>
            
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold; width: 150px;">Status:</td>
                    <td style="padding: 4px 8px;">${job.status || 'unknown'}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold;">Hash Type:</td>
                    <td style="padding: 4px 8px;">${getHashTypeName(job.hash_type)}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold;">Total Hashes:</td>
                    <td style="padding: 4px 8px;">${job.hash_count || 0}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold;">Cracked:</td>
                    <td style="padding: 4px 8px; color: ${success ? '#00ff88' : '#ff3b4e'}; font-weight: bold;">
                        ${job.cracked_count || 0} / ${job.hash_count || 0}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold;">Started:</td>
                    <td style="padding: 4px 8px;">${job.started_at ? new Date(job.started_at).toLocaleString() : 'N/A'}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold;">Completed:</td>
                    <td style="padding: 4px 8px;">${job.completed_at ? new Date(job.completed_at).toLocaleString() : 'N/A'}</td>
                </tr>
                ${job.message ? `
                <tr>
                    <td style="padding: 4px 8px; font-weight: bold;">Message:</td>
                    <td style="padding: 4px 8px;">${job.message}</td>
                </tr>` : ''}
            </table>
            
            ${crackedHashes.length > 0 ? `
            <div style="margin-top: 15px; padding: 10px; 
                        background: rgba(0, 255, 136, 0.06); border-radius: 5px; border: 1px solid #00ff88;">
                <h5 style="margin: 0 0 10px 0; color: #00ff88;">
                    [OK] Cracked Passwords (${crackedHashes.length}):
                </h5>
                <table style="width: 100%; border-collapse: collapse; font-family: monospace; border: 1px solid #2c3d52;">
                    <tr style="background: #0e141d; color: #00ff88;">
                        <th style="padding: 6px 10px; text-align: left;">Hash</th>
                        <th style="padding: 6px 10px; text-align: left;">Password</th>
                    </tr>
                    ${crackedHashes.map((h, i) => `
                    <tr style="background: ${i % 2 === 0 ? '#10161f' : '#141c28'};">
                        <td style="padding: 6px 10px; font-size: 12px; color: #e6eef6;">
                            ${h.hash || 'N/A'}
                        </td>
                        <td style="padding: 6px 10px; font-weight: bold; color: #00ff88; font-size: 14px;">
                            ${h.password || 'N/A'}
                        </td>
                    </tr>`).join('')}
                </table>
            </div>` : `
            <div style="margin-top: 10px; padding: 10px; 
                        background: rgba(255, 59, 78, 0.06); border-radius: 2px;">
                <p style="margin: 0; color: #ff3b4e;">
                    No passwords cracked. Try a larger wordlist.
                </p>
            </div>`}
        </div>`;
    });
    
    container.innerHTML = html;
}


// ==================== SQLMAP FUNCTIONS ====================

function showSQLMapDialog() {
    console.log(`showSQLMapDialog called with scanId: ${scanId}`);
    
    if (!scanId) {
        alert('Error: No scan ID available for SQLMap test');
        return;
    }
    
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.innerHTML = `
        <div class="modal-content" style="max-width: 700px;">
            <h2 style="color: #ff3b4e; margin-bottom: 1rem;">[SQLMAP] SQL Injection Test</h2>
            
            <div style="background: rgba(255, 176, 32, 0.08); border-left: 3px solid #ffb020; padding: 1rem; border-radius: 2px; margin-bottom: 1rem;">
                <strong>[!] LEGAL WARNING</strong>
                <p style="margin: 0.5rem 0;">This will perform REAL SQL injection attacks on the target!</p>
                <p style="margin: 0.5rem 0 0 0; color: #ffb020;">
                    <strong>ONLY use on systems you own or have written authorization to test!</strong>
                </p>
            </div>
            
            <h3 style="color: #ff3b4e; margin-top: 1.5rem;">[*] Target URL:</h3>
            <input type="text" id="sqlmap-url" class="form-input" placeholder="http://target.com/page?id=1" 
                   style="width: 100%; padding: 0.75rem; border: 1px solid #2c3d52; border-radius: 2px; margin-bottom: 1rem;">
            
            <h3 style="color: #ff3b4e; margin-top: 1rem;">[*] Test Level:</h3>
            <select id="sqlmap-level" class="form-input" style="width: 100%; padding: 0.75rem; border: 1px solid #2c3d52; border-radius: 2px; margin-bottom: 1rem;">
                <option value="1">Level 1 - Fast (Default tests)</option>
                <option value="2">Level 2 - Medium (More payloads)</option>
                <option value="3">Level 3 - Thorough (Extensive tests)</option>
                <option value="4">Level 4 - Deep (All parameters)</option>
                <option value="5">Level 5 - Maximum (Every possible test)</option>
            </select>
            
            <h3 style="color: #ff3b4e; margin-top: 1rem;">[*] Risk Level:</h3>
            <select id="sqlmap-risk" class="form-input" style="width: 100%; padding: 0.75rem; border: 1px solid #2c3d52; border-radius: 2px; margin-bottom: 1rem;">
                <option value="1">Risk 1 - Safe (No dangerous queries)</option>
                <option value="2">Risk 2 - Medium (Heavy queries, OR-based)</option>
                <option value="3">Risk 3 - High (May cause issues - UPDATE queries)</option>
            </select>
            
            <h3 style="color: #ff3b4e; margin-top: 1rem;">[*] Additional Options:</h3>
            <div style="margin: 1rem 0;">
                <label style="color: #ff3b4e; display: block; margin: 0.5rem 0; cursor: pointer;">
                    <input type="checkbox" id="sqlmap-enumerate-dbs"> 
                    Enumerate Databases (if vulnerable)
                </label>
                <label style="color: #ff3b4e; display: block; margin: 0.5rem 0; cursor: pointer;">
                    <input type="checkbox" id="sqlmap-current-user"> 
                    Get Current Database User
                </label>
                <label style="color: #ff3b4e; display: block; margin: 0.5rem 0; cursor: pointer;">
                    <input type="checkbox" id="sqlmap-current-db"> 
                    Get Current Database Name
                </label>
            </div>
            
            <div style="color: #ff3b4e; margin-top: 1.5rem; display: flex; gap: 1rem;">
                <button onclick="window.startSQLMapTest(this.parentElement.parentElement.parentElement)" class="btn btn-danger" style="flex: 1;">
                    [>] START SQL INJECTION TEST
                </button>
                <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn btn-secondary" style="flex: 1;">
                    [x] CANCEL
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
        overflow-y: auto;
    `;
    
    document.body.appendChild(dialog);
    console.log(' SQLMap dialog displayed');
}

async function startSQLMapTest(dialogElement) {
    console.log(`startSQLMapTest called with scanId: ${scanId}`);
    
    if (!scanId) {
        alert('Error: No scan ID available');
        return;
    }
    
    // Get input values
    const url = document.getElementById('sqlmap-url').value.trim();
    const level = parseInt(document.getElementById('sqlmap-level').value);
    const risk = parseInt(document.getElementById('sqlmap-risk').value);
    const enumerateDbs = document.getElementById('sqlmap-enumerate-dbs').checked;
    const currentUser = document.getElementById('sqlmap-current-user').checked;
    const currentDb = document.getElementById('sqlmap-current-db').checked;
    
    if (!url) {
        alert('Please enter a target URL');
        return;
    }
    
    // Validate URL format
    try {
        new URL(url);
    } catch {
        alert('Please enter a valid URL (must include http:// or https://)');
        return;
    }
    
    // Close dialog
    dialogElement.remove();
    
    // Show progress
    const container = document.getElementById('sqlmap-container');
    if (container) {
        container.innerHTML = `
            <div class="card" style="margin-bottom: 2rem;">
                <div style="padding: 1.5rem; background: linear-gradient(135deg, #0e141d 0%, #1a2432 100%); border-radius: 2px;">
                    <h3 style="margin: 0 0 1rem 0; color: #00ff88;">[>] SQLMap Test in Progress</h3>
                    <p style="margin: 0.5rem 0;">[*] Target: ${url}</p>
                    <p style="margin: 0.5rem 0;">[*] Level: ${level} | Risk: ${risk}</p>
                    <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">[*] This may take 3-5 minutes...</p>
                    <div class="spinner" style="margin-top: 1rem;"></div>
                </div>
            </div>
        `;
        container.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}/sqlmap-test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: url,
                options: {
                    level: level,
                    risk: risk,
                    enumerate_dbs: enumerateDbs,
                    current_user: currentUser,
                    current_db: currentDb
                }
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log(' SQLMap test started:', data);
            
            if (container) {
                container.innerHTML = `
                    <div class="card" style="margin-bottom: 2rem;">
                        <div style="padding: 1.5rem; background: rgba(0, 255, 136, 0.06); border-left: 4px solid #00ff88; border-radius: 2px;">
                            <h3 style="margin: 0 0 0.5rem 0; color: #00ff88;">[+] SQLMap Test Started</h3>
                            <p style="margin: 0.5rem 0; color: #00ff88;">[*] ${data.message || 'Test is running in background'}</p>
                            <p style="margin: 0.5rem 0 0 0; color: #00ff88;">[*] Checking for results every 10 seconds...</p>
                        </div>
                    </div>
                `;
            }
            
            // Poll for results
            pollSQLMapResults();
            
        } else {
            throw new Error(data.error || 'SQLMap test request failed');
        }
        
    } catch (error) {
        console.error(' SQLMap test error:', error);
        
        if (container) {
            container.innerHTML = `
                <div class="card" style="margin-bottom: 2rem;">
                    <div style="padding: 1.5rem; background: rgba(255, 59, 78, 0.06); border-left: 4px solid #ff3b4e; border-radius: 2px;">
                        <h3 style="margin: 0 0 0.5rem 0; color: #ff3b4e;">[-] SQLMap Test Error</h3>
                        <p style="margin: 0; color: #ff3b4e;">${error.message}</p>
                    </div>
                </div>
            `;
        }
    }
}

let sqlmapPollAttempts = 0;
const maxSQLMapPollAttempts = 30; // 5 minutes (30 x 10 seconds)

function pollSQLMapResults() {
    setTimeout(async () => {
        sqlmapPollAttempts++;
        console.log(`SQLMap poll attempt ${sqlmapPollAttempts}/${maxSQLMapPollAttempts}`);
        
        try {
            const response = await fetch(`${API_URL}/scans/${scanId}/sqlmap-results`);
            const data = await response.json();
            
            if (data.results && data.results.length > 0) {
                console.log(` Found ${data.results.length} SQLMap results`);
                displaySQLMapResults(data.results);
                sqlmapPollAttempts = 0;
            } else {
                if (sqlmapPollAttempts < maxSQLMapPollAttempts) {
                    pollSQLMapResults(); // Continue polling
                } else {
                    const container = document.getElementById('sqlmap-container');
                    if (container) {
                        container.innerHTML = `
                            <div class="card" style="margin-bottom: 2rem;">
                                <div style="padding: 1.5rem; background: rgba(255, 176, 32, 0.06); border-left: 4px solid #ffb020; border-radius: 2px;">
                                    <h3 style="margin: 0 0 0.5rem 0; color: #ffb020;">[~] Test Still Running</h3>
                                    <p style="margin: 0; color: #ffb020;">[*] SQLMap test is taking longer than expected. Refresh the page in a few minutes.</p>
                                </div>
                            </div>
                        `;
                    }
                    sqlmapPollAttempts = 0;
                }
            }
        } catch (error) {
            console.error('Error polling SQLMap results:', error);
            if (sqlmapPollAttempts < maxSQLMapPollAttempts) {
                pollSQLMapResults();
            }
        }
    }, 10000); // Poll every 10 seconds
}

function displaySQLMapResults(results) {
    const container = document.getElementById('sqlmap-results-container');
    if (!container) return;
    
    // Clear progress message
    const progressContainer = document.getElementById('sqlmap-container');
    if (progressContainer) {
        progressContainer.innerHTML = '';
    }
    
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    let html = `
        <h3 style="margin: 2rem 0 1rem 0; color: #00ff88; text-transform: uppercase; letter-spacing: 1px;">[SQLMAP] Test Results</h3>
    `;
    
    results.forEach((result, index) => {
        const borderColor = result.vulnerable ? '#ff3b4e' : '#00ff88';
        const bgColor = result.vulnerable ? 'rgba(255, 59, 78, 0.06)' : 'rgba(0, 255, 136, 0.06)';
        const textColor = result.vulnerable ? '#ff3b4e' : '#00ff88';
        const icon = result.vulnerable ? '[!]' : '[+]';
        
        // Parse injections
        let injections = [];
        try {
            injections = JSON.parse(result.injections || '[]');
        } catch (e) {
            console.error('Error parsing injections:', e);
        }
        
        // Parse databases
        let databases = [];
        try {
            databases = JSON.parse(result.databases || '[]');
        } catch (e) {
            console.error('Error parsing databases:', e);
        }
        
        html += `
            <div class="card" style="margin-bottom: 1.5rem; border-left: 4px solid ${borderColor};">
                <div style="padding: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                        <h4 style="margin: 0; color: #e6eef6;">${icon} SQL Injection Test</h4>
                        <button onclick="deleteSQLMapResult(${result.id})" class="btn btn-danger btn-small">
                            DELETE
                        </button>
                    </div>
                    
                    <div style="background: ${bgColor}; padding: 0.75rem; border-radius: 2px; margin-bottom: 1rem;">
                        <p style="margin: 0; color: ${textColor}; font-weight: 600;">
                            ${result.vulnerable ? '[!] VULNERABLE - SQL Injection Found!' : '[+] SECURE - No SQL Injection Detected'}
                        </p>
                    </div>
                    
                    <div style="margin-bottom: 1rem;">
                        <p style="margin: 0.5rem 0;"><strong>[*] Target URL:</strong> ${result.url}</p>
                        <p style="margin: 0.5rem 0;"><strong>[*] Status:</strong> ${result.status}</p>
                        ${result.dbms ? `<p style="margin: 0.5rem 0;"><strong>[*] Database:</strong> ${result.dbms}</p>` : ''}
                        <p style="margin: 0.5rem 0;"><strong>[*] Started:</strong> ${new Date(result.started_at).toLocaleString()}</p>
                        ${result.completed_at ? `<p style="margin: 0.5rem 0;"><strong>[*] Completed:</strong> ${new Date(result.completed_at).toLocaleString()}</p>` : ''}
                    </div>
                    
                    ${injections.length > 0 ? `
                        <div style="background: rgba(255, 176, 32, 0.06); padding: 1rem; border-left: 3px solid #ffb020; margin: 1rem 0; border-radius: 2px;">
                            <strong style="color: #ffb020;">[!] Injection Points Found:</strong>
                            ${injections.map(inj => `
                                <div style="margin: 0.75rem 0; padding: 0.5rem; background: #141c28; border-radius: 2px;">
                                    <p style="margin: 0.25rem 0;"><strong>Parameter:</strong> ${inj.parameter || 'N/A'}</p>
                                    <p style="margin: 0.25rem 0;"><strong>Type:</strong> ${inj.type || 'N/A'}</p>
                                    <p style="margin: 0.25rem 0;"><strong>Title:</strong> ${inj.title || 'N/A'}</p>
                                    ${inj.payload ? `<p style="margin: 0.25rem 0; font-family: monospace; font-size: 0.85rem; word-break: break-all; color: #00ff88;"><strong>Payload:</strong> ${inj.payload}</p>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                    
                    ${databases.length > 0 ? `
                        <div style="background: rgba(0, 212, 255, 0.06); padding: 1rem; border-left: 3px solid #00d4ff; margin: 1rem 0; border-radius: 2px;">
                            <strong style="color: #00d4ff;">[+] Databases Found:</strong>
                            <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                                ${databases.map(db => `<li>${db}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    
                    ${result.error ? `
                        <div style="background: rgba(255, 59, 78, 0.06); padding: 0.75rem; border-left: 3px solid #ff3b4e; margin-top: 1rem; border-radius: 2px;">
                            <strong style="color: #ff3b4e;">[!] Error:</strong>
                            <p style="margin: 0.5rem 0 0 0; color: #ff3b4e;">${result.error}</p>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

async function deleteSQLMapResult(resultId) {
    if (!confirm('[!] Delete this SQLMap test result?')) return;
    
    try {
        const response = await fetch(`${API_URL}/sqlmap-results/${resultId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            // Reload results
            const resultsResponse = await fetch(`${API_URL}/scans/${scanId}/sqlmap-results`);
            const data = await resultsResponse.json();
            
            if (data.results && data.results.length > 0) {
                displaySQLMapResults(data.results);
            } else {
                document.getElementById('sqlmap-results-container').style.display = 'none';
            }
            
            alert('[OK] SQLMap result deleted');
        }
    } catch (error) {
        console.error('Error deleting SQLMap result:', error);
        alert('[FAIL] Error deleting result');
    }
}

// ==================== EVENT LISTENERS ====================

document.addEventListener('DOMContentLoaded', () => {
    // SQLMap button
    const sqlmapBtn = document.getElementById('sqlmap-test-btn');
    if (sqlmapBtn) {
        console.log(' SQLMap button found');
        sqlmapBtn.addEventListener('click', showSQLMapDialog);
    }
    
    // Hashcat button
    const hashcatBtn = document.getElementById('hashcat-crack-btn');
    if (hashcatBtn) {
        console.log(' Hashcat button found');
        hashcatBtn.addEventListener('click', showHashcatDialog);
    }
    
    // Load existing results when page loads
    setTimeout(() => {
        loadSQLMapResults();
        loadHashcatResults();
    }, 2000);
});

async function loadSQLMapResults() {
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}/sqlmap-results`);
        const data = await response.json();
        
        if (data.results && data.results.length > 0) {
            displaySQLMapResults(data.results);
        }
    } catch (error) {
        console.error('Error loading SQLMap results:', error);
    }
}

// async function loadHashcatResults() {
//     try {
//         const response = await fetch(`${API_URL}/scans/${scanId}/hashcat-results`);
//         const data = await response.json();
        
//         if (data.results && data.results.length > 0) {
//             displayHashcatResults(data.results);
//         }
//     } catch (error) {
//         console.error('Error loading Hashcat results:', error);
//     }
// }

// Load existing Hashcat results on page load
function loadHashcatResults() {
    fetch(`${API_URL}/scans/${scanId}/hashcat-results`)
        .then(r => r.json())
        .then(data => {
            console.log('Hashcat results from DB:', data);
            if (data.results && data.results.length > 0) {
                displayHashcatResults(data.results);
            } else {
                const c = document.getElementById('hashcat-results-container');
                if (c) c.innerHTML = '<p style="color:#b8c6d4;">No cracking jobs yet. Click the button above to start.</p>';
            }
        })
        .catch(err => console.error('loadHashcatResults error:', err));
}

// Make functions globally available
window.showSQLMapDialog = showSQLMapDialog;
window.startSQLMapTest = startSQLMapTest;
window.deleteSQLMapResult = deleteSQLMapResult;
window.showHashcatDialog = showHashcatDialog;
window.startHashcatCrack = startHashcatCrack;


// ==================== HASH DISCOVERY ====================

function discoverHashes() {
    const resultsDiv = document.getElementById('hash-discovery-results');
    
    // Get the most recent SQLMap result
    fetch(`/api/v1/scans/${scanId}/sqlmap-results`)
        .then(response => response.json())
        .then(data => {
            if (data.results && data.results.length > 0) {
                const latestResult = data.results[0];
                
                resultsDiv.innerHTML = '<p>[*] Searching for password hashes...</p>';
                
                // Discover hashes
                return fetch(`/api/v1/scans/${scanId}/discover-hashes`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({sqli_result_id: latestResult.id})
                });
            } else {
                resultsDiv.innerHTML = '<p>[!] No SQLMap results found. Run SQL injection test first.</p>';
                return null;
            }
        })
        .then(response => {
            if (!response) return;
            return response.json();
        })
        .then(data => {
            if (!data) return;
            
            if (data.success && data.hashes) {
                let html = `<div class="success-box">
                    <h4>[+] Found ${data.hashes_found} Password Hashes!</h4>
                    <p>[*] Hashes ready for Hashcat cracking:</p>
                    <div style="max-height: 300px; overflow-y: auto; background: #0e141d; padding: 10px; border: 1px solid #2c3d52; border-radius: 2px;">`;
                
                data.hashes.forEach(h => {
                    html += `<div style="margin: 5px 0; font-family: monospace;">
                        <strong>${h.type_name}:</strong> ${h.hash}
                    </div>`;
                });
                
                html += `</div>
                    <button onclick="sendHashesToHashcat(${JSON.stringify(data.hashes).replace(/"/g, '&quot;')})" class="btn btn-primary" style="margin-top: 10px;">
                        [>] CRACK WITH HASHCAT
                    </button>
                </div>`;
                
                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = `<div class="warning-box">
                    <p>[!] ${data.message || 'No hashes found'}</p>
                    <p>${data.suggestion || ''}</p>
                </div>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<p class="error">[FAIL] Error: ${error.message}</p>`;
        });
}

function sendHashesToHashcat(hashes) {
    // Get unique hash type
    const hashType = hashes[0].type;
    const hashStrings = hashes.map(h => h.hash);
    
    // Scroll to Hashcat section
    const hashcatSection = document.getElementById('hashcat-container') || document.getElementById('hashcat-section');
    if (hashcatSection) {
        hashcatSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Open the Hashcat dialog
    showHashcatDialog();
    
    // Fill in Hashcat form once the dialog is rendered
    setTimeout(() => {
        const textarea = document.getElementById('hashcat-hashes');
        const typeSelect = document.getElementById('hashcat-type');
        
        if (textarea) textarea.value = hashStrings.join('\n');
        if (typeSelect) typeSelect.value = hashType;
        
        // Auto-start cracking
        if (confirm('[!] Start cracking these hashes now?')) {
            const overlay = textarea ? textarea.closest('.modal-overlay') : null;
            if (overlay) {
                startHashcatCrack(overlay);
            } else {
                startHashcatCrack();
            }
        }
    }, 300);
}

// Show hash discovery button when SQLMap finds SQLi
function checkForSQLiAndShowHashDiscovery() {
    fetch(`/api/v1/scans/${scanId}/sqlmap-results`)
        .then(response => response.json())
        .then(data => {
            if (data.results && data.results.length > 0) {
                const vulnerable = data.results.some(r => r.vulnerable);
                if (vulnerable) {
                    document.getElementById('sqlmap-hash-discovery').style.display = 'block';
                }
            }
        });
}

// Call this when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkForSQLiAndShowHashDiscovery);
} else {
    checkForSQLiAndShowHashDiscovery();
}