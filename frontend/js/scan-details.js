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
        // Fetch scan details
        const scanResponse = await fetch(`${API_URL}/scans/${scanId}`);
        if (!scanResponse.ok) {
            throw new Error('Scan not found');
        }
        const scan = await scanResponse.json();
        
        // Fetch vulnerabilities
        const vulnResponse = await fetch(`${API_URL}/scans/${scanId}/vulnerabilities`);
        const vulnData = await vulnResponse.json();
        
        // Hide loading, show content
        loadingState.style.display = 'none';
        content.style.display = 'block';
        
        // Update page with scan data
        updateScanInfo(scan);
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
function createVulnerabilityCard(vuln) {
    const card = document.createElement('div');
    card.className = 'card';
    card.style.marginBottom = '1rem';
    card.style.borderLeft = `4px solid ${getSeverityColor(vuln.severity)}`;
    
    card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
            <div>
                <h4 style="margin: 0 0 0.5rem 0; color: #333;">
                    ${vuln.cve_id || 'Unknown CVE'}
                </h4>
                <div style="color: #666; font-size: 0.9rem;">
                    <strong>Host:</strong> ${vuln.ip_address} ${vuln.hostname ? `(${vuln.hostname})` : ''}
                    ${vuln.port ? ` | <strong>Port:</strong> ${vuln.port}` : ''}
                    ${vuln.service ? ` | <strong>Service:</strong> ${vuln.service}` : ''}
                </div>
            </div>
            <span class="badge ${getSeverityBadgeClass(vuln.severity)}">
                ${vuln.severity.toUpperCase()}
                ${vuln.cvss_score ? ` (${vuln.cvss_score})` : ''}
            </span>
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