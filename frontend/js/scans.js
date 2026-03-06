// API Configuration
const API_URL = "http://localhost:5000/api/v1";

let currentPage = 1;
const pageSize = 10;

// Load scans when page loads
document.addEventListener("DOMContentLoaded", function () {
  loadScans(currentPage);
});

// Load all scans
async function loadScans(page = 1) {
  try {
    const response = await fetch(
      `${API_URL}/scans?page=${page}&limit=${pageSize}`,
    );
    const data = await response.json();

    displayScans(data.scans || []);
  } catch (error) {
    console.error("Error loading scans:", error);
    showError("Failed to load scans. Make sure the API server is running.");
  }
}

// Display scans in table
function displayScans(scans) {
  const loading = document.getElementById("scans-loading");
  const table = document.getElementById("scans-table");
  const noScans = document.getElementById("no-scans");
  const tbody = document.getElementById("scans-tbody");

  loading.style.display = "none";

  if (!scans || scans.length === 0) {
    table.style.display = "none";
    noScans.style.display = "block";
    return;
  }

  table.style.display = "block";
  noScans.style.display = "none";

  tbody.innerHTML = "";

  scans.forEach((scan) => {
    const row = createScanRow(scan);
    tbody.appendChild(row);
  });
}

// Create table row for scan
function createScanRow(scan) {
  const tr = document.createElement("tr");

  tr.innerHTML = `
        <td><strong>#${scan.id}</strong></td>
        <td>${scan.scan_name}</td>
        <td><code>${scan.target}</code></td>
        <td>${scan.scan_type}</td>
        <td><span class="badge ${getStatusClass(scan.status)}">${scan.status.toUpperCase()}</span></td>
        <td>${scan.total_hosts || 0}</td>
        <td>${getVulnerabilityBadge(scan)}</td>
        <td>${formatDate(scan.started_at || scan.created_at)}</td>
        <td style="display: flex; gap: 0.5rem;">
        <a href="scan-details.html?id=${scan.id}" class="btn btn-secondary btn-small">View</a>
        <button onclick="deleteScan(${scan.id})" class="btn btn-danger btn-small" title="Delete">🗑️</button>
        </td>
        
    `;

  return tr;
}

// Get status badge class
function getStatusClass(status) {
  const statusMap = {
    completed: "badge-success",
    running: "badge-info",
    pending: "badge-warning",
    failed: "badge-danger",
  };
  return statusMap[status] || "badge-info";
}

// Get vulnerability badge
function getVulnerabilityBadge(scan) {
  const total = scan.total_vulnerabilities || 0;

  if (total === 0) {
    return '<span class="badge badge-success">0</span>';
  }

  let html = `<strong>${total}</strong>`;

  if (scan.critical_count > 0) {
    html += ` <span style="color: #dc3545;">●${scan.critical_count}</span>`;
  }
  if (scan.high_count > 0) {
    html += ` <span style="color: #fd7e14;">●${scan.high_count}</span>`;
  }
  if (scan.medium_count > 0) {
    html += ` <span style="color: #ffc107;">●${scan.medium_count}</span>`;
  }

  return html;
}

// Format date
function formatDate(dateString) {
  if (!dateString) return "N/A";
  const date = new Date(dateString);
  return (
    date.toLocaleDateString() +
    " " +
    date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );
}

// Show error
function showError(message) {
  const tbody = document.getElementById("scans-tbody");
  tbody.innerHTML = `
        <tr>
            <td colspan="9" style="text-align: center; color: #dc3545; padding: 2rem;">
                ⚠️ ${message}
            </td>
        </tr>
    `;
}


// Delete scan function
async function deleteScan(scanId) {
    const confirmed = confirm(
        '⚠️ Delete this scan?\n\nThis will permanently delete all scan data and cannot be undone!'
    );
    
    if (!confirmed) return;
    
    try {
        const response = await fetch(`${API_URL}/scans/${scanId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('✅ Scan deleted successfully!');
            loadScans(currentPage);  // Reload current page
        } else {
            alert(`❌ Error: ${data.error}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('❌ Failed to delete scan.');
    }
}