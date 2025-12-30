/**
 * ForenX-NGINX Sentinel Dashboard
 * Main JavaScript for the forensic dashboard
 */

const API_BASE = 'http://localhost:8000/api';
let currentView = 'dashboard';
let currentLogsPage = 1;
let logsTotalPages = 1;
let realtimeEnabled = false;
let websocket = null;

// Chart instances
let timelineChart = null;
let topIpsChart = null;
let statusChart = null;
let endpointsChart = null;
let userAgentsChart = null;
let methodsChart = null;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
    loadDashboardData();
    initializeCharts();
});

function setupEventListeners() {
    // File upload handling
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    
    fileInput.addEventListener('change', handleFileSelect);
    
    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#2563eb';
        dropZone.style.background = 'rgba(37, 99, 235, 0.1)';
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.style.borderColor = '#e2e8f0';
        dropZone.style.background = '#f8fafc';
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#e2e8f0';
        dropZone.style.background = '#f8fafc';
        
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelect({ target: fileInput });
        }
    });
}

function handleFileSelect(e) {
    const files = e.target.files;
    const fileList = document.getElementById('fileList');
    
    fileList.innerHTML = '';
    
    if (files.length > 0) {
        fileList.innerHTML = '<h6>Selected Files:</h6>';
        
        for (let file of files) {
            const fileSize = (file.size / 1024).toFixed(2) + ' KB';
            fileList.innerHTML += `
                <div class="alert alert-light d-flex justify-content-between align-items-center mb-2">
                    <div>
                        <i class="fas fa-file-logs me-2"></i>
                        ${file.name}
                        <small class="text-muted ms-2">(${fileSize})</small>
                    </div>
                    <i class="fas fa-check text-success"></i>
                </div>
            `;
        }
    }
}

// View Navigation Functions
function showDashboard() {
    switchView('dashboard', 'Dashboard Overview', 'Real-time forensic analysis of NGINX logs');
    loadDashboardData();
}

function showLogsView() {
    switchView('logs', 'Raw Logs Explorer', 'Browse and search through parsed logs');
    loadLogs();
}

function showAlertsView() {
    switchView('alerts', 'Security Alerts', 'Detected attacks and suspicious activities');
    loadAlerts();
}

function showAnalyticsView() {
    switchView('analytics', 'Analytics & Insights', 'Detailed traffic analysis and patterns');
    loadAnalytics();
}

function showTimelineView() {
    switchView('timeline', 'Timeline Forensics', 'Interactive timeline with attack markers');
    // To be implemented
}

function showRealTimeView() {
    switchView('realtime', 'Real-time Monitor', 'Live log streaming and monitoring');
    // Real-time view specific initialization
}

function showSettings() {
    alert('Settings view - To be implemented in Phase 2');
}

function showHelp() {
    alert('Help & Documentation - To be implemented in Phase 2');
}

function switchView(viewName, title, subtitle) {
    // Hide all views
    document.querySelectorAll('#mainContent > div').forEach(div => {
        div.style.display = 'none';
    });
    
    // Show selected view
    document.getElementById(viewName + 'View').style.display = 'block';
    
    // Update header
    document.getElementById('viewTitle').textContent = title;
    document.getElementById('viewSubtitle').textContent = subtitle;
    
    // Update sidebar active state
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.classList.remove('active');
    });
    // Note: This is simplified - you'd need to map view names to sidebar items
    
    currentView = viewName;
}

// API Functions
async function loadDashboardData() {
    try {
        // Load metrics
        const metricsResponse = await fetch(`${API_BASE}/metrics?time_range=24h`);
        const metrics = await metricsResponse.json();
        
        updateStatsCards(metrics);
        
        // Load timeline
        await loadTimelineData();
        
        // Load top IPs
        await loadTopIps();
        
        // Load status distribution
        await loadStatusDistribution();
        
        // Load recent alerts
        await loadRecentAlerts();
        
        // Load attack types
        await loadAttackTypes();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showToast('Error loading dashboard data', 'danger');
    }
}

async function loadTimelineData() {
    try {
        const range = document.getElementById('timelineRange').value;
        const interval = document.getElementById('timelineInterval').value;
        
        const response = await fetch(`${API_BASE}/timeline?interval=${interval}&time_range=${range}`);
        const data = await response.json();
        
        if (data.error) {
            console.warn(data.error);
            return;
        }
        
        updateTimelineChart(data);
        
    } catch (error) {
        console.error('Error loading timeline data:', error);
    }
}

async function loadTopIps() {
    try {
        const response = await fetch(`${API_BASE}/top-data?category=ips&limit=10`);
        const data = await response.json();
        
        if (data.error) {
            console.warn(data.error);
            return;
        }
        
        updateTopIpsChart(data);
        
    } catch (error) {
        console.error('Error loading top IPs:', error);
    }
}

async function loadStatusDistribution() {
    try {
        const response = await fetch(`${API_BASE}/top-data?category=status_codes`);
        const data = await response.json();
        
        if (data.error) {
            console.warn(data.error);
            return;
        }
        
        updateStatusChart(data);
        
    } catch (error) {
        console.error('Error loading status distribution:', error);
    }
}

async function loadRecentAlerts() {
    try {
        const response = await fetch(`${API_BASE}/alerts?limit=5`);
        const data = await response.json();
        
        updateAlertsTable(data.alerts || []);
        
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function loadAttackTypes() {
    // This would be calculated from alerts
    const attackTypesDiv = document.getElementById('attackTypesList');
    attackTypesDiv.innerHTML = `
        <div class="alert alert-light">
            <small>Attack types will be displayed after log analysis</small>
        </div>
    `;
}

async function loadLogs() {
    try {
        const response = await fetch(`${API_BASE}/logs?page=${currentLogsPage}&limit=100`);
        const data = await response.json();
        
        updateLogsTable(data.logs || []);
        
        logsTotalPages = data.pagination?.pages || 1;
        document.getElementById('logsPageInfo').textContent = 
            `Page ${currentLogsPage} of ${logsTotalPages}`;
        document.getElementById('logsCount').textContent = 
            `Showing ${data.logs?.length || 0} logs`;
        
    } catch (error) {
        console.error('Error loading logs:', error);
        showToast('Error loading logs', 'danger');
    }
}

async function loadAnalytics() {
    try {
        // Load endpoints
        const endpointsResponse = await fetch(`${API_BASE}/top-data?category=endpoints&limit=10`);
        const endpointsData = await endpointsResponse.json();
        
        if (!endpointsData.error) {
            updateEndpointsChart(endpointsData);
        }
        
        // Load user agents
        const uaResponse = await fetch(`${API_BASE}/top-data?category=user_agents&limit=8`);
        const uaData = await uaResponse.json();
        
        if (!uaData.error) {
            updateUserAgentsChart(uaData);
        }
        
        // Load methods (from metrics)
        const metricsResponse = await fetch(`${API_BASE}/metrics`);
        const metrics = await metricsResponse.json();
        
        if (metrics.request_methods) {
            updateMethodsChart(metrics.request_methods);
        }
        
    } catch (error) {
        console.error('Error loading analytics:', error);
        showToast('Error loading analytics', 'danger');
    }
}

// UI Update Functions
function updateStatsCards(metrics) {
    const statsRow = document.getElementById('statsRow');
    
    statsRow.innerHTML = `
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${metrics.total_requests?.toLocaleString() || 0}</h3>
                        <p class="text-muted mb-0">Total Requests</p>
                    </div>
                    <div class="stat-icon" style="background: #dbeafe; color: #1d4ed8;">
                        <i class="fas fa-globe"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${metrics.unique_ips?.toLocaleString() || 0}</h3>
                        <p class="text-muted mb-0">Unique IPs</p>
                    </div>
                    <div class="stat-icon" style="background: #fce7f3; color: #be185d;">
                        <i class="fas fa-network-wired"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${formatBytes(metrics.total_bytes || 0)}</h3>
                        <p class="text-muted mb-0">Total Bytes</p>
                    </div>
                    <div class="stat-icon" style="background: #dcfce7; color: #166534;">
                        <i class="fas fa-database"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${metrics.status_4xx || 0}</h3>
                        <p class="text-muted mb-0">4xx Errors</p>
                    </div>
                    <div class="stat-icon" style="background: #fef3c7; color: #92400e;">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${metrics.status_5xx || 0}</h3>
                        <p class="text-muted mb-0">5xx Errors</p>
                    </div>
                    <div class="stat-icon" style="background: #fee2e2; color: #991b1b;">
                        <i class="fas fa-bug"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${(metrics.error_rate * 100 || 0).toFixed(1)}%</h3>
                        <p class="text-muted mb-0">Error Rate</p>
                    </div>
                    <div class="stat-icon" style="background: #e0e7ff; color: #3730a3;">
                        <i class="fas fa-percentage"></i>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function updateTimelineChart(data) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    if (timelineChart) {
        timelineChart.destroy();
    }
    
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.timestamps,
            datasets: [{
                label: 'Requests',
                data: data.request_counts,
                borderColor: '#2563eb',
                backgroundColor: 'rgba(37, 99, 235, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

function updateTopIpsChart(data) {
    const ctx = document.getElementById('topIpsChart').getContext('2d');
    
    if (topIpsChart) {
        topIpsChart.destroy();
    }
    
    // Truncate IPs for display
    const truncatedLabels = data.labels.map(ip => {
        if (ip.length > 15) {
            return ip.substring(0, 12) + '...';
        }
        return ip;
    });
    
    topIpsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: truncatedLabels,
            datasets: [{
                data: data.values,
                backgroundColor: [
                    '#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
                    '#ec4899', '#f43f5e', '#ef4444', '#f97316', '#f59e0b'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Requests: ${context.parsed.y}`;
                        },
                        afterLabel: function(context) {
                            return `IP: ${data.labels[context.dataIndex]}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateStatusChart(data) {
    const ctx = document.getElementById('statusChart').getContext('2d');
    
    if (statusChart) {
        statusChart.destroy();
    }
    
    // Color mapping for status codes
    const statusColors = data.labels.map(status => {
        if (status.startsWith('2')) return '#10b981';
        if (status.startsWith('3')) return '#f59e0b';
        if (status.startsWith('4')) return '#ef4444';
        if (status.startsWith('5')) return '#dc2626';
        return '#6b7280';
    });
    
    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: statusColors,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            cutout: '70%'
        }
    });
}

function updateAlertsTable(alerts) {
    const tableBody = document.getElementById('alertsTable');
    
    if (alerts.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted py-4">
                    No security alerts detected yet
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    
    alerts.forEach(alert => {
        const time = new Date(alert.timestamp).toLocaleTimeString();
        const confidencePercent = Math.round(alert.confidence * 100);
        
        // Determine severity color
        let severityClass = 'warning';
        if (alert.confidence > 0.8) severityClass = 'danger';
        if (alert.confidence < 0.5) severityClass = 'info';
        
        html += `
            <tr class="log-row alert-${severityClass}">
                <td><small>${time}</small></td>
                <td>
                    <span class="badge bg-${severityClass}">
                        ${alert.attack_type}
                    </span>
                </td>
                <td><span class="ip-badge">${alert.client_ip}</span></td>
                <td><small>${truncateText(alert.endpoint, 30)}</small></td>
                <td>
                    <div class="d-flex align-items-center">
                        <div class="progress flex-grow-1 me-2" style="height: 6px;">
                            <div class="progress-bar bg-${severityClass}" 
                                 style="width: ${confidencePercent}%"></div>
                        </div>
                        <small>${confidencePercent}%</small>
                    </div>
                </td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

function updateLogsTable(logs) {
    const tableBody = document.getElementById('logsTable');
    
    if (logs.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-muted py-4">
                    No logs loaded. Upload log files to begin analysis.
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    
    logs.forEach(log => {
        const time = new Date(log.timestamp).toLocaleString();
        const statusClass = `status-${Math.floor(log.status / 100)}xx`;
        const bytes = log.bytes_sent ? formatBytes(log.bytes_sent) : '-';
        const userAgent = truncateText(log.user_agent || '-', 40);
        
        html += `
            <tr class="log-row">
                <td><small>${time}</small></td>
                <td><span class="ip-badge">${log.client_ip}</span></td>
                <td><span class="badge bg-light text-dark">${log.method}</span></td>
                <td><small>${truncateText(log.endpoint, 40)}</small></td>
                <td><span class="${statusClass} fw-bold">${log.status}</span></td>
                <td><small>${bytes}</small></td>
                <td><small title="${log.user_agent || ''}">${userAgent}</small></td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

function updateEndpointsChart(data) {
    const ctx = document.getElementById('endpointsChart').getContext('2d');
    
    if (endpointsChart) {
        endpointsChart.destroy();
    }
    
    // Truncate long endpoint names
    const truncatedLabels = data.labels.map(endpoint => {
        if (endpoint.length > 30) {
            return endpoint.substring(0, 27) + '...';
        }
        return endpoint;
    });
    
    endpointsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: truncatedLabels,
            datasets: [{
                label: 'Requests',
                data: data.values,
                backgroundColor: '#3b82f6'
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return data.labels[context[0].dataIndex];
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateUserAgentsChart(data) {
    const ctx = document.getElementById('userAgentsChart').getContext('2d');
    
    if (userAgentsChart) {
        userAgentsChart.destroy();
    }
    
    userAgentsChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: [
                    '#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
                    '#ec4899', '#f43f5e', '#ef4444', '#f97316'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

function updateMethodsChart(methods) {
    const ctx = document.getElementById('methodsChart').getContext('2d');
    
    if (methodsChart) {
        methodsChart.destroy();
    }
    
    const labels = Object.keys(methods);
    const values = Object.values(methods);
    
    // Color mapping for HTTP methods
    const methodColors = {
        'GET': '#3b82f6',
        'POST': '#10b981',
        'PUT': '#f59e0b',
        'DELETE': '#ef4444',
        'PATCH': '#8b5cf6',
        'HEAD': '#6b7280',
        'OPTIONS': '#6366f1'
    };
    
    const backgroundColors = labels.map(method => methodColors[method] || '#9ca3af');
    
    methodsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests',
                data: values,
                backgroundColor: backgroundColors
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Utility Functions
function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function truncateText(text, maxLength) {
    if (!text) return '-';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

function showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    // Add to container
    const container = document.querySelector('.toast-container');
    if (!container) {
        const newContainer = document.createElement('div');
        newContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(newContainer);
        container = newContainer;
    }
    
    container.appendChild(toast);
    
    // Show toast
    const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
    bsToast.show();
    
    // Remove after hiding
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

async function uploadLogs() {
    const fileInput = document.getElementById('fileInput');
    const logType = document.getElementById('logType').value;
    
    if (fileInput.files.length === 0) {
        showToast('Please select log files to upload', 'warning');
        return;
    }
    
    const uploadBtn = document.getElementById('uploadBtn');
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Uploading...';
    
    try {
        const formData = new FormData();
        
        // Add each file
        for (let i = 0; i < fileInput.files.length; i++) {
            formData.append('files', fileInput.files[i]);
        }
        formData.append('log_type', logType);
        
        console.log('Uploading files:', Array.from(fileInput.files).map(f => f.name));
        
        // FIXED: Use correct API endpoint
        const response = await fetch(`${API_BASE}/upload-logs`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Upload failed: ${response.status} ${response.statusText} - ${errorText}`);
        }
        
        const result = await response.json();
        
        console.log('Upload result:', result);
        
        if (result.files_processed) {
            const failedFiles = result.files_processed.filter(f => f.error);
            const successFiles = result.files_processed.filter(f => !f.error);
            
            if (failedFiles.length > 0) {
                showToast(`${failedFiles.length} file(s) failed to process`, 'warning');
            }
            
            if (successFiles.length > 0) {
                showToast(`Successfully processed ${successFiles.length} file(s) with ${result.total_records} log entries`, 'success');
            }
        }
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('uploadModal'));
        modal.hide();
        
        // Wait a moment for backend to process, then reload dashboard
        setTimeout(() => {
            loadDashboardData();
            if (currentView === 'logs') {
                loadLogs();
            }
        }, 1000);
        
        // Reset file input
        fileInput.value = '';
        document.getElementById('fileList').innerHTML = '';
        
    } catch (error) {
        console.error('Upload error:', error);
        showToast(`Error uploading files: ${error.message}`, 'danger');
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '<i class="fas fa-upload me-1"></i> Upload & Analyze';
    }
}

// Logs Filter Functions
function filterLogs() {
    const modal = new bootstrap.Modal(document.getElementById('filterModal'));
    modal.show();
}

function applyFilters() {
    // Get filter values
    const ipFilter = document.getElementById('filterIp').value;
    const statusFilter = document.getElementById('filterStatus').value;
    const timeRange = document.getElementById('filterTimeRange').value;
    
    // Build query string
    let query = `page=1&limit=100`;
    
    if (ipFilter) query += `&ip_filter=${encodeURIComponent(ipFilter)}`;
    if (statusFilter) query += `&status_filter=${statusFilter}`;
    
    // Convert time range to start time
    if (timeRange !== 'all') {
        const now = new Date();
        let startTime;
        
        switch (timeRange) {
            case '1h':
                startTime = new Date(now.getTime() - 60 * 60 * 1000);
                break;
            case '24h':
                startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                break;
            case '7d':
                startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
        }
        
        if (startTime) {
            query += `&time_start=${startTime.toISOString()}`;
        }
    }
    
    // Load logs with filters
    loadFilteredLogs(query);
    
    // Close modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('filterModal'));
    modal.hide();
}

async function loadFilteredLogs(query) {
    try {
        const response = await fetch(`${API_BASE}/logs?${query}`);
        const data = await response.json();
        
        updateLogsTable(data.logs || []);
        
        logsTotalPages = data.pagination?.pages || 1;
        currentLogsPage = 1;
        document.getElementById('logsPageInfo').textContent = 
            `Page ${currentLogsPage} of ${logsTotalPages}`;
        
    } catch (error) {
        console.error('Error loading filtered logs:', error);
        showToast('Error loading filtered logs', 'danger');
    }
}

function searchLogs() {
    const searchTerm = document.getElementById('searchLogs').value.toLowerCase();
    const rows = document.querySelectorAll('#logsTable tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
}

function changeLogsPage(delta) {
    const newPage = currentLogsPage + delta;
    
    if (newPage >= 1 && newPage <= logsTotalPages) {
        currentLogsPage = newPage;
        loadLogs();
    }
}

// Export Functions
async function exportData() {
    try {
        const response = await fetch(`${API_BASE}/export?format=csv`);
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'nginx_logs_export.csv';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showToast('Export started successfully', 'success');
        } else {
            showToast('Error exporting data', 'danger');
        }
    } catch (error) {
        console.error('Export error:', error);
        showToast('Error exporting data', 'danger');
    }
}

// Real-time Functions
function toggleRealtime() {
    const toggle = document.getElementById('realtimeToggle');
    realtimeEnabled = toggle.checked;
    
    const statusBadge = document.getElementById('realtimeStatus');
    
    if (realtimeEnabled) {
        statusBadge.innerHTML = '<i class="fas fa-circle me-1"></i> Real-time: ON';
        statusBadge.style.background = '#10b981';
        connectWebSocket();
    } else {
        statusBadge.innerHTML = '<i class="fas fa-circle me-1"></i> Real-time: OFF';
        statusBadge.style.background = '#dc2626';
        disconnectWebSocket();
    }
}

function connectWebSocket() {
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        return;
    }
    
    websocket = new WebSocket(`ws://${window.location.host}/ws/logs`);
    
    websocket.onopen = () => {
        console.log('WebSocket connected');
        showToast('Real-time monitoring connected', 'success');
    };
    
    websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'heartbeat') {
            // Keep-alive heartbeat
            return;
        }
        
        // Handle incoming log data
        if (currentView === 'realtime') {
            addRealtimeLog(data);
        }
    };
    
    websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        showToast('Real-time connection error', 'danger');
    };
    
    websocket.onclose = () => {
        console.log('WebSocket disconnected');
        if (realtimeEnabled) {
            // Try to reconnect after 5 seconds
            setTimeout(connectWebSocket, 5000);
        }
    };
}

function disconnectWebSocket() {
    if (websocket) {
        websocket.close();
        websocket = null;
    }
}

function addRealtimeLog(logData) {
    const tableBody = document.getElementById('realtimeTable');
    
    // Insert at beginning
    const time = new Date().toLocaleTimeString();
    
    const row = document.createElement('tr');
    row.className = 'log-row';
    row.innerHTML = `
        <td><small>${time}</small></td>
        <td><span class="ip-badge">${logData.client_ip}</span></td>
        <td><span class="badge bg-light text-dark">${logData.method}</span></td>
        <td><small>${truncateText(logData.endpoint, 40)}</small></td>
        <td><span class="status-${Math.floor(logData.status/100)}xx fw-bold">${logData.status}</span></td>
    `;
    
    tableBody.insertBefore(row, tableBody.firstChild);
    
    // Limit number of rows
    if (tableBody.children.length > 100) {
        tableBody.removeChild(tableBody.lastChild);
    }
}

function clearRealtimeLogs() {
    document.getElementById('realtimeTable').innerHTML = '';
}

// Modal Functions
function showUploadModal() {
    const modal = new bootstrap.Modal(document.getElementById('uploadModal'));
    modal.show();
}

// Initialize empty charts
function initializeCharts() {
    // Initialize with empty data for charts
    const emptyData = { labels: [], values: [] };
    
    // Initialize all chart canvases
    const charts = ['timelineChart', 'topIpsChart', 'statusChart', 'endpointsChart', 'userAgentsChart', 'methodsChart'];
    
    charts.forEach(chartId => {
        const ctx = document.getElementById(chartId)?.getContext('2d');
        if (ctx) {
            new Chart(ctx, {
                type: chartId.includes('timeline') ? 'line' : 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: '#e5e7eb'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
    });
}
