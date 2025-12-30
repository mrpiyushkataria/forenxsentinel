/**
 * ForenX-NGINX Sentinel Dashboard
 * Main JavaScript for the forensic dashboard - ENHANCED VERSION
 */

const API_BASE = '/api';  // Use relative path
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
let dailyChart = null;
let weeklyChart = null;
let monthlyChart = null;
let errorTrendChart = null;
let timelineViewChart = null;

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

function showHistoricalView() {
    switchView('historical', 'Historical Analytics', 'Long-term trends and patterns analysis');
    loadHistoricalMetrics();
    loadPeriodComparison();
}

function showTimelineView() {
    switchView('timeline', 'Timeline Forensics', 'Interactive timeline with attack markers');
    loadTimelineViewData();
}

function showRealTimeView() {
    switchView('realtime', 'Real-time Monitor', 'Live log streaming and monitoring');
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
    const viewElement = document.getElementById(viewName + 'View');
    if (viewElement) {
        viewElement.style.display = 'block';
    }
    
    // Update header
    document.getElementById('viewTitle').textContent = title;
    document.getElementById('viewSubtitle').textContent = subtitle;
    
    // Update sidebar active state
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Activate the clicked sidebar item
    const activeItem = Array.from(document.querySelectorAll('.sidebar-item')).find(item => 
        item.textContent.includes(title.split(' ')[0])
    );
    if (activeItem) {
        activeItem.classList.add('active');
    }
    
    currentView = viewName;
}

// API Functions
async function loadDashboardData() {
    try {
        console.log('Loading dashboard data...');
        
        // Load metrics
        const metricsResponse = await fetch(`${API_BASE}/metrics?time_range=24h`);
        if (!metricsResponse.ok) {
            throw new Error(`Metrics API error: ${metricsResponse.status}`);
        }
        const metrics = await metricsResponse.json();
        console.log('Metrics loaded:', metrics);
        
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
        const range = document.getElementById('timelineRange')?.value || '24h';
        const interval = document.getElementById('timelineInterval')?.value || 'hour';
        
        const response = await fetch(`${API_BASE}/timeline?interval=${interval}&time_range=${range}`);
        if (!response.ok) {
            throw new Error(`Timeline API error: ${response.status}`);
        }
        const data = await response.json();
        
        console.log('Timeline data:', data);
        
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
        if (!response.ok) {
            throw new Error(`Top IPs API error: ${response.status}`);
        }
        const data = await response.json();
        
        console.log('Top IPs data:', data);
        
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
        if (!response.ok) {
            throw new Error(`Status API error: ${response.status}`);
        }
        const data = await response.json();
        
        console.log('Status data:', data);
        
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
        if (!response.ok) {
            throw new Error(`Alerts API error: ${response.status}`);
        }
        const data = await response.json();
        
        console.log('Alerts data:', data);
        
        updateAlertsTable(data.alerts || []);
        
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function loadAttackTypes() {
    try {
        const response = await fetch(`${API_BASE}/alerts?limit=100`);
        if (!response.ok) {
            throw new Error(`Attack types API error: ${response.status}`);
        }
        const data = await response.json();
        
        const attackTypesDiv = document.getElementById('attackTypesList');
        const alerts = data.alerts || [];
        
        if (alerts.length === 0) {
            attackTypesDiv.innerHTML = `
                <div class="alert alert-light">
                    <small>Attack types will be displayed after log analysis</small>
                </div>
            `;
            return;
        }
        
        // Count attack types
        const attackCounts = {};
        alerts.forEach(alert => {
            const type = alert.attack_type;
            attackCounts[type] = (attackCounts[type] || 0) + 1;
        });
        
        // Display attack types
        let html = '';
        for (const [type, count] of Object.entries(attackCounts)) {
            let badgeClass = 'bg-secondary';
            if (type.includes('SQL')) badgeClass = 'bg-danger';
            else if (type.includes('XSS')) badgeClass = 'bg-warning';
            else if (type.includes('DoS')) badgeClass = 'bg-danger';
            else if (type.includes('Brute')) badgeClass = 'bg-danger';
            
            html += `
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="badge ${badgeClass} me-2">${type}</span>
                    <small class="text-muted">${count} alerts</small>
                </div>
            `;
        }
        
        attackTypesDiv.innerHTML = html;
        
    } catch (error) {
        console.error('Error loading attack types:', error);
        const attackTypesDiv = document.getElementById('attackTypesList');
        attackTypesDiv.innerHTML = `
            <div class="alert alert-light">
                <small>Error loading attack types</small>
            </div>
        `;
    }
}

async function loadLogs() {
    try {
        const response = await fetch(`${API_BASE}/logs?page=${currentLogsPage}&limit=100`);
        if (!response.ok) {
            throw new Error(`Logs API error: ${response.status}`);
        }
        const data = await response.json();
        
        console.log('Logs data received:', data.logs?.length || 0, 'logs');
        
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
        console.log('Loading analytics data...');
        
        // Load endpoints
        const endpointsResponse = await fetch(`${API_BASE}/top-data?category=endpoints&limit=10`);
        if (endpointsResponse.ok) {
            const endpointsData = await endpointsResponse.json();
            console.log('Endpoints data:', endpointsData);
            if (!endpointsData.error) {
                updateEndpointsChart(endpointsData);
            }
        }
        
        // Load user agents
        const uaResponse = await fetch(`${API_BASE}/top-data?category=user_agents&limit=8`);
        if (uaResponse.ok) {
            const uaData = await uaResponse.json();
            console.log('User agents data:', uaData);
            if (!uaData.error) {
                updateUserAgentsChart(uaData);
            }
        }
        
        // Load methods from logs
        await loadMethodsFromLogs();
        
    } catch (error) {
        console.error('Error loading analytics:', error);
        showToast('Error loading analytics', 'danger');
    }
}

async function loadMethodsFromLogs() {
    try {
        const response = await fetch(`${API_BASE}/logs?limit=1000`);
        if (!response.ok) return;
        
        const data = await response.json();
        const logs = data.logs || [];
        
        const methodCounts = {};
        logs.forEach(log => {
            if (log.method) {
                methodCounts[log.method] = (methodCounts[log.method] || 0) + 1;
            }
        });
        
        if (Object.keys(methodCounts).length > 0) {
            updateMethodsChart(methodCounts);
        }
        
    } catch (error) {
        console.error('Error loading methods:', error);
    }
}

async function loadHistoricalMetrics() {
    try {
        const response = await fetch(`${API_BASE}/historical/metrics`);
        if (response.ok) {
            const data = await response.json();
            updateHistoricalCharts(data);
            changeErrorTrend('daily'); // Initialize error trend chart
        }
    } catch (error) {
        console.error('Error loading historical metrics:', error);
    }
}

async function loadPeriodComparison() {
    try {
        const response = await fetch(`${API_BASE}/compare/periods`);
        if (response.ok) {
            const data = await response.json();
            updateComparisonChart(data);
        }
    } catch (error) {
        console.error('Error loading period comparison:', error);
    }
}

async function loadTimelineViewData() {
    try {
        const mode = document.getElementById('timelineMode')?.value || 'requests';
        const range = document.getElementById('timelineViewRange')?.value || '7d';
        
        // Get timeline data
        const response = await fetch(`${API_BASE}/timeline?interval=day&time_range=${range}`);
        if (!response.ok) return;
        
        const data = await response.json();
        createTimelineViewChart(data, mode);
        
    } catch (error) {
        console.error('Error loading timeline view data:', error);
    }
}

// UI Update Functions
function updateStatsCards(metrics) {
    const statsRow = document.getElementById('statsRow');
    
    if (!statsRow) {
        console.error('Stats row element not found');
        return;
    }
    
    console.log('Updating stats with:', metrics);
    
    // Ensure we have valid numbers
    const totalRequests = metrics.total_requests || 0;
    const uniqueIps = metrics.unique_ips || 0;
    const totalBytes = metrics.total_bytes || 0;
    const status4xx = metrics.status_4xx || 0;
    const status5xx = metrics.status_5xx || 0;
    const errorRate = metrics.error_rate || 0;
    
    statsRow.innerHTML = `
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="mb-0">${totalRequests.toLocaleString()}</h3>
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
                        <h3 class="mb-0">${uniqueIps.toLocaleString()}</h3>
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
                        <h3 class="mb-0">${formatBytes(totalBytes)}</h3>
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
                        <h3 class="mb-0">${status4xx.toLocaleString()}</h3>
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
                        <h3 class="mb-0">${status5xx.toLocaleString()}</h3>
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
                        <h3 class="mb-0">${(errorRate * 100).toFixed(1)}%</h3>
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
    const canvas = document.getElementById('timelineChart');
    if (!canvas) {
        console.error('Timeline chart canvas not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    if (timelineChart) {
        timelineChart.destroy();
    }
    
    // Ensure we have data
    const timestamps = data.timestamps || [];
    const requestCounts = data.request_counts || [];
    
    if (timestamps.length === 0 || requestCounts.length === 0) {
        // Create empty chart with message
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['No data'],
                datasets: [{
                    label: 'Requests',
                    data: [0],
                    borderColor: '#e2e8f0',
                    backgroundColor: 'rgba(226, 232, 240, 0.1)',
                    borderWidth: 1,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No timeline data available'
                    }
                }
            }
        });
        return;
    }
    
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timestamps,
            datasets: [{
                label: 'Requests',
                data: requestCounts,
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
                    },
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
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
    const canvas = document.getElementById('topIpsChart');
    if (!canvas) {
        console.error('Top IPs chart canvas not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    if (topIpsChart) {
        topIpsChart.destroy();
    }
    
    const labels = data.labels || [];
    const values = data.values || [];
    
    if (labels.length === 0 || values.length === 0) {
        // Create empty chart
        topIpsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['No data'],
                datasets: [{
                    data: [0],
                    backgroundColor: '#e2e8f0'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No IP data available'
                    }
                }
            }
        });
        return;
    }
    
    // Truncate IPs for display
    const truncatedLabels = labels.map(ip => {
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
                data: values,
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
                            return `IP: ${labels[context.dataIndex]}`;
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
    const canvas = document.getElementById('statusChart');
    if (!canvas) {
        console.error('Status chart canvas not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    if (statusChart) {
        statusChart.destroy();
    }
    
    const labels = data.labels || [];
    const values = data.values || [];
    
    if (labels.length === 0 || values.length === 0) {
        // Create empty chart
        statusChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['No data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#e2e8f0']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No status data available'
                    }
                },
                cutout: '70%'
            }
        });
        return;
    }
    
    // Color mapping for status codes
    const statusColors = labels.map(status => {
        if (status.startsWith('2')) return '#10b981';
        if (status.startsWith('3')) return '#f59e0b';
        if (status.startsWith('4')) return '#ef4444';
        if (status.startsWith('5')) return '#dc2626';
        return '#6b7280';
    });
    
    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
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
    if (!tableBody) {
        console.error('Alerts table body not found');
        return;
    }
    
    console.log('Updating alerts table with:', alerts.length, 'alerts');
    
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
        const confidencePercent = Math.round((alert.confidence || 0.5) * 100);
        
        // Determine severity color
        let severityClass = 'warning';
        if (confidencePercent > 80) severityClass = 'danger';
        if (confidencePercent < 50) severityClass = 'info';
        
        html += `
            <tr class="log-row alert-${severityClass}">
                <td><small>${time}</small></td>
                <td>
                    <span class="badge bg-${severityClass}">
                        ${alert.attack_type || 'Unknown'}
                    </span>
                </td>
                <td><span class="ip-badge">${alert.client_ip || 'Unknown'}</span></td>
                <td><small>${truncateText(alert.endpoint || '', 30)}</small></td>
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
    if (!tableBody) {
        console.error('Logs table body not found');
        return;
    }
    
    console.log('Updating logs table with:', logs.length, 'logs');
    
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
                <td><span class="ip-badge">${log.client_ip || 'Unknown'}</span></td>
                <td><span class="badge bg-light text-dark">${log.method || 'GET'}</span></td>
                <td><small>${truncateText(log.endpoint || '', 40)}</small></td>
                <td><span class="${statusClass} fw-bold">${log.status || 0}</span></td>
                <td><small>${bytes}</small></td>
                <td><small title="${log.user_agent || ''}">${userAgent}</small></td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

function updateEndpointsChart(data) {
    const canvas = document.getElementById('endpointsChart');
    if (!canvas) {
        console.error('Endpoints chart canvas not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    if (endpointsChart) {
        endpointsChart.destroy();
    }
    
    const labels = data.labels || [];
    const values = data.values || [];
    
    if (labels.length === 0 || values.length === 0) {
        endpointsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['No data'],
                datasets: [{
                    label: 'Requests',
                    data: [0],
                    backgroundColor: '#e2e8f0'
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No endpoint data available'
                    }
                }
            }
        });
        return;
    }
    
    // Truncate long endpoint names
    const truncatedLabels = labels.map(endpoint => {
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
                data: values,
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
                            return labels[context[0].dataIndex];
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
    const canvas = document.getElementById('userAgentsChart');
    if (!canvas) {
        console.error('User agents chart canvas not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    if (userAgentsChart) {
        userAgentsChart.destroy();
    }
    
    const labels = data.labels || [];
    const values = data.values || [];
    
    if (labels.length === 0 || values.length === 0) {
        userAgentsChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['No data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#e2e8f0']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No user agent data available'
                    }
                }
            }
        });
        return;
    }
    
    userAgentsChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: values,
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

function updateMethodsChart(methodCounts) {
    const canvas = document.getElementById('methodsChart');
    if (!canvas) {
        console.error('Methods chart canvas not found');
        return;
    }
    
    const ctx = canvas.getContext('2d');
    
    if (methodsChart) {
        methodsChart.destroy();
    }
    
    const labels = Object.keys(methodCounts);
    const values = Object.values(methodCounts);
    
    if (labels.length === 0) {
        methodsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['No data'],
                datasets: [{
                    label: 'Requests',
                    data: [0],
                    backgroundColor: '#e2e8f0'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No method data available'
                    }
                }
            }
        });
        return;
    }
    
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

// Historical Analytics Functions
function updateHistoricalCharts(data) {
    // Daily requests chart
    if (data.daily && data.daily.length > 0) {
        createDailyChart(data.daily);
    }
    
    // Weekly trends chart
    if (data.weekly && data.weekly.length > 0) {
        createWeeklyChart(data.weekly);
    }
    
    // Monthly summary chart
    if (data.monthly && data.monthly.length > 0) {
        createMonthlyChart(data.monthly);
    }
}

function createDailyChart(dailyData) {
    const canvas = document.getElementById('dailyChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Clear existing chart
    if (dailyChart) {
        dailyChart.destroy();
    }
    
    const labels = dailyData.map(d => d.date.split('-').slice(1).join('-'));
    const requests = dailyData.map(d => d.requests);
    const errors = dailyData.map(d => d.errors);
    const uniqueIps = dailyData.map(d => d.unique_ips);
    
    dailyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Requests',
                    data: requests,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Errors',
                    data: errors,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Unique IPs',
                    data: uniqueIps,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            stacked: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Daily Traffic Overview (Last 30 Days)'
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Requests & Errors'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Unique IPs'
                    },
                    grid: {
                        drawOnChartArea: false,
                    },
                }
            }
        }
    });
}

function createWeeklyChart(weeklyData) {
    const canvas = document.getElementById('weeklyChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Clear existing chart
    if (weeklyChart) {
        weeklyChart.destroy();
    }
    
    const labels = weeklyData.map(w => `Week ${w.week.split('-W')[1]}`);
    const requests = weeklyData.map(w => w.requests);
    const errorRate = weeklyData.map(w => w.error_rate * 100);
    
    weeklyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Requests',
                    data: requests,
                    backgroundColor: 'rgba(59, 130, 246, 0.8)',
                    borderColor: '#3b82f6',
                    borderWidth: 1
                },
                {
                    label: 'Error Rate %',
                    data: errorRate,
                    type: 'line',
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Weekly Trends'
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
                    title: {
                        display: true,
                        text: 'Requests'
                    }
                },
                y1: {
                    position: 'right',
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Error Rate %'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

function createMonthlyChart(monthlyData) {
    const canvas = document.getElementById('monthlyChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Clear existing chart
    if (monthlyChart) {
        monthlyChart.destroy();
    }
    
    const labels = monthlyData.map(m => {
        const [year, month] = m.month.split('-');
        return `${year}-${month}`;
    });
    
    const requests = monthlyData.map(m => m.requests);
    const uniqueIps = monthlyData.map(m => m.unique_ips);
    
    // Calculate average requests per IP
    const avgPerIp = monthlyData.map(m => 
        m.unique_ips > 0 ? (m.requests / m.unique_ips).toFixed(1) : 0
    );
    
    monthlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Requests',
                    data: requests,
                    backgroundColor: 'rgba(139, 92, 246, 0.7)',
                    borderColor: '#8b5cf6',
                    borderWidth: 1
                },
                {
                    label: 'Unique IPs',
                    data: uniqueIps,
                    backgroundColor: 'rgba(16, 185, 129, 0.7)',
                    borderColor: '#10b981',
                    borderWidth: 1
                },
                {
                    label: 'Avg Requests per IP',
                    data: avgPerIp,
                    type: 'line',
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Monthly Summary'
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
                    title: {
                        display: true,
                        text: 'Count'
                    }
                }
            }
        }
    });
}

async function changeErrorTrend(period) {
    try {
        const response = await fetch(`${API_BASE}/historical/metrics`);
        if (!response.ok) return;
        
        const data = await response.json();
        let trendData = [];
        
        if (period === 'daily' && data.daily) {
            trendData = data.daily.slice(-14); // Last 14 days
        } else if (period === 'weekly' && data.weekly) {
            trendData = data.weekly;
        } else if (period === 'monthly' && data.monthly) {
            trendData = data.monthly;
        }
        
        if (trendData.length > 0) {
            createErrorTrendChart(trendData, period);
        }
    } catch (error) {
        console.error('Error loading error trend:', error);
    }
}

function createErrorTrendChart(data, period) {
    const canvas = document.getElementById('errorTrendChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Clear existing chart
    if (errorTrendChart) {
        errorTrendChart.destroy();
    }
    
    const labels = data.map(d => {
        if (period === 'daily') return d.date.split('-').slice(1).join('-');
        if (period === 'weekly') return `Week ${d.week.split('-W')[1]}`;
        if (period === 'monthly') return d.month.split('-')[1];
        return '';
    });
    
    const errorRates = data.map(d => d.error_rate * 100);
    
    errorTrendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Error Rate %',
                data: errorRates,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
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
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: value => value + '%'
                    }
                }
            }
        }
    });
}

function updateComparisonChart(data) {
    const comparisonDiv = document.getElementById('periodComparison');
    if (!comparisonDiv) return;
    
    if (!data.current || !data.previous) {
        comparisonDiv.innerHTML = '<div class="alert alert-light">Not enough data for comparison</div>';
        return;
    }
    
    let html = '<div class="row g-3">';
    
    const metrics = ['requests', 'unique_ips', 'errors', 'error_rate'];
    const metricNames = {
        'requests': 'Requests',
        'unique_ips': 'Unique IPs',
        'errors': 'Errors',
        'error_rate': 'Error Rate'
    };
    const metricIcons = {
        'requests': 'fa-globe',
        'unique_ips': 'fa-network-wired',
        'errors': 'fa-exclamation-triangle',
        'error_rate': 'fa-percentage'
    };
    
    metrics.forEach(metric => {
        const current = metric === 'error_rate' 
            ? (data.current[metric] * 100).toFixed(1) + '%'
            : data.current[metric].toLocaleString();
        
        const previous = metric === 'error_rate'
            ? (data.previous[metric] * 100).toFixed(1) + '%'
            : data.previous[metric].toLocaleString();
        
        const change = data.changes[metric];
        const isPositive = metric === 'error_rate' ? change < 0 : change > 0;
        const changeClass = isPositive ? 'comparison-positive' : 'comparison-negative';
        const changeIcon = isPositive ? 'fa-arrow-up' : 'fa-arrow-down';
        const changeText = Math.abs(change).toFixed(1);
        
        html += `
        <div class="col-md-6 col-lg-3">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="text-muted mb-1">${metricNames[metric]}</h6>
                        <h4 class="mb-0">${current}</h4>
                        <small class="text-muted">Previous: ${previous}</small>
                    </div>
                    <div class="stat-icon" style="background: #e0f2fe; color: #0369a1;">
                        <i class="fas ${metricIcons[metric]}"></i>
                    </div>
                </div>
                <div class="mt-2">
                    <small class="${changeClass} fw-bold">
                        <i class="fas ${changeIcon} me-1"></i>
                        ${metric === 'error_rate' ? changeText + ' pp' : changeText + '%'}
                        ${metric === 'error_rate' ? (isPositive ? 'improvement' : 'increase') : (isPositive ? 'increase' : 'decrease')}
                    </small>
                </div>
            </div>
        </div>
        `;
    });
    
    html += '</div>';
    comparisonDiv.innerHTML = html;
}

function createTimelineViewChart(data, mode) {
    const canvas = document.getElementById('timelineViewChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Clear existing chart
    if (timelineViewChart) {
        timelineViewChart.destroy();
    }
    
    const timestamps = data.timestamps || [];
    const requestCounts = data.request_counts || [];
    
    if (timestamps.length === 0) {
        timelineViewChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['No data'],
                datasets: [{
                    label: 'Requests',
                    data: [0],
                    borderColor: '#e2e8f0',
                    backgroundColor: 'rgba(226, 232, 240, 0.1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'No timeline data available'
                    }
                }
            }
        });
        return;
    }
    
    timelineViewChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timestamps,
            datasets: [{
                label: 'Requests',
                data: requestCounts,
                borderColor: '#2563eb',
                backgroundColor: 'rgba(37, 99, 235, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Historical Timeline'
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
    let container = document.querySelector('.toast-container');
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
        if (modal) {
            modal.hide();
        }
        
        // Wait a moment for backend to process, then reload current view
        setTimeout(() => {
            switch(currentView) {
                case 'dashboard':
                    loadDashboardData();
                    break;
                case 'logs':
                    loadLogs();
                    break;
                case 'analytics':
                    loadAnalytics();
                    break;
                case 'historical':
                    loadHistoricalMetrics();
                    loadPeriodComparison();
                    break;
                case 'timeline':
                    loadTimelineViewData();
                    break;
                case 'alerts':
                    loadAlerts();
                    break;
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
    if (modal) {
        modal.hide();
    }
}

async function loadFilteredLogs(query) {
    try {
        const response = await fetch(`${API_BASE}/logs?${query}`);
        if (!response.ok) {
            throw new Error(`Filter API error: ${response.status}`);
        }
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
    
    // Fix WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/logs`;
    
    websocket = new WebSocket(wsUrl);
    
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
    if (!tableBody) return;
    
    // Insert at beginning
    const time = new Date().toLocaleTimeString();
    
    const row = document.createElement('tr');
    row.className = 'log-row';
    row.innerHTML = `
        <td><small>${time}</small></td>
        <td><span class="ip-badge">${logData.client_ip || 'Unknown'}</span></td>
        <td><span class="badge bg-light text-dark">${logData.method || 'GET'}</span></td>
        <td><small>${truncateText(logData.endpoint || '', 40)}</small></td>
        <td><span class="status-${Math.floor((logData.status || 200)/100)}xx fw-bold">${logData.status || 200}</span></td>
    `;
    
    tableBody.insertBefore(row, tableBody.firstChild);
    
    // Limit number of rows
    if (tableBody.children.length > 100) {
        tableBody.removeChild(tableBody.lastChild);
    }
}

function clearRealtimeLogs() {
    const tableBody = document.getElementById('realtimeTable');
    if (tableBody) {
        tableBody.innerHTML = '';
    }
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
        const canvas = document.getElementById(chartId);
        if (canvas) {
            const ctx = canvas.getContext('2d');
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
