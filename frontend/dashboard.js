/**
 * ForenX-NGINX Sentinel Pro - Enhanced Dashboard
 * Professional visualizations with Chart.js and advanced analytics
 */

const API_BASE = '/api';
let currentView = 'dashboard';
let currentLogsPage = 1;
let logsTotalPages = 1;
let realtimeEnabled = false;
let websocket = null;

// Chart instances for professional visualization
let charts = {
    timeline: null,
    geoMap: null,
    statusDonut: null,
    trafficHeatmap: null,
    endpointPerformance: null,
    bandwidthChart: null,
    responseTimeChart: null,
    userAgentChart: null,
    attackTrendChart: null,
    hourlyPattern: null,
    dailyPattern: null
};

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    initDashboard();
    setupEventListeners();
    loadDashboardData();
    initializeProfessionalCharts();
});

function initDashboard() {
    // Set up professional theme
    document.body.classList.add('dashboard-pro');
    
    // Initialize tooltips
    initTooltips();
    
    // Initialize real-time updates
    initRealtimeUpdates();
}

function setupEventListeners() {
    // File upload with drag and drop
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    
    if (dropZone) {
        dropZone.addEventListener('dragover', handleDragOver);
        dropZone.addEventListener('dragleave', handleDragLeave);
        dropZone.addEventListener('drop', handleDrop);
        dropZone.addEventListener('click', () => fileInput.click());
    }
    
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }
    
    // View switchers
    document.querySelectorAll('.view-switcher').forEach(btn => {
        btn.addEventListener('click', function() {
            const view = this.dataset.view;
            switchView(view);
        });
    });
    
    // Filter controls
    document.querySelectorAll('.filter-control').forEach(control => {
        control.addEventListener('change', applyFilters);
    });
    
    // Export buttons
    document.getElementById('exportCsv')?.addEventListener('click', exportToCSV);
    document.getElementById('exportJson')?.addEventListener('click', exportToJSON);
    document.getElementById('exportPdf')?.addEventListener('click', exportToPDF);
}

function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.add('dragover');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.remove('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length) {
        document.getElementById('fileInput').files = files;
        handleFileSelect({ target: document.getElementById('fileInput') });
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    const fileList = document.getElementById('fileList');
    
    if (!fileList) return;
    
    fileList.innerHTML = '';
    
    if (files.length > 0) {
        const list = document.createElement('div');
        list.className = 'file-list';
        
        Array.from(files).forEach(file => {
            const item = document.createElement('div');
            item.className = 'file-item';
            item.innerHTML = `
                <i class="fas fa-file-alt"></i>
                <span class="file-name">${file.name}</span>
                <span class="file-size">${formatFileSize(file.size)}</span>
            `;
            list.appendChild(item);
        });
        
        fileList.appendChild(list);
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Professional Chart Initialization
function initializeProfessionalCharts() {
    // Initialize with empty professional charts
    const chartConfigs = {
        timeline: {
            type: 'line',
            options: getProfessionalLineOptions('Request Timeline')
        },
        statusDonut: {
            type: 'doughnut',
            options: getProfessionalDonutOptions('Status Distribution')
        },
        trafficHeatmap: {
            type: 'bar',
            options: getProfessionalBarOptions('Traffic Heatmap')
        },
        endpointPerformance: {
            type: 'horizontalBar',
            options: getProfessionalHorizontalBarOptions('Endpoint Performance')
        },
        bandwidthChart: {
            type: 'line',
            options: getProfessionalLineOptions('Bandwidth Usage')
        },
        responseTimeChart: {
            type: 'line',
            options: getProfessionalLineOptions('Response Times')
        }
    };
    
    // Initialize each chart
    Object.keys(chartConfigs).forEach(chartId => {
        const canvas = document.getElementById(chartId + 'Chart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const config = chartConfigs[chartId];
            
            charts[chartId] = new Chart(ctx, {
                type: config.type,
                data: { datasets: [] },
                options: config.options
            });
        }
    });
}

// Professional Chart Options
function getProfessionalLineOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: true,
                position: 'top',
                labels: {
                    font: { size: 12 },
                    padding: 20
                }
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                titleFont: { size: 14 },
                bodyFont: { size: 13 },
                padding: 12,
                cornerRadius: 6
            }
        },
        scales: {
            x: {
                grid: {
                    color: 'rgba(0, 0, 0, 0.05)'
                },
                ticks: {
                    font: { size: 11 }
                }
            },
            y: {
                grid: {
                    color: 'rgba(0, 0, 0, 0.05)'
                },
                ticks: {
                    font: { size: 11 }
                },
                beginAtZero: true
            }
        }
    };
}

function getProfessionalDonutOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
            legend: {
                position: 'right',
                labels: {
                    font: { size: 12 },
                    padding: 15
                }
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                callbacks: {
                    label: function(context) {
                        const label = context.label || '';
                        const value = context.raw || 0;
                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                        const percentage = Math.round((value / total) * 100);
                        return `${label}: ${value} (${percentage}%)`;
                    }
                }
            }
        }
    };
}

function getProfessionalBarOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: false,
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
                    font: { size: 11 }
                }
            },
            y: {
                grid: {
                    color: 'rgba(0, 0, 0, 0.05)'
                },
                ticks: {
                    font: { size: 11 }
                },
                beginAtZero: true
            }
        }
    };
}

function getProfessionalHorizontalBarOptions(title) {
    return {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            x: {
                grid: {
                    color: 'rgba(0, 0, 0, 0.05)'
                },
                ticks: {
                    font: { size: 11 }
                },
                beginAtZero: true
            },
            y: {
                grid: {
                    display: false
                },
                ticks: {
                    font: { size: 11 }
                }
            }
        }
    };
}

// Advanced Data Loading Functions
async function loadDashboardData() {
    try {
        showLoading('dashboard');
        
        // Load multiple metrics in parallel
        const [
            metrics,
            timeline,
            geoData,
            statusData,
            endpointData,
            patterns
        ] = await Promise.all([
            fetchData('/api/metrics?detailed=true'),
            fetchData('/api/timeline?interval=hour&time_range=24h'),
            fetchData('/api/geo-distribution'),
            fetchData('/api/status-analysis'),
            fetchData('/api/endpoint-performance?limit=15'),
            fetchData('/api/traffic-patterns')
        ]);
        
        // Update all dashboard components
        updateProfessionalStatsCards(metrics);
        updateTimelineChart(timeline);
        updateStatusDonutChart(statusData);
        updateGeoVisualization(geoData);
        updateEndpointPerformanceChart(endpointData);
        updateTrafficPatterns(patterns);
        updateAlertsTable();
        updateAttackTrends();
        
        hideLoading('dashboard');
        showToast('Dashboard loaded successfully', 'success');
        
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showToast('Error loading dashboard data', 'danger');
        hideLoading('dashboard');
    }
}

async function fetchData(endpoint) {
    const response = await fetch(API_BASE + endpoint);
    if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
    }
    return response.json();
}

function updateProfessionalStatsCards(metrics) {
    const statsContainer = document.getElementById('statsCards');
    if (!statsContainer) return;
    
    const cards = [
        {
            title: 'Total Requests',
            value: metrics.total_requests?.toLocaleString() || '0',
            icon: 'fa-globe',
            color: 'primary',
            change: '+12%',
            trend: 'up'
        },
        {
            title: 'Unique IPs',
            value: metrics.unique_ips?.toLocaleString() || '0',
            icon: 'fa-users',
            color: 'success',
            change: '+5%',
            trend: 'up'
        },
        {
            title: 'Bandwidth',
            value: metrics.formatted_bandwidth || '0 MB/s',
            icon: 'fa-chart-line',
            color: 'info',
            change: '+18%',
            trend: 'up'
        },
        {
            title: 'Error Rate',
            value: metrics.error_rate ? `${(metrics.error_rate * 100).toFixed(1)}%` : '0%',
            icon: 'fa-exclamation-triangle',
            color: metrics.error_rate > 0.1 ? 'danger' : 'warning',
            change: metrics.error_rate > 0.1 ? '+8%' : '-2%',
            trend: metrics.error_rate > 0.1 ? 'up' : 'down'
        },
        {
            title: 'Avg Response',
            value: metrics.avg_response_time ? `${(metrics.avg_response_time * 1000).toFixed(0)}ms` : '0ms',
            icon: 'fa-tachometer-alt',
            color: 'secondary',
            change: '-15%',
            trend: 'down'
        },
        {
            title: 'Requests/sec',
            value: metrics.requests_per_second?.toFixed(2) || '0',
            icon: 'fa-bolt',
            color: 'warning',
            change: '+22%',
            trend: 'up'
        }
    ];
    
    statsContainer.innerHTML = cards.map(card => `
        <div class="col-xl-2 col-lg-4 col-md-6">
            <div class="stat-card-pro ${card.color}">
                <div class="stat-icon">
                    <i class="fas ${card.icon}"></i>
                </div>
                <div class="stat-content">
                    <h3>${card.value}</h3>
                    <p>${card.title}</p>
                    <div class="stat-trend ${card.trend}">
                        <i class="fas fa-arrow-${card.trend}"></i>
                        ${card.change}
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function updateTimelineChart(data) {
    if (!charts.timeline || !data.timestamps) return;
    
    const datasets = [{
        label: 'Requests',
        data: data.values || [],
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        borderWidth: 2,
        tension: 0.4,
        fill: true
    }];
    
    charts.timeline.data = {
        labels: data.timestamps,
        datasets: datasets
    };
    
    charts.timeline.update();
}

function updateStatusDonutChart(data) {
    if (!charts.statusDonut || !data.distribution) return;
    
    const labels = Object.keys(data.distribution);
    const values = Object.values(data.distribution);
    
    // Professional color palette
    const colors = [
        '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
        '#3b82f6', '#ec4899', '#f97316', '#84cc16'
    ];
    
    charts.statusDonut.data = {
        labels: labels,
        datasets: [{
            data: values,
            backgroundColor: colors.slice(0, labels.length),
            borderWidth: 1,
            borderColor: '#fff'
        }]
    };
    
    charts.statusDonut.update();
}

function updateGeoVisualization(data) {
    // This would integrate with a map library like Leaflet or Google Maps
    // For now, display a table with geographic data
    const geoContainer = document.getElementById('geoData');
    if (!geoContainer || !data.countries) return;
    
    const countries = Object.entries(data.countries)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    geoContainer.innerHTML = `
        <div class="geo-table">
            <h6>Top Countries by Requests</h6>
            <table class="table">
                <thead>
                    <tr>
                        <th>Country</th>
                        <th>Requests</th>
                        <th>% of Total</th>
                    </tr>
                </thead>
                <tbody>
                    ${countries.map(([country, count]) => `
                        <tr>
                            <td>
                                <i class="fas fa-globe-americas me-2"></i>
                                ${country}
                            </td>
                            <td>${count.toLocaleString()}</td>
                            <td>
                                <div class="progress">
                                    <div class="progress-bar" 
                                         style="width: ${(count / data.total_requests * 100).toFixed(1)}%">
                                        ${(count / data.total_requests * 100).toFixed(1)}%
                                    </div>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    
    // If coordinates data is available, initialize map
    if (data.coordinates && data.coordinates.length > 0) {
        initGeographicMap(data.coordinates);
    }
}

function initGeographicMap(coordinates) {
    // Placeholder for map initialization
    // In production, integrate with Leaflet/Mapbox/Google Maps
    console.log('Initializing map with', coordinates.length, 'coordinates');
}

function updateEndpointPerformanceChart(data) {
    if (!charts.endpointPerformance || !data.endpoints) return;
    
    const endpoints = Object.entries(data.endpoints)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 10);
    
    const labels = endpoints.map(([endpoint]) => 
        endpoint.length > 30 ? endpoint.substring(0, 27) + '...' : endpoint
    );
    const values = endpoints.map(([, stats]) => stats.count);
    const responseTimes = endpoints.map(([, stats]) => 
        stats.avg_response_time ? (stats.avg_response_time * 1000).toFixed(0) : 0
    );
    
    charts.endpointPerformance.data = {
        labels: labels,
        datasets: [
            {
                label: 'Requests',
                data: values,
                backgroundColor: 'rgba(59, 130, 246, 0.8)',
                borderColor: '#3b82f6',
                borderWidth: 1
            },
            {
                label: 'Response Time (ms)',
                data: responseTimes,
                backgroundColor: 'rgba(239, 68, 68, 0.8)',
                borderColor: '#ef4444',
                borderWidth: 1
            }
        ]
    };
    
    charts.endpointPerformance.update();
}

function updateTrafficPatterns(data) {
    if (!data.hourly_distribution) return;
    
    // Update hourly pattern chart
    if (charts.hourlyPattern) {
        const hours = Object.keys(data.hourly_distribution).sort();
        const counts = hours.map(hour => data.hourly_distribution[hour]);
        
        charts.hourlyPattern.data = {
            labels: hours,
            datasets: [{
                label: 'Requests per Hour',
                data: counts,
                borderColor: '#8b5cf6',
                backgroundColor: 'rgba(139, 92, 246, 0.1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true
            }]
        };
        
        charts.hourlyPattern.update();
    }
    
    // Update daily pattern chart
    if (charts.dailyPattern && data.daily_distribution) {
        const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        const counts = days.map(day => data.daily_distribution[day] || 0);
        
        charts.dailyPattern.data = {
            labels: days,
            datasets: [{
                label: 'Requests',
                data: counts,
                backgroundColor: days.map((_, i) => 
                    i < 5 ? 'rgba(59, 130, 246, 0.8)' : 'rgba(139, 92, 246, 0.8)'
                ),
                borderColor: days.map((_, i) => 
                    i < 5 ? '#3b82f6' : '#8b5cf6'
                ),
                borderWidth: 1
            }]
        };
        
        charts.dailyPattern.update();
    }
}

function updateAlertsTable() {
    // Load and display alerts in a professional table
    fetchData('/api/alerts?limit=10').then(data => {
        const table = document.getElementById('alertsTable');
        if (!table) return;
        
        const alerts = data.alerts || [];
        
        if (alerts.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-4">
                        <i class="fas fa-check-circle text-success me-2"></i>
                        No security alerts detected
                    </td>
                </tr>
            `;
            return;
        }
        
        table.innerHTML = alerts.map(alert => `
            <tr class="alert-row severity-${getSeverityLevel(alert.confidence)}">
                <td>
                    <span class="timestamp">${formatDateTime(alert.timestamp)}</span>
                </td>
                <td>
                    <span class="alert-badge ${getAlertBadgeClass(alert.attack_type)}">
                        ${alert.attack_type}
                    </span>
                </td>
                <td>
                    <span class="ip-address" title="${alert.client_ip}">
                        <i class="fas fa-network-wired me-1"></i>
                        ${truncateText(alert.client_ip, 15)}
                    </span>
                </td>
                <td>
                    <span class="endpoint" title="${alert.endpoint}">
                        ${truncateText(alert.endpoint, 25)}
                    </span>
                </td>
                <td>
                    <div class="confidence-meter">
                        <div class="confidence-fill" 
                             style="width: ${alert.confidence * 100}%">
                            ${Math.round(alert.confidence * 100)}%
                        </div>
                    </div>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" 
                            onclick="viewAlertDetails('${alert.id}')">
                        <i class="fas fa-search"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }).catch(error => {
        console.error('Error loading alerts:', error);
    });
}

function getSeverityLevel(confidence) {
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
}

function getAlertBadgeClass(attackType) {
    const typeMap = {
        'SQL Injection': 'danger',
        'XSS': 'warning',
        'DoS': 'danger',
        'Brute Force': 'danger',
        'Path Traversal': 'warning'
    };
    return typeMap[attackType] || 'secondary';
}

function updateAttackTrends() {
    // Load attack trends for visualization
    fetchData('/api/advanced-analytics').then(data => {
        if (!data.security || !charts.attackTrendChart) return;
        
        const trends = data.security.attack_trend;
        if (trends && trends.by_hour) {
            const hours = Object.keys(trends.by_hour).sort();
            const counts = hours.map(hour => trends.by_hour[hour]);
            
            charts.attackTrendChart.data = {
                labels: hours,
                datasets: [{
                    label: 'Attack Attempts',
                    data: counts,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }]
            };
            
            charts.attackTrendChart.update();
        }
    });
}

// Enhanced Analytics Functions
async function loadAdvancedAnalytics() {
    try {
        showLoading('analytics');
        
        const analytics = await fetchData('/api/advanced-analytics');
        
        updatePerformanceMetrics(analytics.performance);
        updateSecurityMetrics(analytics.security);
        updateTrafficMetrics(analytics.traffic);
        updateUserMetrics(analytics.users);
        updateContentMetrics(analytics.content);
        
        hideLoading('analytics');
        showToast('Advanced analytics loaded', 'success');
        
    } catch (error) {
        console.error('Error loading advanced analytics:', error);
        showToast('Error loading analytics', 'danger');
        hideLoading('analytics');
    }
}

function updatePerformanceMetrics(metrics) {
    const container = document.getElementById('performanceMetrics');
    if (!container || !metrics) return;
    
    container.innerHTML = `
        <div class="row">
            <div class="col-md-3">
                <div class="metric-card">
                    <h6>Avg Response Time</h6>
                    <h3>${(metrics.avg_response_time * 1000).toFixed(0)}ms</h3>
                    <small>P95: ${(metrics.p95_response_time * 1000).toFixed(0)}ms</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card">
                    <h6>Throughput</h6>
                    <h3>${metrics.throughput.toFixed(1)}</h3>
                    <small>requests per hour</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card">
                    <h6>Bandwidth</h6>
                    <h3>${(metrics.bandwidth).toFixed(1)}MB</h3>
                    <small>total transferred</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card">
                    <h6>Avg Payload</h6>
                    <h3>${formatBytes(metrics.avg_payload_size)}</h3>
                    <small>per request</small>
                </div>
            </div>
        </div>
    `;
}

function updateSecurityMetrics(metrics) {
    const container = document.getElementById('securityMetrics');
    if (!container || !metrics) return;
    
    const highRiskIPs = metrics.high_risk_ips || [];
    
    container.innerHTML = `
        <div class="security-summary">
            <div class="alert-count">
                <h3>${metrics.total_alerts || 0}</h3>
                <p>Total Security Alerts</p>
            </div>
            
            ${highRiskIPs.length > 0 ? `
                <div class="high-risk-ips">
                    <h6>High Risk IPs</h6>
                    <div class="ip-list">
                        ${highRiskIPs.map(ip => `
                            <div class="ip-item">
                                <span class="ip-address">${ip.ip}</span>
                                <span class="ip-alerts">${ip.alert_count} alerts</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

// Utility Functions
function formatDateTime(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.add('loading');
    }
}

function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.remove('loading');
    }
}

function showToast(message, type = 'info') {
    // Create professional toast notification
    const toast = document.createElement('div');
    toast.className = `toast-pro toast-${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas fa-${getToastIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    const container = document.getElementById('toastContainer') || createToastContainer();
    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, 5000);
}

function getToastIcon(type) {
    const icons = {
        success: 'check-circle',
        danger: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container-pro';
    document.body.appendChild(container);
    return container;
}

// Export Functions
async function exportToCSV() {
    try {
        const data = await fetchData('/api/export-analytics?format=csv');
        if (data.csv_data) {
            downloadFile(data.csv_data, 'analytics.csv', 'text/csv');
            showToast('CSV export started', 'success');
        }
    } catch (error) {
        console.error('Export error:', error);
        showToast('Export failed', 'danger');
    }
}

async function exportToJSON() {
    try {
        const data = await fetchData('/api/export-analytics?format=json');
        downloadFile(JSON.stringify(data, null, 2), 'analytics.json', 'application/json');
        showToast('JSON export started', 'success');
    } catch (error) {
        console.error('Export error:', error);
        showToast('Export failed', 'danger');
    }
}

async function exportToPDF() {
    showToast('PDF export feature coming soon', 'info');
    // Implement PDF export using jsPDF or similar library
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Real-time Functions
function initRealtimeUpdates() {
    // Connect to WebSocket for real-time updates
    connectWebSocket();
    
    // Set up periodic updates
    setInterval(() => {
        if (currentView === 'dashboard') {
            refreshDashboardMetrics();
        }
    }, 30000); // Update every 30 seconds
}

async function refreshDashboardMetrics() {
    try {
        const metrics = await fetchData('/api/metrics?time_range=1h');
        updateProfessionalStatsCards(metrics);
    } catch (error) {
        console.error('Error refreshing metrics:', error);
    }
}

function connectWebSocket() {
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        return;
    }
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/analytics`;
    
    websocket = new WebSocket(wsUrl);
    
    websocket.onopen = () => {
        console.log('WebSocket connected for real-time analytics');
        showToast('Real-time analytics connected', 'success');
    };
    
    websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleRealtimeUpdate(data);
    };
    
    websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    websocket.onclose = () => {
        console.log('WebSocket disconnected');
        // Try to reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
    };
}

function handleRealtimeUpdate(data) {
    if (data.type === 'analytics_update') {
        // Update dashboard with real-time data
        if (currentView === 'dashboard') {
            updateProfessionalStatsCards(data.metrics);
            
            // Add real-time notification for new alerts
            if (data.alerts_count > lastAlertCount) {
                showNewAlertNotification(data.alerts_count - lastAlertCount);
            }
            lastAlertCount = data.alerts_count;
        }
    }
}

let lastAlertCount = 0;

function showNewAlertNotification(count) {
    const notification = document.createElement('div');
    notification.className = 'alert-notification';
    notification.innerHTML = `
        <i class="fas fa-shield-alt"></i>
        <span>${count} new security alert${count > 1 ? 's' : ''} detected</span>
        <button onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

// View Switching
function switchView(viewName) {
    // Hide all views
    document.querySelectorAll('.view-content').forEach(view => {
        view.style.display = 'none';
    });
    
    // Show selected view
    const viewElement = document.getElementById(viewName + 'View');
    if (viewElement) {
        viewElement.style.display = 'block';
    }
    
    // Update active state
    document.querySelectorAll('.view-switcher').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.view === viewName) {
            btn.classList.add('active');
        }
    });
    
    // Load view-specific data
    currentView = viewName;
    loadViewData(viewName);
}

function loadViewData(viewName) {
    switch (viewName) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'analytics':
            loadAdvancedAnalytics();
            break;
        case 'geo':
            loadGeographicData();
            break;
        case 'security':
            loadSecurityData();
            break;
        case 'performance':
            loadPerformanceData();
            break;
        default:
            break;
    }
}

async function loadGeographicData() {
    try {
        const geoData = await fetchData('/api/geo-distribution');
        updateGeoVisualization(geoData);
    } catch (error) {
        console.error('Error loading geographic data:', error);
    }
}

async function loadSecurityData() {
    try {
        const securityData = await fetchData('/api/advanced-analytics');
        updateSecurityMetrics(securityData.security);
    } catch (error) {
        console.error('Error loading security data:', error);
    }
}

async function loadPerformanceData() {
    try {
        const performanceData = await fetchData('/api/advanced-analytics');
        updatePerformanceMetrics(performanceData.performance);
    } catch (error) {
        console.error('Error loading performance data:', error);
    }
}

// Initialize tooltips
function initTooltips() {
    // Initialize Bootstrap tooltips if available
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    }
}

// Make functions available globally
window.switchView = switchView;
window.viewAlertDetails = viewAlertDetails;
window.exportToCSV = exportToCSV;
window.exportToJSON = exportToJSON;
window.exportToPDF = exportToPDF;
