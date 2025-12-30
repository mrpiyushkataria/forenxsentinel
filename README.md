# ForenX-NGINX Sentinel

Advanced NGINX Log Forensic Dashboard for Security Analysis and Threat Detection.

## Features

- **Complete NGINX Log Analysis**: Parse access and error logs in multiple formats
- **Real-time Monitoring**: Live log streaming via WebSockets
- **Attack Detection**: SQL injection, XSS, path traversal, brute force, DoS
- **Data Exfiltration Detection**: Identify large data transfers
- **Interactive Dashboard**: Charts, graphs, and visualizations
- **Forensic Integrity**: File hashing for tamper detection
- **Export Functionality**: CSV/JSON export of filtered logs
- **Extensible Architecture**: Ready for Apache, MySQL, PHP logs

## Quick Start

### Method 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/forenxsentinel.git
cd forenxsentinel

# Start with Docker Compose
docker-compose up -d

# Access dashboard at http://localhost:8080
# API at http://localhost:8000
