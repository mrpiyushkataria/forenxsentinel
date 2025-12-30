#!/usr/bin/env python3
"""
ForenX-NGINX Sentinel - Advanced NGINX Forensic Dashboard
Backend Server with FastAPI
"""
import os
import json
import time
import hashlib
import asyncio
import uvicorn
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import logging

# Import custom modules
from log_parser import NGINXParser
from detection_engine import DetectionEngine
from models import LogEntry, AggregatedMetrics, AttackAlert

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ForenX-NGINX Sentinel",
    description="Advanced NGINX Log Forensic Dashboard",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
parser = NGINXParser()
detector = DetectionEngine()

# In-memory storage (replace with DB in production)
logs_data = {
    "access_logs": [],
    "error_logs": [],
    "parsed_logs": [],
    "alerts": [],
    "metrics": {},
    "file_hashes": {}  # For tamper detection
}

class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                self.active_connections.remove(connection)

manager = ConnectionManager()

@app.get("/")
async def root():
    return {"message": "ForenX-NGINX Sentinel API", "status": "running"}

@app.post("/api/upload-logs")
async def upload_logs(
    files: List[UploadFile] = File(...),
    log_type: str = Form("auto"),
    timezone: str = Form("UTC")
):
    """Upload and parse NGINX log files"""
    results = {
        "files_processed": [],
        "total_records": 0,
        "alerts_found": 0,
        "file_hashes": []
    }
    
    for file in files:
        try:
            # Read file content
            content = await file.read()
            
            # Calculate hash for integrity
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Detect log type
            if log_type == "auto":
                detected_type = parser.detect_log_type(content.decode('utf-8', errors='ignore')[:1000])
            else:
                detected_type = log_type
            
            # Parse logs
            if detected_type == "access":
                parsed = parser.parse_access_log(content.decode('utf-8', errors='ignore'))
                logs_data["access_logs"].extend(parsed)
                logs_data["parsed_logs"].extend(parsed)
            elif detected_type == "error":
                parsed = parser.parse_error_log(content.decode('utf-8', errors='ignore'))
                logs_data["error_logs"].extend(parsed)
                logs_data["parsed_logs"].extend(parsed)
            
            # Run detection
            alerts = detector.analyze_logs(parsed)
            logs_data["alerts"].extend(alerts)
            
            # Store hash for tamper detection
            logs_data["file_hashes"][file.filename] = {
                "hash": file_hash,
                "timestamp": datetime.now().isoformat(),
                "size": len(content)
            }
            
            results["files_processed"].append({
                "filename": file.filename,
                "type": detected_type,
                "records": len(parsed),
                "hash": file_hash,
                "alerts": len(alerts)
            })
            results["total_records"] += len(parsed)
            results["alerts_found"] += len(alerts)
            
        except Exception as e:
            logger.error(f"Error processing {file.filename}: {e}")
            results["files_processed"].append({
                "filename": file.filename,
                "error": str(e)
            })
    
    # Update metrics
    update_metrics()
    
    return results

@app.get("/api/metrics")
async def get_metrics(time_range: str = "24h"):
    """Get aggregated metrics for dashboard"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs loaded"}
    
    # Filter by time range
    now = datetime.now()
    if time_range == "1h":
        cutoff = now - timedelta(hours=1)
    elif time_range == "6h":
        cutoff = now - timedelta(hours=6)
    elif time_range == "24h":
        cutoff = now - timedelta(hours=24)
    elif time_range == "7d":
        cutoff = now - timedelta(days=7)
    else:
        cutoff = datetime.min
    
    filtered_logs = [
        log for log in logs_data["parsed_logs"] 
        if log.timestamp >= cutoff
    ]
    
    # Calculate metrics
    metrics = calculate_metrics(filtered_logs)
    return metrics

@app.get("/api/logs")
async def get_logs(
    page: int = 1,
    limit: int = 100,
    ip_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    endpoint_filter: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None
):
    """Get filtered logs with pagination"""
    logs = logs_data["parsed_logs"]
    
    # Apply filters
    if ip_filter:
        logs = [log for log in logs if ip_filter in log.client_ip]
    
    if status_filter:
        logs = [log for log in logs if str(log.status) == status_filter]
    
    if endpoint_filter:
        logs = [log for log in logs if endpoint_filter in log.endpoint]
    
    if time_start:
        start_time = datetime.fromisoformat(time_start.replace('Z', '+00:00'))
        logs = [log for log in logs if log.timestamp >= start_time]
    
    if time_end:
        end_time = datetime.fromisoformat(time_end.replace('Z', '+00:00'))
        logs = [log for log in logs if log.timestamp <= end_time]
    
    # Paginate
    total = len(logs)
    start = (page - 1) * limit
    end = start + limit
    paginated_logs = logs[start:end]
    
    return {
        "logs": [log.dict() for log in paginated_logs],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit
        }
    }

@app.get("/api/alerts")
async def get_alerts(severity: Optional[str] = None, limit: int = 50):
    """Get security alerts"""
    alerts = logs_data["alerts"]
    
    if severity:
        alerts = [alert for alert in alerts if alert.severity == severity]
    
    alerts = alerts[-limit:]  # Get latest alerts
    
    return {"alerts": [alert.dict() for alert in alerts]}

@app.get("/api/top-data")
async def get_top_data(
    category: str = "ips",
    limit: int = 10,
    time_range: str = "24h"
):
    """Get top data for charts (IPs, endpoints, user-agents)"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs loaded"}
    
    # Filter by time
    now = datetime.now()
    cutoff = now - get_timedelta(time_range)
    filtered_logs = [
        log for log in logs_data["parsed_logs"] 
        if log.timestamp >= cutoff
    ]
    
    if category == "ips":
        # Top IPs by request count
        ip_counts = {}
        for log in filtered_logs:
            ip_counts[log.client_ip] = ip_counts.get(log.client_ip, 0) + 1
        
        top_data = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return {
            "labels": [item[0] for item in top_data],
            "values": [item[1] for item in top_data]
        }
    
    elif category == "endpoints":
        # Top endpoints by request count
        endpoint_counts = {}
        for log in filtered_logs:
            endpoint_counts[log.endpoint] = endpoint_counts.get(log.endpoint, 0) + 1
        
        top_data = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return {
            "labels": [item[0] for item in top_data],
            "values": [item[1] for item in top_data]
        }
    
    elif category == "user_agents":
        # Top user-agents
        ua_counts = {}
        for log in filtered_logs:
            if log.user_agent:
                ua = log.user_agent[:50]  # Truncate long UAs
                ua_counts[ua] = ua_counts.get(ua, 0) + 1
        
        top_data = sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return {
            "labels": [item[0] for item in top_data],
            "values": [item[1] for item in top_data]
        }
    
    elif category == "status_codes":
        # Status code distribution
        status_counts = {}
        for log in filtered_logs:
            status_counts[str(log.status)] = status_counts.get(str(log.status), 0) + 1
        
        return {
            "labels": list(status_counts.keys()),
            "values": list(status_counts.values())
        }

@app.get("/api/timeline")
async def get_timeline(
    interval: str = "hour",
    time_range: str = "24h"
):
    """Get timeline data for charts"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs loaded"}
    
    # Filter by time
    now = datetime.now()
    cutoff = now - get_timedelta(time_range)
    filtered_logs = [
        log for log in logs_data["parsed_logs"] 
        if log.timestamp >= cutoff
    ]
    
    # Group by time interval
    timeline = {}
    
    for log in filtered_logs:
        if interval == "minute":
            key = log.timestamp.strftime("%Y-%m-%d %H:%M")
        elif interval == "hour":
            key = log.timestamp.strftime("%Y-%m-%d %H:00")
        elif interval == "day":
            key = log.timestamp.strftime("%Y-%m-%d")
        else:
            key = log.timestamp.strftime("%Y-%m-%d %H:%M")
        
        timeline[key] = timeline.get(key, 0) + 1
    
    # Sort by time
    sorted_timeline = sorted(timeline.items(), key=lambda x: x[0])
    
    return {
        "timestamps": [item[0] for item in sorted_timeline],
        "request_counts": [item[1] for item in sorted_timeline]
    }

@app.post("/api/export")
async def export_logs(
    format: str = "csv",
    filters: Optional[Dict[str, Any]] = None
):
    """Export filtered logs to CSV or JSON"""
    logs = logs_data["parsed_logs"]
    
    # Apply filters if provided
    if filters:
        if filters.get("ip_filter"):
            logs = [log for log in logs if filters["ip_filter"] in log.client_ip]
        if filters.get("status_filter"):
            logs = [log for log in logs if str(log.status) == filters["status_filter"]]
        if filters.get("time_start"):
            start_time = datetime.fromisoformat(filters["time_start"].replace('Z', '+00:00'))
            logs = [log for log in logs if log.timestamp >= start_time]
    
    # Convert to list of dicts
    log_dicts = [log.dict() for log in logs]
    
    if format == "csv":
        # Create CSV
        df = pd.DataFrame(log_dicts)
        csv_path = "/tmp/exported_logs.csv"
        df.to_csv(csv_path, index=False)
        return FileResponse(csv_path, filename="nginx_logs_export.csv")
    
    elif format == "json":
        # Create JSON
        json_path = "/tmp/exported_logs.json"
        with open(json_path, 'w') as f:
            json.dump(log_dicts, f, indent=2, default=str)
        return FileResponse(json_path, filename="nginx_logs_export.json")

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time log streaming"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await asyncio.sleep(10)
            await websocket.send_json({"type": "heartbeat", "time": datetime.now().isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

def calculate_metrics(logs: List[LogEntry]) -> AggregatedMetrics:
    """Calculate aggregated metrics from logs"""
    if not logs:
        return AggregatedMetrics()
    
    total_requests = len(logs)
    unique_ips = len(set(log.client_ip for log in logs))
    total_bytes = sum(log.bytes_sent for log in logs if log.bytes_sent)
    
    # Status code counts
    status_2xx = sum(1 for log in logs if 200 <= log.status < 300)
    status_3xx = sum(1 for log in logs if 300 <= log.status < 400)
    status_4xx = sum(1 for log in logs if 400 <= log.status < 500)
    status_5xx = sum(1 for log in logs if 500 <= log.status < 600)
    
    # Error rate
    error_rate = (status_4xx + status_5xx) / total_requests if total_requests > 0 else 0
    
    # Request methods
    methods = {}
    for log in logs:
        methods[log.method] = methods.get(log.method, 0) + 1
    
    # Top endpoints (by request count)
    endpoint_counts = {}
    for log in logs:
        endpoint_counts[log.endpoint] = endpoint_counts.get(log.endpoint, 0) + 1
    top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Top IPs (by request count)
    ip_counts = {}
    for log in logs:
        ip_counts[log.client_ip] = ip_counts.get(log.client_ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return AggregatedMetrics(
        total_requests=total_requests,
        unique_ips=unique_ips,
        total_bytes=total_bytes,
        status_2xx=status_2xx,
        status_3xx=status_3xx,
        status_4xx=status_4xx,
        status_5xx=status_5xx,
        error_rate=error_rate,
        request_methods=methods,
        top_endpoints=dict(top_endpoints),
        top_ips=dict(top_ips),
        timeframe_min=min(log.timestamp for log in logs) if logs else None,
        timeframe_max=max(log.timestamp for log in logs) if logs else None
    )

def update_metrics():
    """Update global metrics"""
    if logs_data["parsed_logs"]:
        logs_data["metrics"] = calculate_metrics(logs_data["parsed_logs"])

def get_timedelta(time_range: str) -> timedelta:
    """Convert time range string to timedelta"""
    if time_range == "1h":
        return timedelta(hours=1)
    elif time_range == "6h":
        return timedelta(hours=6)
    elif time_range == "24h":
        return timedelta(hours=24)
    elif time_range == "7d":
        return timedelta(days=7)
    elif time_range == "30d":
        return timedelta(days=30)
    else:
        return timedelta(hours=24)

# Mount frontend static files (for production)
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
