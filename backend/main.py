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
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import logging

# Import custom modules
from log_parser import NGINXParser
from detection_engine import DetectionEngine
from models import LogEntry, AggregatedMetrics, AttackAlert, ErrorLogEntry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ForenX-NGINX Sentinel",
    description="Advanced NGINX Log Forensic Dashboard",
    version="1.0.0"
)

# CORS middleware - allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
parser = NGINXParser()
detector = DetectionEngine()

# In-memory storage
logs_data = {
    "access_logs": [],
    "error_logs": [],
    "parsed_logs": [],
    "alerts": [],
    "metrics": {},
    "file_hashes": {}
}

class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                if connection in self.active_connections:
                    self.active_connections.remove(connection)

manager = ConnectionManager()

@app.get("/")
async def root():
    return {"message": "ForenX-NGINX Sentinel API", "status": "running", "version": "1.0.0"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/upload-logs")
async def upload_logs(
    files: List[UploadFile] = File(...),
    log_type: str = Form("auto")
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
            logger.info(f"Processing file: {file.filename}")
            
            # Read file content
            content = await file.read()
            
            # Calculate hash for integrity
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Decode content
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                # Try latin-1 as fallback
                content_str = content.decode('latin-1', errors='ignore')
            
            # Detect log type
            sample = content_str[:1000] if len(content_str) > 1000 else content_str
            if log_type == "auto":
                detected_type = parser.detect_log_type(sample)
            else:
                detected_type = log_type
            
            logger.info(f"Detected log type: {detected_type} for {file.filename}")
            
            # Parse logs based on type
            parsed = []
            if detected_type == "error":
                parsed = parser.parse_error_log(content_str)
                logs_data["error_logs"].extend(parsed)
            else:
                # Default to access log parsing
                parsed = parser.parse_access_log(content_str, detected_type)
                logs_data["access_logs"].extend(parsed)
            
            logs_data["parsed_logs"].extend(parsed)
            
            # Run detection on access logs only
            if detected_type != "error" and parsed:
                alerts = detector.analyze_logs(parsed)
                logs_data["alerts"].extend(alerts)
            else:
                alerts = []
            
            # Store hash for tamper detection
            logs_data["file_hashes"][file.filename] = {
                "hash": file_hash,
                "timestamp": datetime.now().isoformat(),
                "size": len(content),
                "type": detected_type
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
            
            logger.info(f"Parsed {len(parsed)} records from {file.filename}")
            
        except Exception as e:
            logger.error(f"Error processing {file.filename}: {str(e)}", exc_info=True)
            results["files_processed"].append({
                "filename": file.filename,
                "error": str(e),
                "success": False
            })
    
    # Update metrics if we have logs
    if logs_data["parsed_logs"]:
        update_metrics()
    
    # Broadcast update via WebSocket
    if results["total_records"] > 0:
        await manager.broadcast({
            "type": "upload_complete",
            "records": results["total_records"],
            "alerts": results["alerts_found"]
        })
    
    return results

@app.get("/api/metrics")
async def get_metrics(time_range: str = "24h"):
    """Get aggregated metrics for dashboard"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs loaded", "total_requests": 0}
    
    # Filter by time range
    now = datetime.now()
    cutoff = get_cutoff_time(time_range)
    
    filtered_logs = [
        log for log in logs_data["parsed_logs"] 
        if hasattr(log, 'timestamp') and log.timestamp >= cutoff
    ]
    
    # Calculate metrics
    metrics = calculate_metrics(filtered_logs)
    return metrics.dict()

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
    filtered_logs = []
    for log in logs:
        include = True
        
        if ip_filter and ip_filter not in log.client_ip:
            include = False
        
        if status_filter and str(log.status) != status_filter:
            include = False
        
        if endpoint_filter and endpoint_filter not in log.endpoint:
            include = False
        
        if time_start:
            try:
                start_time = datetime.fromisoformat(time_start.replace('Z', '+00:00'))
                if log.timestamp < start_time:
                    include = False
            except:
                pass
        
        if time_end:
            try:
                end_time = datetime.fromisoformat(time_end.replace('Z', '+00:00'))
                if log.timestamp > end_time:
                    include = False
            except:
                pass
        
        if include:
            filtered_logs.append(log)
    
    # Paginate
    total = len(filtered_logs)
    start = (page - 1) * limit
    end = start + limit
    paginated_logs = filtered_logs[start:end]
    
    return {
        "logs": [log.dict() for log in paginated_logs],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if limit > 0 else 0
        }
    }

@app.get("/api/alerts")
async def get_alerts(severity: Optional[str] = None, limit: int = 50):
    """Get security alerts"""
    alerts = logs_data["alerts"]
    
    # Sort by timestamp (newest first)
    alerts.sort(key=lambda x: x.timestamp, reverse=True)
    
    if severity:
        alerts = [alert for alert in alerts if alert.attack_type == severity]
    
    alerts = alerts[:limit]
    
    return {"alerts": [alert.dict() for alert in alerts]}

@app.get("/api/top-data")
async def get_top_data(
    category: str = "ips",
    limit: int = 10,
    time_range: str = "24h"
):
    """Get top data for charts"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs loaded", "labels": [], "values": []}
    
    # Filter by time
    cutoff = get_cutoff_time(time_range)
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
            if log.user_agent and log.user_agent != '-':
                ua = log.user_agent[:50]
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
            status = str(log.status)
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "labels": list(status_counts.keys()),
            "values": list(status_counts.values())
        }
    
    else:
        return {"labels": [], "values": []}

@app.get("/api/timeline")
async def get_timeline(
    interval: str = "hour",
    time_range: str = "24h"
):
    """Get timeline data for charts"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs loaded", "timestamps": [], "request_counts": []}
    
    # Filter by time
    cutoff = get_cutoff_time(time_range)
    filtered_logs = [
        log for log in logs_data["parsed_logs"] 
        if log.timestamp >= cutoff
    ]
    
    if not filtered_logs:
        return {"timestamps": [], "request_counts": []}
    
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
    format: str = "csv"
):
    """Export filtered logs to CSV or JSON"""
    logs = logs_data["parsed_logs"]
    
    if not logs:
        raise HTTPException(status_code=400, detail="No logs to export")
    
    # Convert to list of dicts
    log_dicts = [log.dict() for log in logs]
    
    if format.lower() == "csv":
        # Create CSV
        df = pd.DataFrame(log_dicts)
        
        # Fix datetime serialization
        for col in df.columns:
            if df[col].dtype == 'object':
                try:
                    # Check if column contains datetime objects
                    if any(isinstance(x, datetime) for x in df[col] if x is not None):
                        df[col] = df[col].apply(lambda x: x.isoformat() if x and isinstance(x, datetime) else x)
                except:
                    pass
        
        csv_path = "/tmp/exported_logs.csv"
        df.to_csv(csv_path, index=False)
        return FileResponse(
            csv_path, 
            filename="nginx_logs_export.csv",
            media_type="text/csv"
        )
    
    elif format.lower() == "json":
        # Create JSON with proper datetime serialization
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        json_path = "/tmp/exported_logs.json"
        with open(json_path, 'w') as f:
            json.dump(log_dicts, f, indent=2, default=json_serializer)
        return FileResponse(
            json_path, 
            filename="nginx_logs_export.json",
            media_type="application/json"
        )
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'csv' or 'json'.")

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time log streaming"""
    await manager.connect(websocket)
    try:
        # Send initial data
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to ForenX-NGINX Sentinel",
            "timestamp": datetime.now().isoformat(),
            "log_count": len(logs_data["parsed_logs"])
        })
        
        while True:
            # Keep connection alive
            await asyncio.sleep(30)
            await websocket.send_json({
                "type": "heartbeat", 
                "time": datetime.now().isoformat(),
                "log_count": len(logs_data["parsed_logs"])
            })
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
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

def get_cutoff_time(time_range: str) -> datetime:
    """Convert time range string to cutoff datetime"""
    now = datetime.now()
    
    if time_range == "1h":
        return now - timedelta(hours=1)
    elif time_range == "6h":
        return now - timedelta(hours=6)
    elif time_range == "12h":
        return now - timedelta(hours=12)
    elif time_range == "24h":
        return now - timedelta(hours=24)
    elif time_range == "7d":
        return now - timedelta(days=7)
    elif time_range == "30d":
        return now - timedelta(days=30)
    else:
        return datetime.min

# Create uploads directory
os.makedirs("uploads", exist_ok=True)

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
