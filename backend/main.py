#!/usr/bin/env python3
"""
ForenX-NGINX Sentinel - Advanced NGINX Forensic Dashboard
Backend Server with FastAPI - FINAL WORKING VERSION
"""
import os
import json
import time
import hashlib
import asyncio
import uvicorn
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
import logging

# Import custom modules
from log_parser import NGINXParser
from detection_engine import DetectionEngine
from models import LogEntry, AggregatedMetrics, AttackAlert, ErrorLogEntry, AttackType

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
    allow_origins=["*"],  # Allow all for development
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
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

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
    
    # Clear existing data
    logs_data["parsed_logs"] = []
    logs_data["alerts"] = []
    
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
                results["alerts_found"] += len(alerts)
            
            # Store hash for tamper detection
            logs_data["file_hashes"][file.filename] = {
                "hash": file_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "size": len(content),
                "type": detected_type
            }
            
            results["files_processed"].append({
                "filename": file.filename,
                "type": detected_type,
                "records": len(parsed),
                "hash": file_hash,
                "alerts": len(alerts) if 'alerts' in locals() else 0
            })
            results["total_records"] += len(parsed)
            
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
    
    logger.info(f"Upload complete: {results}")
    return results

@app.get("/api/metrics")
async def get_metrics(time_range: str = "24h"):
    """Get aggregated metrics for dashboard - FIXED (NO TIME FILTERING)"""
    logger.info(f"Getting metrics for time_range: {time_range}")
    
    if not logs_data["parsed_logs"]:
        logger.info("No parsed logs found, returning zeros")
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "total_bytes": 0,
            "status_4xx": 0,
            "status_5xx": 0,
            "error_rate": 0.0
        }
    
    logger.info(f"Total logs in memory: {len(logs_data['parsed_logs'])}")
    
    # DON'T filter by time - show all logs regardless of timestamp
    filtered_logs = logs_data["parsed_logs"]
    
    logger.info(f"Using ALL logs (no time filter): {len(filtered_logs)}")
    
    if not filtered_logs:
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "total_bytes": 0,
            "status_4xx": 0,
            "status_5xx": 0,
            "error_rate": 0.0
        }
    
    # Calculate metrics
    total_requests = len(filtered_logs)
    
    # Get unique IPs
    unique_ips = set()
    for log in filtered_logs:
        if hasattr(log, 'client_ip') and log.client_ip:
            unique_ips.add(log.client_ip)
    unique_ips_count = len(unique_ips)
    
    # Calculate bytes safely
    total_bytes = 0
    for log in filtered_logs:
        if hasattr(log, 'bytes_sent') and log.bytes_sent:
            try:
                total_bytes += int(log.bytes_sent)
            except:
                pass
    
    # Calculate status codes safely
    status_4xx = 0
    status_5xx = 0
    for log in filtered_logs:
        if hasattr(log, 'status'):
            try:
                status = int(log.status)
                if 400 <= status < 500:
                    status_4xx += 1
                elif 500 <= status < 600:
                    status_5xx += 1
            except:
                pass
    
    error_rate = (status_4xx + status_5xx) / total_requests if total_requests > 0 else 0
    
    metrics = {
        "total_requests": total_requests,
        "unique_ips": unique_ips_count,
        "total_bytes": total_bytes,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
        "error_rate": error_rate
    }
    
    logger.info(f"Returning metrics: {metrics}")
    return metrics

@app.get("/api/logs")
async def get_logs(
    page: int = 1,
    limit: int = 100,
    ip_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    time_start: Optional[str] = None
):
    """Get filtered logs with pagination"""
    logs = logs_data["parsed_logs"]
    
    logger.info(f"Getting logs page {page}, limit {limit}, total logs: {len(logs)}")
    
    # Apply filters
    filtered_logs = []
    for log in logs:
        include = True
        
        if ip_filter and hasattr(log, 'client_ip'):
            if ip_filter not in log.client_ip:
                include = False
        
        if status_filter and hasattr(log, 'status'):
            if str(log.status) != status_filter:
                include = False
        
        if time_start and hasattr(log, 'timestamp'):
            try:
                start_time = datetime.fromisoformat(time_start.replace('Z', '+00:00'))
                if log.timestamp < start_time:
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
    
    # Convert to dict with proper serialization
    log_dicts = []
    for log in paginated_logs:
        try:
            log_dict = log.dict()
            log_dicts.append(log_dict)
        except Exception as e:
            logger.error(f"Error serializing log: {e}")
            continue
    
    response = {
        "logs": log_dicts,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if limit > 0 else 0
        }
    }
    
    logger.info(f"Returning {len(log_dicts)} logs")
    return response

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Get security alerts"""
    alerts = logs_data["alerts"]
    
    logger.info(f"Getting alerts, limit {limit}, total alerts: {len(alerts)}")
    
    # Sort by timestamp (newest first)
    alerts.sort(key=lambda x: x.timestamp if hasattr(x, 'timestamp') else datetime.min, reverse=True)
    alerts = alerts[:limit]
    
    # Convert to dict with proper serialization
    alert_dicts = []
    for alert in alerts:
        try:
            alert_dict = alert.dict()
            alert_dicts.append(alert_dict)
        except Exception as e:
            logger.error(f"Error serializing alert: {e}")
            continue
    
    logger.info(f"Returning {len(alert_dicts)} alerts")
    return {"alerts": alert_dicts}

@app.get("/api/top-data")
async def get_top_data(
    category: str = "ips",
    limit: int = 10
):
    """Get top data for charts"""
    logger.info(f"Getting top data for category: {category}")
    
    if not logs_data["parsed_logs"]:
        logger.info("No parsed logs found, returning empty")
        return {"labels": [], "values": []}
    
    logs = logs_data["parsed_logs"]
    
    if category == "ips":
        # Top IPs by request count
        ip_counts = {}
        for log in logs:
            if hasattr(log, 'client_ip'):
                ip = log.client_ip
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        top_data = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        result = {
            "labels": [item[0] for item in top_data],
            "values": [item[1] for item in top_data]
        }
        
    elif category == "endpoints":
        # Top endpoints by request count
        endpoint_counts = {}
        for log in logs:
            if hasattr(log, 'endpoint'):
                endpoint = log.endpoint
                endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
        
        top_data = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        result = {
            "labels": [item[0] for item in top_data],
            "values": [item[1] for item in top_data]
        }
        
    elif category == "user_agents":
        # Top user-agents
        ua_counts = {}
        for log in logs:
            if hasattr(log, 'user_agent') and log.user_agent and log.user_agent != '-':
                ua = log.user_agent[:50]
                ua_counts[ua] = ua_counts.get(ua, 0) + 1
        
        top_data = sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        result = {
            "labels": [item[0] for item in top_data],
            "values": [item[1] for item in top_data]
        }
        
    elif category == "status_codes":
        # Status code distribution
        status_counts = {}
        for log in logs:
            if hasattr(log, 'status'):
                status = str(log.status)
                status_counts[status] = status_counts.get(status, 0) + 1
        
        # Sort by status code
        sorted_codes = sorted(status_counts.items(), key=lambda x: x[0])
        result = {
            "labels": [item[0] for item in sorted_codes],
            "values": [item[1] for item in sorted_codes]
        }
        
    else:
        result = {"labels": [], "values": []}
    
    logger.info(f"Returning top data: {len(result['labels'])} items")
    return result

@app.get("/api/timeline")
async def get_timeline(
    interval: str = "hour",
    time_range: str = "24h"
):
    """Get timeline data for charts - WITH TIME FILTERING"""
    logger.info(f"Getting timeline data, interval: {interval}, time_range: {time_range}")
    
    if not logs_data["parsed_logs"]:
        logger.info("No parsed logs found, returning empty")
        return {"timestamps": [], "request_counts": []}
    
    # Calculate time window based on time_range
    now = datetime.now(timezone.utc)
    start_time = None
    
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
    elif time_range == "6h":
        start_time = now - timedelta(hours=6)
    elif time_range == "24h":
        start_time = now - timedelta(hours=24)
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
    elif time_range == "30d":
        start_time = now - timedelta(days=30)
    else:
        # Default to all logs
        start_time = None
    
    # Filter logs by time if start_time is specified
    if start_time:
        filtered_logs = []
        for log in logs_data["parsed_logs"]:
            if hasattr(log, 'timestamp'):
                # Check if log timestamp is within range
                if log.timestamp >= start_time:
                    filtered_logs.append(log)
    else:
        filtered_logs = logs_data["parsed_logs"]
    
    logger.info(f"Filtered logs for timeline: {len(filtered_logs)} out of {len(logs_data['parsed_logs'])}")
    
    if not filtered_logs:
        return {"timestamps": [], "request_counts": []}
    
    # Group by time interval
    timeline = {}
    
    for log in filtered_logs:
        if hasattr(log, 'timestamp'):
            if interval == "minute":
                key = log.timestamp.strftime("%Y-%m-%d %H:%M")
            elif interval == "hour":
                key = log.timestamp.strftime("%Y-%m-%d %H:00")
            elif interval == "day":
                key = log.timestamp.strftime("%Y-%m-%d")
            elif interval == "week":
                # Get week number
                week_num = log.timestamp.isocalendar()[1]
                key = f"{log.timestamp.year}-W{week_num:02d}"
            elif interval == "month":
                key = log.timestamp.strftime("%Y-%m")
            else:
                key = log.timestamp.strftime("%Y-%m-%d %H:%M")
            
            timeline[key] = timeline.get(key, 0) + 1
    
    # Sort by time
    sorted_timeline = sorted(timeline.items(), key=lambda x: x[0])
    
    result = {
        "timestamps": [item[0] for item in sorted_timeline],
        "request_counts": [item[1] for item in sorted_timeline]
    }
    
    logger.info(f"Returning timeline data: {len(result['timestamps'])} time points")
    return result


@app.get("/api/historical/metrics")
async def get_historical_metrics():
    """Get metrics aggregated by time periods"""
    if not logs_data["parsed_logs"]:
        return {"daily": [], "weekly": [], "monthly": []}
    
    logs = logs_data["parsed_logs"]
    
    # Aggregate by day
    daily_data = {}
    for log in logs:
        if hasattr(log, 'timestamp'):
            day_key = log.timestamp.strftime("%Y-%m-%d")
            if day_key not in daily_data:
                daily_data[day_key] = {
                    "date": day_key,
                    "requests": 0,
                    "errors": 0,
                    "unique_ips": set(),
                    "bytes": 0
                }
            
            daily = daily_data[day_key]
            daily["requests"] += 1
            
            if hasattr(log, 'bytes_sent') and log.bytes_sent:
                try:
                    daily["bytes"] += int(log.bytes_sent)
                except:
                    pass
            
            if hasattr(log, 'client_ip') and log.client_ip:
                daily["unique_ips"].add(log.client_ip)
            
            if hasattr(log, 'status'):
                try:
                    status = int(log.status)
                    if 400 <= status < 600:
                        daily["errors"] += 1
                except:
                    pass
    
    # Convert sets to counts
    daily_result = []
    for day_key, data in sorted(daily_data.items()):
        daily_result.append({
            "date": data["date"],
            "requests": data["requests"],
            "errors": data["errors"],
            "unique_ips": len(data["unique_ips"]),
            "bytes": data["bytes"],
            "error_rate": data["errors"] / data["requests"] if data["requests"] > 0 else 0
        })
    
    return {
        "daily": daily_result[-30:],  # Last 30 days
        "weekly": aggregate_by_week(daily_result),
        "monthly": aggregate_by_month(daily_result)
    }

def aggregate_by_week(daily_data):
    """Aggregate daily data by week"""
    weekly_data = {}
    for day in daily_data:
        date_obj = datetime.strptime(day["date"], "%Y-%m-%d")
        year, week, _ = date_obj.isocalendar()
        week_key = f"{year}-W{week:02d}"
        
        if week_key not in weekly_data:
            weekly_data[week_key] = {
                "week": week_key,
                "requests": 0,
                "errors": 0,
                "unique_ips": 0,
                "bytes": 0
            }
        
        weekly = weekly_data[week_key]
        weekly["requests"] += day["requests"]
        weekly["errors"] += day["errors"]
        weekly["unique_ips"] += day["unique_ips"]
        weekly["bytes"] += day["bytes"]
    
    result = []
    for week_key, data in sorted(weekly_data.items()):
        result.append({
            "week": data["week"],
            "requests": data["requests"],
            "errors": data["errors"],
            "unique_ips": data["unique_ips"],
            "bytes": data["bytes"],
            "error_rate": data["errors"] / data["requests"] if data["requests"] > 0 else 0
        })
    
    return result

def aggregate_by_month(daily_data):
    """Aggregate daily data by month"""
    monthly_data = {}
    for day in daily_data:
        date_obj = datetime.strptime(day["date"], "%Y-%m-%d")
        month_key = date_obj.strftime("%Y-%m")
        
        if month_key not in monthly_data:
            monthly_data[month_key] = {
                "month": month_key,
                "requests": 0,
                "errors": 0,
                "unique_ips": 0,
                "bytes": 0
            }
        
        monthly = monthly_data[month_key]
        monthly["requests"] += day["requests"]
        monthly["errors"] += day["errors"]
        monthly["unique_ips"] += day["unique_ips"]
        monthly["bytes"] += day["bytes"]
    
    result = []
    for month_key, data in sorted(monthly_data.items()):
        result.append({
            "month": data["month"],
            "requests": data["requests"],
            "errors": data["errors"],
            "unique_ips": data["unique_ips"],
            "bytes": data["bytes"],
            "error_rate": data["errors"] / data["requests"] if data["requests"] > 0 else 0
        })
    
    return result

@app.get("/api/compare/periods")
async def compare_periods():
    """Compare current period with previous period"""
    if not logs_data["parsed_logs"]:
        return {
            "current": {},
            "previous": {},
            "changes": {}
        }
    
    now = datetime.now(timezone.utc)
    
    # Current period (last 24 hours)
    current_start = now - timedelta(hours=24)
    # Previous period (24-48 hours ago)
    previous_start = now - timedelta(hours=48)
    previous_end = now - timedelta(hours=24)
    
    current_logs = []
    previous_logs = []
    
    for log in logs_data["parsed_logs"]:
        if hasattr(log, 'timestamp'):
            if log.timestamp >= current_start:
                current_logs.append(log)
            elif previous_end <= log.timestamp < previous_start:
                previous_logs.append(log)
    
    def calculate_period_metrics(logs):
        if not logs:
            return {
                "requests": 0,
                "unique_ips": 0,
                "bytes": 0,
                "errors": 0,
                "error_rate": 0
            }
        
        total_requests = len(logs)
        unique_ips = len(set([log.client_ip for log in logs if hasattr(log, 'client_ip')]))
        
        total_bytes = 0
        for log in logs:
            if hasattr(log, 'bytes_sent') and log.bytes_sent:
                try:
                    total_bytes += int(log.bytes_sent)
                except:
                    pass
        
        errors = 0
        for log in logs:
            if hasattr(log, 'status'):
                try:
                    status = int(log.status)
                    if 400 <= status < 600:
                        errors += 1
                except:
                    pass
        
        error_rate = errors / total_requests if total_requests > 0 else 0
        
        return {
            "requests": total_requests,
            "unique_ips": unique_ips,
            "bytes": total_bytes,
            "errors": errors,
            "error_rate": error_rate
        }
    
    current_metrics = calculate_period_metrics(current_logs)
    previous_metrics = calculate_period_metrics(previous_logs)
    
    # Calculate changes
    changes = {}
    for key in current_metrics:
        if key in previous_metrics and previous_metrics[key] > 0:
            if key == "error_rate":
                changes[key] = current_metrics[key] - previous_metrics[key]
            else:
                changes[key] = ((current_metrics[key] - previous_metrics[key]) / previous_metrics[key]) * 100
        else:
            changes[key] = 0
    
    return {
        "current": current_metrics,
        "previous": previous_metrics,
        "changes": changes
    }

@app.get("/api/export")
async def export_logs(format: str = "csv"):
    """Export filtered logs to CSV or JSON"""
    logs = logs_data["parsed_logs"]
    
    if not logs:
        raise HTTPException(status_code=400, detail="No logs to export")
    
    # Convert to list of dicts
    log_dicts = []
    for log in logs:
        try:
            d = log.dict()
            log_dicts.append(d)
        except:
            continue
    
    if format.lower() == "csv":
        # Create CSV
        df = pd.DataFrame(log_dicts)
        csv_path = "/tmp/exported_logs.csv"
        df.to_csv(csv_path, index=False)
        return FileResponse(
            csv_path, 
            filename="nginx_logs_export.csv",
            media_type="text/csv"
        )
    
    elif format.lower() == "json":
        # Create JSON
        json_path = "/tmp/exported_logs.json"
        with open(json_path, 'w') as f:
            json.dump(log_dicts, f, indent=2)
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "log_count": len(logs_data["parsed_logs"])
        })
        
        while True:
            # Keep connection alive
            await asyncio.sleep(30)
            await websocket.send_json({
                "type": "heartbeat", 
                "time": datetime.now(timezone.utc).isoformat(),
                "log_count": len(logs_data["parsed_logs"])
            })
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.get("/api/debug")
async def debug_endpoint():
    """Debug endpoint to check data"""
    sample_log = None
    if logs_data["parsed_logs"]:
        sample_log = logs_data["parsed_logs"][0]
        sample_log_dict = sample_log.dict() if hasattr(sample_log, 'dict') else str(sample_log)
    else:
        sample_log_dict = None
    
    sample_alert = None
    if logs_data["alerts"]:
        sample_alert = logs_data["alerts"][0]
        sample_alert_dict = sample_alert.dict() if hasattr(sample_alert, 'dict') else str(sample_alert)
    else:
        sample_alert_dict = None
    
    return {
        "parsed_logs_count": len(logs_data["parsed_logs"]),
        "alerts_count": len(logs_data["alerts"]),
        "sample_log": sample_log_dict,
        "sample_alert": sample_alert_dict,
        "metrics": logs_data.get("metrics", {}),
        "file_hashes": logs_data.get("file_hashes", {})
    }

def update_metrics():
    """Update global metrics"""
    if logs_data["parsed_logs"]:
        # Simple metrics calculation
        logs = logs_data["parsed_logs"]
        total_requests = len(logs)
        
        # Get unique IPs
        unique_ips = set()
        for log in logs:
            if hasattr(log, 'client_ip') and log.client_ip:
                unique_ips.add(log.client_ip)
        unique_ips_count = len(unique_ips)
        
        total_bytes = 0
        for log in logs:
            if hasattr(log, 'bytes_sent') and log.bytes_sent:
                try:
                    total_bytes += int(log.bytes_sent)
                except:
                    pass
        
        status_4xx = 0
        status_5xx = 0
        for log in logs:
            if hasattr(log, 'status'):
                try:
                    status = int(log.status)
                    if 400 <= status < 500:
                        status_4xx += 1
                    elif 500 <= status < 600:
                        status_5xx += 1
                except:
                    pass
        
        error_rate = (status_4xx + status_5xx) / total_requests if total_requests > 0 else 0
        
        logs_data["metrics"] = {
            "total_requests": total_requests,
            "unique_ips": unique_ips_count,
            "total_bytes": total_bytes,
            "status_4xx": status_4xx,
            "status_5xx": status_5xx,
            "error_rate": error_rate
        }
        
        logger.info(f"Updated metrics: {logs_data['metrics']}")

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
