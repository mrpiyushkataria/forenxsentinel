#!/usr/bin/env python3
"""
ForenX-NGINX Sentinel - Advanced NGINX Forensic Dashboard
Enhanced Backend with GeoIP, Advanced Analytics, and Multi-Log Support
"""
import os
import json
import time
import hashlib
import asyncio
import uvicorn
import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any, Tuple
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import logging
import geoip2.database
from collections import defaultdict, Counter
import re
import csv
import io

# Import custom modules
from log_parser import NGINXParser
from detection_engine import DetectionEngine
from models import LogEntry, AggregatedMetrics, AttackAlert, ErrorLogEntry, AttackType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ForenX-NGINX Sentinel Pro",
    description="Advanced NGINX Log Forensic Dashboard with GeoIP and Analytics",
    version="2.0.0"
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

# Initialize GeoIP database (provide your own or use free version)
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    logger.info("GeoIP database loaded successfully")
except:
    logger.warning("GeoIP database not found, geographic features will be limited")

# In-memory storage with enhanced structure
logs_data = {
    "access_logs": [],
    "error_logs": [],
    "parsed_logs": [],
    "alerts": [],
    "metrics": {},
    "file_hashes": {},
    "geo_data": {},  # Store geographic data
    "hourly_patterns": {},
    "daily_patterns": {},
    "endpoint_stats": {},
    "status_analysis": {}
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

def get_ip_location(ip_address: str) -> Dict[str, Any]:
    """Get geographic location for IP address"""
    if not geoip_reader or ip_address in ['127.0.0.1', 'localhost']:
        return None
    
    try:
        response = geoip_reader.city(ip_address)
        return {
            "country": response.country.name,
            "country_code": response.country.iso_code,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "timezone": response.location.time_zone
        }
    except:
        return None

def analyze_traffic_patterns(logs: List[LogEntry]) -> Dict[str, Any]:
    """Analyze traffic patterns for enhanced insights"""
    patterns = {
        "hourly_distribution": defaultdict(int),
        "daily_distribution": defaultdict(int),
        "weekly_distribution": defaultdict(int),
        "peak_hours": [],
        "trough_hours": [],
        "avg_requests_per_hour": 0,
        "busiest_day": None,
        "quietest_day": None
    }
    
    hourly_counts = defaultdict(int)
    daily_counts = defaultdict(int)
    weekday_counts = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'timestamp'):
            hour = log.timestamp.hour
            day = log.timestamp.strftime("%Y-%m-%d")
            weekday = log.timestamp.strftime("%A")
            
            hourly_counts[hour] += 1
            daily_counts[day] += 1
            weekday_counts[weekday] += 1
    
    # Calculate statistics
    if hourly_counts:
        patterns["hourly_distribution"] = dict(sorted(hourly_counts.items()))
        total_requests = sum(hourly_counts.values())
        patterns["avg_requests_per_hour"] = total_requests / len(hourly_counts)
        
        # Find peak and trough hours
        max_hour = max(hourly_counts, key=hourly_counts.get)
        min_hour = min(hourly_counts, key=hourly_counts.get)
        
        patterns["peak_hours"] = [
            {"hour": hour, "count": count}
            for hour, count in hourly_counts.items()
            if count >= hourly_counts[max_hour] * 0.8  # Top 20%
        ]
        
        patterns["trough_hours"] = [
            {"hour": hour, "count": count}
            for hour, count in hourly_counts.items()
            if count <= hourly_counts[min_hour] * 1.2  # Bottom 20%
        ]
    
    if daily_counts:
        patterns["daily_distribution"] = dict(sorted(daily_counts.items()))
    
    if weekday_counts:
        patterns["weekly_distribution"] = dict(weekday_counts)
        patterns["busiest_day"] = max(weekday_counts, key=weekday_counts.get)
        patterns["quietest_day"] = min(weekday_counts, key=weekday_counts.get)
    
    return patterns

def analyze_endpoint_performance(logs: List[LogEntry]) -> Dict[str, Any]:
    """Analyze endpoint performance metrics"""
    endpoint_stats = defaultdict(lambda: {
        "count": 0,
        "total_bytes": 0,
        "avg_bytes": 0,
        "response_times": [],
        "status_codes": defaultdict(int),
        "methods": defaultdict(int),
        "unique_ips": set(),
        "errors": 0
    })
    
    for log in logs:
        if hasattr(log, 'endpoint'):
            endpoint = log.endpoint
            stats = endpoint_stats[endpoint]
            
            stats["count"] += 1
            
            if hasattr(log, 'bytes_sent') and log.bytes_sent:
                try:
                    stats["total_bytes"] += int(log.bytes_sent)
                except:
                    pass
            
            if hasattr(log, 'request_time'):
                try:
                    stats["response_times"].append(float(log.request_time))
                except:
                    pass
            
            if hasattr(log, 'status'):
                status = str(log.status)
                stats["status_codes"][status] += 1
                if 400 <= int(status) < 600:
                    stats["errors"] += 1
            
            if hasattr(log, 'method'):
                stats["methods"][log.method] += 1
            
            if hasattr(log, 'client_ip'):
                stats["unique_ips"].add(log.client_ip)
    
    # Calculate averages and format response
    result = {}
    for endpoint, stats in endpoint_stats.items():
        if stats["count"] > 0:
            stats["avg_bytes"] = stats["total_bytes"] / stats["count"]
            
            # Calculate response time percentiles
            if stats["response_times"]:
                times = sorted(stats["response_times"])
                stats["p50_response_time"] = np.percentile(times, 50) if times else 0
                stats["p95_response_time"] = np.percentile(times, 95) if times else 0
                stats["p99_response_time"] = np.percentile(times, 99) if times else 0
                stats["avg_response_time"] = np.mean(times) if times else 0
            else:
                stats["p50_response_time"] = 0
                stats["p95_response_time"] = 0
                stats["p99_response_time"] = 0
                stats["avg_response_time"] = 0
            
            # Convert sets to counts
            stats["unique_ip_count"] = len(stats["unique_ips"])
            stats.pop("unique_ips", None)
            stats.pop("response_times", None)
            
            # Convert defaultdict to dict
            stats["status_codes"] = dict(stats["status_codes"])
            stats["methods"] = dict(stats["methods"])
            
            result[endpoint] = dict(stats)
    
    return result

def generate_geo_distribution(logs: List[LogEntry]) -> Dict[str, Any]:
    """Generate geographic distribution data for map visualization"""
    geo_data = {
        "countries": defaultdict(int),
        "cities": defaultdict(int),
        "coordinates": [],
        "total_requests_by_country": {},
        "unique_ips_by_country": defaultdict(set)
    }
    
    for log in logs:
        if hasattr(log, 'client_ip'):
            ip = log.client_ip
            location = get_ip_location(ip)
            
            if location:
                country = location.get("country", "Unknown")
                city = location.get("city", "Unknown")
                lat = location.get("latitude")
                lon = location.get("longitude")
                
                geo_data["countries"][country] += 1
                geo_data["cities"][city] += 1
                geo_data["unique_ips_by_country"][country].add(ip)
                
                if lat and lon:
                    geo_data["coordinates"].append({
                        "ip": ip,
                        "latitude": lat,
                        "longitude": lon,
                        "country": country,
                        "city": city,
                        "count": 1
                    })
    
    # Aggregate coordinates by location
    aggregated_coords = {}
    for coord in geo_data["coordinates"]:
        key = f"{coord['latitude']},{coord['longitude']}"
        if key in aggregated_coords:
            aggregated_coords[key]["count"] += 1
        else:
            aggregated_coords[key] = coord
    
    geo_data["coordinates"] = list(aggregated_coords.values())
    
    # Calculate total requests by country
    for country, ips in geo_data["unique_ips_by_country"].items():
        geo_data["total_requests_by_country"][country] = {
            "requests": geo_data["countries"][country],
            "unique_ips": len(ips)
        }
    
    # Remove sets from final output
    geo_data.pop("unique_ips_by_country", None)
    
    return geo_data

@app.get("/")
async def root():
    return {"message": "ForenX-NGINX Sentinel Pro API", "status": "running", "version": "2.0.0"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.post("/api/upload-logs")
async def upload_logs(
    files: List[UploadFile] = File(...),
    log_type: str = Form("auto")
):
    """Upload and parse NGINX log files with enhanced processing"""
    results = {
        "files_processed": [],
        "total_records": 0,
        "alerts_found": 0,
        "file_hashes": []
    }
    
    # Clear existing data
    logs_data["parsed_logs"] = []
    logs_data["alerts"] = []
    logs_data["geo_data"] = {}
    logs_data["hourly_patterns"] = {}
    logs_data["daily_patterns"] = {}
    logs_data["endpoint_stats"] = {}
    logs_data["status_analysis"] = {}
    
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
    
    # Update all analytics if we have logs
    if logs_data["parsed_logs"]:
        update_all_analytics()
    
    logger.info(f"Upload complete: {results}")
    return results

def update_all_analytics():
    """Update all analytics data after log upload"""
    logs = logs_data["parsed_logs"]
    
    if not logs:
        return
    
    # Update basic metrics
    update_metrics()
    
    # Update traffic patterns
    logs_data["hourly_patterns"] = analyze_traffic_patterns(logs)
    
    # Update endpoint performance
    logs_data["endpoint_stats"] = analyze_endpoint_performance(logs)
    
    # Update geographic distribution
    logs_data["geo_data"] = generate_geo_distribution(logs)
    
    # Update status analysis
    logs_data["status_analysis"] = analyze_status_patterns(logs)
    
    logger.info("All analytics updated successfully")

def analyze_status_patterns(logs: List[LogEntry]) -> Dict[str, Any]:
    """Analyze status code patterns"""
    status_data = {
        "distribution": defaultdict(int),
        "by_hour": defaultdict(lambda: defaultdict(int)),
        "by_endpoint": defaultdict(lambda: defaultdict(int)),
        "trends": defaultdict(lambda: defaultdict(int)),
        "error_sequences": []
    }
    
    for log in logs:
        if hasattr(log, 'status'):
            status = str(log.status)
            status_data["distribution"][status] += 1
            
            # Group by hour
            if hasattr(log, 'timestamp'):
                hour = log.timestamp.strftime("%H:00")
                status_data["by_hour"][hour][status] += 1
                
                # Daily trends
                day = log.timestamp.strftime("%Y-%m-%d")
                status_data["trends"][day][status] += 1
            
            # Group by endpoint
            if hasattr(log, 'endpoint'):
                status_data["by_endpoint"][log.endpoint][status] += 1
    
    # Calculate percentages
    total = len(logs)
    status_data["percentages"] = {
        status: (count / total * 100) 
        for status, count in status_data["distribution"].items()
    }
    
    # Find error sequences
    error_sequences = []
    error_window = []
    
    for log in logs:
        if hasattr(log, 'status') and 400 <= int(log.status) < 600:
            error_window.append(log)
            if len(error_window) >= 5:  # Sequence of 5+ errors
                if len(error_sequences) == 0 or error_sequences[-1]["end"] != log.timestamp:
                    error_sequences.append({
                        "start": error_window[0].timestamp,
                        "end": log.timestamp,
                        "count": len(error_window),
                        "status_codes": [str(l.status) for l in error_window],
                        "endpoints": [l.endpoint for l in error_window if hasattr(l, 'endpoint')]
                    })
                else:
                    error_sequences[-1]["count"] += 1
                error_window = []
        else:
            error_window = []
    
    status_data["error_sequences"] = error_sequences
    
    return dict(status_data)

@app.get("/api/metrics")
async def get_metrics(time_range: str = "24h", detailed: bool = False):
    """Get enhanced metrics with optional details"""
    if not logs_data["parsed_logs"]:
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "total_bytes": 0,
            "status_4xx": 0,
            "status_5xx": 0,
            "error_rate": 0.0,
            "avg_response_time": 0.0,
            "requests_per_second": 0.0,
            "bandwidth_usage": 0.0
        }
    
    logs = logs_data["parsed_logs"]
    
    # Filter by time range if needed
    if time_range != "all":
        now = datetime.now(timezone.utc)
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
            start_time = now - timedelta(hours=24)  # Default
        
        logs = [log for log in logs if hasattr(log, 'timestamp') and log.timestamp >= start_time]
    
    if not logs:
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "total_bytes": 0,
            "status_4xx": 0,
            "status_5xx": 0,
            "error_rate": 0.0,
            "avg_response_time": 0.0,
            "requests_per_second": 0.0,
            "bandwidth_usage": 0.0
        }
    
    # Calculate basic metrics
    total_requests = len(logs)
    
    unique_ips = set()
    for log in logs:
        if hasattr(log, 'client_ip') and log.client_ip:
            unique_ips.add(log.client_ip)
    unique_ips_count = len(unique_ips)
    
    total_bytes = 0
    response_times = []
    
    for log in logs:
        if hasattr(log, 'bytes_sent') and log.bytes_sent:
            try:
                total_bytes += int(log.bytes_sent)
            except:
                pass
        
        if hasattr(log, 'request_time'):
            try:
                response_times.append(float(log.request_time))
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
    
    # Calculate advanced metrics
    avg_response_time = np.mean(response_times) if response_times else 0
    
    # Calculate time span for RPS
    if len(logs) > 1:
        timestamps = [log.timestamp for log in logs if hasattr(log, 'timestamp')]
        if timestamps:
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            requests_per_second = total_requests / time_span if time_span > 0 else 0
        else:
            requests_per_second = 0
    else:
        requests_per_second = 0
    
    # Calculate bandwidth usage (MB per second)
    bandwidth_usage = (total_bytes / 1024 / 1024) / (time_span if time_span > 0 else 1)
    
    metrics = {
        "total_requests": total_requests,
        "unique_ips": unique_ips_count,
        "total_bytes": total_bytes,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
        "error_rate": error_rate,
        "avg_response_time": avg_response_time,
        "requests_per_second": round(requests_per_second, 2),
        "bandwidth_usage": round(bandwidth_usage, 2),
        "formatted_bytes": format_bytes(total_bytes),
        "formatted_bandwidth": f"{bandwidth_usage:.2f} MB/s"
    }
    
    # Add detailed metrics if requested
    if detailed:
        # Method distribution
        method_dist = defaultdict(int)
        for log in logs:
            if hasattr(log, 'method'):
                method_dist[log.method] += 1
        
        # Top endpoints
        endpoint_dist = defaultdict(int)
        for log in logs:
            if hasattr(log, 'endpoint'):
                endpoint_dist[log.endpoint] += 1
        
        metrics.update({
            "method_distribution": dict(method_dist),
            "top_endpoints": dict(sorted(endpoint_dist.items(), key=lambda x: x[1], reverse=True)[:10]),
            "response_time_percentiles": {
                "p50": np.percentile(response_times, 50) if response_times else 0,
                "p95": np.percentile(response_times, 95) if response_times else 0,
                "p99": np.percentile(response_times, 99) if response_times else 0
            }
        })
    
    return metrics

def format_bytes(bytes_num: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} PB"

@app.get("/api/geo-distribution")
async def get_geo_distribution():
    """Get geographic distribution data for map visualization"""
    if not logs_data["geo_data"]:
        return {"error": "No geographic data available. Upload logs first."}
    
    return logs_data["geo_data"]

@app.get("/api/traffic-patterns")
async def get_traffic_patterns():
    """Get traffic pattern analysis"""
    if not logs_data["hourly_patterns"]:
        return {"error": "No traffic pattern data available. Upload logs first."}
    
    return logs_data["hourly_patterns"]

@app.get("/api/endpoint-performance")
async def get_endpoint_performance(limit: int = 20):
    """Get endpoint performance metrics"""
    if not logs_data["endpoint_stats"]:
        return {"endpoints": {}, "total_endpoints": 0}
    
    endpoints = logs_data["endpoint_stats"]
    sorted_endpoints = sorted(
        endpoints.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )[:limit]
    
    return {
        "endpoints": dict(sorted_endpoints),
        "total_endpoints": len(endpoints)
    }

@app.get("/api/status-analysis")
async def get_status_analysis():
    """Get detailed status code analysis"""
    if not logs_data["status_analysis"]:
        return {"error": "No status analysis data available. Upload logs first."}
    
    return logs_data["status_analysis"]

@app.get("/api/timeline")
async def get_timeline(
    interval: str = "hour",
    time_range: str = "24h",
    metric: str = "requests"
):
    """Get timeline data for charts with multiple metrics"""
    if not logs_data["parsed_logs"]:
        return {"timestamps": [], "values": [], "metric": metric}
    
    logs = logs_data["parsed_logs"]
    
    # Filter by time range
    if time_range != "all":
        now = datetime.now(timezone.utc)
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
            start_time = now - timedelta(hours=24)
        
        logs = [log for log in logs if hasattr(log, 'timestamp') and log.timestamp >= start_time]
    
    if not logs:
        return {"timestamps": [], "values": [], "metric": metric}
    
    # Group by time interval
    timeline = defaultdict(lambda: {
        "requests": 0,
        "errors": 0,
        "bytes": 0,
        "response_time": 0,
        "count": 0
    })
    
    for log in logs:
        if hasattr(log, 'timestamp'):
            if interval == "minute":
                key = log.timestamp.strftime("%Y-%m-%d %H:%M")
            elif interval == "hour":
                key = log.timestamp.strftime("%Y-%m-%d %H:00")
            elif interval == "day":
                key = log.timestamp.strftime("%Y-%m-%d")
            elif interval == "week":
                week_num = log.timestamp.isocalendar()[1]
                key = f"{log.timestamp.year}-W{week_num:02d}"
            elif interval == "month":
                key = log.timestamp.strftime("%Y-%m")
            else:
                key = log.timestamp.strftime("%Y-%m-%d %H:%M")
            
            data = timeline[key]
            data["requests"] += 1
            
            if hasattr(log, 'status'):
                try:
                    status = int(log.status)
                    if 400 <= status < 600:
                        data["errors"] += 1
                except:
                    pass
            
            if hasattr(log, 'bytes_sent') and log.bytes_sent:
                try:
                    data["bytes"] += int(log.bytes_sent)
                except:
                    pass
            
            if hasattr(log, 'request_time'):
                try:
                    data["response_time"] += float(log.request_time)
                    data["count"] += 1
                except:
                    pass
    
    # Calculate averages and prepare response
    sorted_timeline = sorted(timeline.items(), key=lambda x: x[0])
    
    timestamps = []
    values = []
    
    for key, data in sorted_timeline:
        timestamps.append(key)
        
        if metric == "requests":
            values.append(data["requests"])
        elif metric == "errors":
            values.append(data["errors"])
        elif metric == "bytes":
            values.append(data["bytes"] / 1024)  # Convert to KB
        elif metric == "error_rate":
            rate = (data["errors"] / data["requests"]) * 100 if data["requests"] > 0 else 0
            values.append(rate)
        elif metric == "response_time":
            avg_time = data["response_time"] / data["count"] if data["count"] > 0 else 0
            values.append(avg_time * 1000)  # Convert to milliseconds
        else:
            values.append(data["requests"])
    
    return {
        "timestamps": timestamps,
        "values": values,
        "metric": metric,
        "unit": get_metric_unit(metric)
    }

def get_metric_unit(metric: str) -> str:
    """Get unit for metric"""
    units = {
        "requests": "Requests",
        "errors": "Errors",
        "bytes": "KB",
        "error_rate": "%",
        "response_time": "ms"
    }
    return units.get(metric, "Count")

@app.get("/api/advanced-analytics")
async def get_advanced_analytics():
    """Get comprehensive advanced analytics"""
    if not logs_data["parsed_logs"]:
        return {"error": "No data available. Upload logs first."}
    
    logs = logs_data["parsed_logs"]
    
    # Calculate various analytics
    analytics = {
        "performance": calculate_performance_metrics(logs),
        "security": calculate_security_metrics(),
        "traffic": calculate_traffic_metrics(logs),
        "users": calculate_user_metrics(logs),
        "content": calculate_content_metrics(logs)
    }
    
    return analytics

def calculate_performance_metrics(logs: List[LogEntry]) -> Dict[str, Any]:
    """Calculate performance metrics"""
    response_times = []
    bytes_transferred = []
    
    for log in logs:
        if hasattr(log, 'request_time'):
            try:
                response_times.append(float(log.request_time))
            except:
                pass
        
        if hasattr(log, 'bytes_sent') and log.bytes_sent:
            try:
                bytes_transferred.append(int(log.bytes_sent))
            except:
                pass
    
    return {
        "avg_response_time": np.mean(response_times) if response_times else 0,
        "p95_response_time": np.percentile(response_times, 95) if response_times else 0,
        "p99_response_time": np.percentile(response_times, 99) if response_times else 0,
        "throughput": len(logs) / 3600,  # requests per hour
        "bandwidth": sum(bytes_transferred) / 1024 / 1024,  # MB
        "avg_payload_size": np.mean(bytes_transferred) if bytes_transferred else 0
    }

def calculate_security_metrics() -> Dict[str, Any]:
    """Calculate security metrics"""
    alerts = logs_data["alerts"]
    
    alert_counts = defaultdict(int)
    for alert in alerts:
        alert_counts[alert.attack_type.value] += 1
    
    return {
        "total_alerts": len(alerts),
        "alert_distribution": dict(alert_counts),
        "high_risk_ips": count_high_risk_ips(),
        "attack_trend": analyze_attack_trends(alerts)
    }

def count_high_risk_ips() -> List[Dict[str, Any]]:
    """Count high-risk IPs based on alerts"""
    ip_alerts = defaultdict(list)
    
    for alert in logs_data["alerts"]:
        ip_alerts[alert.client_ip].append(alert)
    
    high_risk = []
    for ip, alerts in ip_alerts.items():
        if len(alerts) >= 5:  # IPs with 5+ alerts
            alert_types = Counter([alert.attack_type.value for alert in alerts])
            high_risk.append({
                "ip": ip,
                "alert_count": len(alerts),
                "alert_types": dict(alert_types),
                "confidence_avg": np.mean([alert.confidence for alert in alerts])
            })
    
    return sorted(high_risk, key=lambda x: x["alert_count"], reverse=True)[:10]

def analyze_attack_trends(alerts: List[AttackAlert]) -> Dict[str, Any]:
    """Analyze attack trends over time"""
    alerts_by_hour = defaultdict(int)
    alerts_by_day = defaultdict(int)
    
    for alert in alerts:
        hour = alert.timestamp.strftime("%H:00")
        day = alert.timestamp.strftime("%Y-%m-%d")
        
        alerts_by_hour[hour] += 1
        alerts_by_day[day] += 1
    
    return {
        "by_hour": dict(alerts_by_hour),
        "by_day": dict(alerts_by_day),
        "peak_hour": max(alerts_by_hour, key=alerts_by_hour.get) if alerts_by_hour else None,
        "peak_day": max(alerts_by_day, key=alerts_by_day.get) if alerts_by_day else None
    }

def calculate_traffic_metrics(logs: List[LogEntry]) -> Dict[str, Any]:
    """Calculate traffic metrics"""
    hourly_traffic = defaultdict(int)
    daily_traffic = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'timestamp'):
            hour = log.timestamp.strftime("%H:00")
            day = log.timestamp.strftime("%Y-%m-%d")
            
            hourly_traffic[hour] += 1
            daily_traffic[day] += 1
    
    return {
        "hourly_distribution": dict(hourly_traffic),
        "daily_distribution": dict(daily_traffic),
        "peak_hour": max(hourly_traffic, key=hourly_traffic.get) if hourly_traffic else None,
        "peak_day": max(daily_traffic, key=daily_traffic.get) if daily_traffic else None,
        "avg_daily_requests": np.mean(list(daily_traffic.values())) if daily_traffic else 0
    }

def calculate_user_metrics(logs: List[LogEntry]) -> Dict[str, Any]:
    """Calculate user metrics"""
    user_agents = defaultdict(int)
    ips = set()
    countries = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'user_agent') and log.user_agent:
            user_agents[log.user_agent] += 1
        
        if hasattr(log, 'client_ip'):
            ips.add(log.client_ip)
            
            # Get country from GeoIP
            location = get_ip_location(log.client_ip)
            if location and location.get("country"):
                countries[location["country"]] += 1
    
    # Get top user agents
    top_user_agents = dict(sorted(user_agents.items(), key=lambda x: x[1], reverse=True)[:10])
    
    return {
        "unique_visitors": len(ips),
        "top_user_agents": top_user_agents,
        "bot_traffic": sum(count for ua, count in user_agents.items() if 'bot' in ua.lower()),
        "country_distribution": dict(countries)
    }

def calculate_content_metrics(logs: List[LogEntry]) -> Dict[str, Any]:
    """Calculate content metrics"""
    content_types = defaultdict(int)
    endpoints = defaultdict(int)
    methods = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'endpoint'):
            endpoints[log.endpoint] += 1
            
            # Guess content type from endpoint
            if log.endpoint.endswith(('.css', '.js', '.png', '.jpg', '.gif', '.ico')):
                ext = log.endpoint.split('.')[-1]
                content_types[ext] += 1
            elif '/api/' in log.endpoint:
                content_types['api'] += 1
            elif any(ext in log.endpoint for ext in ['.html', '.php', '.jsp']):
                content_types['html'] += 1
            else:
                content_types['other'] += 1
        
        if hasattr(log, 'method'):
            methods[log.method] += 1
    
    return {
        "content_type_distribution": dict(content_types),
        "top_endpoints": dict(sorted(endpoints.items(), key=lambda x: x[1], reverse=True)[:10]),
        "method_distribution": dict(methods),
        "api_vs_web": {
            "api": content_types.get('api', 0),
            "web": content_types.get('html', 0) + content_types.get('other', 0),
            "static": sum(count for ext, count in content_types.items() if ext not in ['api', 'html', 'other'])
        }
    }

@app.get("/api/export-analytics")
async def export_analytics(format: str = "csv"):
    """Export comprehensive analytics data"""
    if not logs_data["parsed_logs"]:
        raise HTTPException(status_code=400, detail="No data to export")
    
    # Prepare all analytics data
    analytics = {
        "basic_metrics": await get_metrics("all", True),
        "traffic_patterns": await get_traffic_patterns(),
        "geo_distribution": await get_geo_distribution(),
        "endpoint_performance": await get_endpoint_performance(50),
        "status_analysis": await get_status_analysis(),
        "advanced_analytics": await get_advanced_analytics()
    }
    
    if format.lower() == "json":
        return JSONResponse(content=analytics)
    
    elif format.lower() == "csv":
        # Create CSV file with multiple sheets
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write basic metrics
        writer.writerow(["Basic Metrics"])
        writer.writerow(["Metric", "Value"])
        for key, value in analytics["basic_metrics"].items():
            if isinstance(value, (int, float, str)):
                writer.writerow([key, value])
        
        writer.writerow([])
        writer.writerow(["Traffic Patterns"])
        # Add more CSV data...
        
        output.seek(0)
        return JSONResponse(content={"csv_data": output.getvalue()})
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")

@app.get("/api/log-statistics")
async def get_log_statistics():
    """Get detailed statistics about parsed logs"""
    if not logs_data["parsed_logs"]:
        return {"error": "No logs available"}
    
    logs = logs_data["parsed_logs"]
    
    stats = {
        "total_logs": len(logs),
        "time_range": {},
        "status_summary": {},
        "method_summary": {},
        "endpoint_summary": {},
        "user_agent_summary": {},
        "bytes_summary": {}
    }
    
    # Time range
    if logs:
        timestamps = [log.timestamp for log in logs if hasattr(log, 'timestamp')]
        if timestamps:
            stats["time_range"] = {
                "start": min(timestamps).isoformat(),
                "end": max(timestamps).isoformat(),
                "duration_days": (max(timestamps) - min(timestamps)).days
            }
    
    # Status summary
    status_counts = defaultdict(int)
    for log in logs:
        if hasattr(log, 'status'):
            status_counts[str(log.status)] += 1
    stats["status_summary"] = {
        "total": len(status_counts),
        "distribution": dict(status_counts),
        "error_rate": sum(count for status, count in status_counts.items() 
                         if status.startswith('4') or status.startswith('5')) / len(logs) * 100
    }
    
    # Method summary
    method_counts = defaultdict(int)
    for log in logs:
        if hasattr(log, 'method'):
            method_counts[log.method] += 1
    stats["method_summary"] = dict(method_counts)
    
    # Endpoint summary
    endpoint_counts = defaultdict(int)
    for log in logs:
        if hasattr(log, 'endpoint'):
            endpoint_counts[log.endpoint] += 1
    
    stats["endpoint_summary"] = {
        "total": len(endpoint_counts),
        "top_10": dict(sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    }
    
    # User agent summary
    ua_counts = defaultdict(int)
    for log in logs:
        if hasattr(log, 'user_agent') and log.user_agent:
            ua_counts[log.user_agent[:50]] += 1
    
    stats["user_agent_summary"] = {
        "total": len(ua_counts),
        "top_10": dict(sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    }
    
    # Bytes summary
    bytes_list = []
    for log in logs:
        if hasattr(log, 'bytes_sent') and log.bytes_sent:
            try:
                bytes_list.append(int(log.bytes_sent))
            except:
                pass
    
    if bytes_list:
        stats["bytes_summary"] = {
            "total": sum(bytes_list),
            "avg": np.mean(bytes_list),
            "min": min(bytes_list),
            "max": max(bytes_list),
            "p95": np.percentile(bytes_list, 95)
        }
    
    return stats

@app.websocket("/ws/analytics")
async def analytics_websocket(websocket: WebSocket):
    """WebSocket for real-time analytics updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Send analytics update every 10 seconds
            await asyncio.sleep(10)
            
            if logs_data["parsed_logs"]:
                update = {
                    "type": "analytics_update",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metrics": await get_metrics("1h", False),
                    "alerts_count": len(logs_data["alerts"]),
                    "active_connections": len(manager.active_connections)
                }
                
                await websocket.send_json(update)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Analytics WebSocket error: {e}")
        manager.disconnect(websocket)

def update_metrics():
    """Update basic metrics"""
    if logs_data["parsed_logs"]:
        logs = logs_data["parsed_logs"]
        
        total_requests = len(logs)
        
        unique_ips = set()
        for log in logs:
            if hasattr(log, 'client_ip') and log.client_ip:
                unique_ips.add(log.client_ip)
        
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
            "unique_ips": len(unique_ips),
            "total_bytes": total_bytes,
            "status_4xx": status_4xx,
            "status_5xx": status_5xx,
            "error_rate": error_rate,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Updated metrics: {logs_data['metrics']}")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
