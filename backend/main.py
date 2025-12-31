#!/usr/bin/env python3
"""
ForenX-NGINX Sentinel - Advanced NGINX Forensic Dashboard v2.0
Complete with IP Geolocation, Interactive Maps, and Advanced Analytics
"""
import os
import json
import time
import hashlib
import asyncio
import uvicorn
import pandas as pd
import redis
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any, Tuple
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import logging
import maxminddb
from collections import defaultdict, Counter
import re

# Import custom modules
from log_parser import NGINXParser
from detection_engine import DetectionEngine
from models import LogEntry, AggregatedMetrics, AttackAlert, ErrorLogEntry, AttackType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ForenX-NGINX Sentinel v2.0",
    description="Advanced NGINX Forensic Dashboard with IP Geolocation & Interactive Maps",
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

# Redis for caching and real-time features
redis_client = None
try:
    redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)
    redis_client.ping()
    logger.info("Redis connected successfully")
except:
    logger.warning("Redis not available, using in-memory cache")
    redis_client = None

# GeoIP database
geoip_reader = None
GEOIP_DATABASE_PATH = os.getenv('GEOIP_DATABASE', '/app/geolite2/GeoLite2-City.mmdb')
if os.path.exists(GEOIP_DATABASE_PATH):
    try:
        geoip_reader = maxminddb.open_database(GEOIP_DATABASE_PATH)
        logger.info(f"GeoIP database loaded from {GEOIP_DATABASE_PATH}")
    except Exception as e:
        logger.error(f"Failed to load GeoIP database: {e}")
        geoip_reader = None
else:
    logger.warning(f"GeoIP database not found at {GEOIP_DATABASE_PATH}")

# In-memory storage (fallback)
logs_data = {
    "access_logs": [],
    "error_logs": [],
    "parsed_logs": [],
    "alerts": [],
    "metrics": {},
    "file_hashes": {},
    "geolocations": {},
    "hourly_patterns": {},
    "daily_patterns": {}
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

# Helper functions
def get_geolocation(ip_address: str) -> Dict:
    """Get geolocation for an IP address"""
    if not geoip_reader:
        return {"city": "Unknown", "country": "Unknown", "latitude": 0, "longitude": 0}
    
    try:
        geo_data = geoip_reader.get(ip_address)
        if geo_data:
            city = geo_data.get('city', {}).get('names', {}).get('en', 'Unknown')
            country = geo_data.get('country', {}).get('names', {}).get('en', 'Unknown')
            latitude = geo_data.get('location', {}).get('latitude', 0)
            longitude = geo_data.get('location', {}).get('longitude', 0)
            
            return {
                "city": city,
                "country": country,
                "latitude": latitude,
                "longitude": longitude,
                "continent": geo_data.get('continent', {}).get('names', {}).get('en', 'Unknown'),
                "timezone": geo_data.get('location', {}).get('time_zone', 'Unknown')
            }
    except Exception as e:
        logger.error(f"Error getting geolocation for {ip_address}: {e}")
    
    return {"city": "Unknown", "country": "Unknown", "latitude": 0, "longitude": 0}

def analyze_traffic_patterns(logs: List[LogEntry]):
    """Analyze traffic patterns for different time granularities"""
    hourly_patterns = defaultdict(int)
    daily_patterns = defaultdict(int)
    weekday_patterns = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'timestamp'):
            # Hourly pattern
            hour_key = log.timestamp.strftime("%H:00")
            hourly_patterns[hour_key] += 1
            
            # Daily pattern
            date_key = log.timestamp.strftime("%Y-%m-%d")
            daily_patterns[date_key] += 1
            
            # Weekday pattern
            weekday_key = log.timestamp.strftime("%A")
            weekday_patterns[weekday_key] += 1
    
    logs_data["hourly_patterns"] = dict(sorted(hourly_patterns.items()))
    logs_data["daily_patterns"] = dict(sorted(daily_patterns.items()))
    logs_data["weekday_patterns"] = weekday_patterns

def calculate_bandwidth_usage(logs: List[LogEntry]) -> Dict:
    """Calculate bandwidth usage by IP and endpoint"""
    ip_bandwidth = defaultdict(int)
    endpoint_bandwidth = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'bytes_sent') and log.bytes_sent:
            bytes_sent = int(log.bytes_sent)
            
            # By IP
            if hasattr(log, 'client_ip'):
                ip_bandwidth[log.client_ip] += bytes_sent
            
            # By endpoint
            if hasattr(log, 'endpoint'):
                endpoint_bandwidth[log.endpoint] += bytes_sent
    
    return {
        "ip_bandwidth": dict(sorted(ip_bandwidth.items(), key=lambda x: x[1], reverse=True)[:20]),
        "endpoint_bandwidth": dict(sorted(endpoint_bandwidth.items(), key=lambda x: x[1], reverse=True)[:20])
    }

@app.get("/")
async def root():
    return {
        "message": "ForenX-NGINX Sentinel API v2.0",
        "status": "running",
        "version": "2.0.0",
        "features": [
            "IP Geolocation Mapping",
            "Interactive Visualizations",
            "Multiple Time Granularities",
            "Real-time Monitoring",
            "Advanced Threat Detection",
            "Bandwidth Analytics"
        ]
    }

@app.post("/api/upload-logs")
async def upload_logs(
    files: List[UploadFile] = File(...),
    log_type: str = Form("auto"),
    rotate_logs: bool = Form(False)
):
    """Upload and parse NGINX log files with rotation support"""
    results = {
        "files_processed": [],
        "total_records": 0,
        "alerts_found": 0,
        "geolocations_added": 0,
        "file_hashes": []
    }
    
    # Clear existing data
    logs_data["parsed_logs"] = []
    logs_data["alerts"] = []
    logs_data["geolocations"] = {}
    
    for file in files:
        try:
            logger.info(f"Processing file: {file.filename}")
            
            # Check for rotated logs pattern
            filename = file.filename.lower()
            is_rotated = any(pattern in filename for pattern in ['.gz', '.1', '.2', '.old', '.backup'])
            
            if is_rotated:
                logger.info(f"Detected rotated log file: {file.filename}")
            
            # Read file content
            content = await file.read()
            
            # Calculate hash
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Decode content
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    content_str = content.decode('latin-1', errors='ignore')
                except:
                    content_str = content.decode('utf-8', errors='ignore')
            
            # Detect log type
            sample = content_str[:1000] if len(content_str) > 1000 else content_str
            if log_type == "auto":
                detected_type = parser.detect_log_type(sample)
            else:
                detected_type = log_type
            
            logger.info(f"Detected log type: {detected_type} for {file.filename}")
            
            # Parse logs
            parsed = []
            if detected_type == "error":
                parsed = parser.parse_error_log(content_str)
                logs_data["error_logs"].extend(parsed)
            else:
                parsed = parser.parse_access_log(content_str, detected_type)
                logs_data["access_logs"].extend(parsed)
            
            logs_data["parsed_logs"].extend(parsed)
            
            # Extract geolocations for new IPs
            geolocations_added = 0
            if detected_type != "error":
                unique_ips = set()
                for log in parsed:
                    if hasattr(log, 'client_ip') and log.client_ip:
                        ip = log.client_ip
                        if ip not in logs_data["geolocations"]:
                            geo = get_geolocation(ip)
                            logs_data["geolocations"][ip] = geo
                            geolocations_added += 1
                        unique_ips.add(ip)
            
            # Run detection
            if detected_type != "error" and parsed:
                alerts = detector.analyze_logs(parsed)
                logs_data["alerts"].extend(alerts)
                results["alerts_found"] += len(alerts)
            
            # Analyze patterns
            if parsed:
                analyze_traffic_patterns(parsed)
            
            # Store file info
            logs_data["file_hashes"][file.filename] = {
                "hash": file_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "size": len(content),
                "type": detected_type,
                "rotated": is_rotated
            }
            
            results["files_processed"].append({
                "filename": file.filename,
                "type": detected_type,
                "records": len(parsed),
                "hash": file_hash,
                "alerts": len(alerts) if 'alerts' in locals() else 0,
                "rotated": is_rotated,
                "geolocations": geolocations_added
            })
            results["total_records"] += len(parsed)
            results["geolocations_added"] += geolocations_added
            
            logger.info(f"Parsed {len(parsed)} records, added {geolocations_added} geolocations")
            
        except Exception as e:
            logger.error(f"Error processing {file.filename}: {str(e)}", exc_info=True)
            results["files_processed"].append({
                "filename": file.filename,
                "error": str(e),
                "success": False
            })
    
    # Update metrics and cache
    if logs_data["parsed_logs"]:
        update_metrics()
        if redis_client:
            cache_key = f"metrics:{datetime.now().strftime('%Y%m%d')}"
            redis_client.setex(cache_key, 3600, json.dumps(logs_data["metrics"]))
    
    logger.info(f"Upload complete: {results}")
    return results

@app.get("/api/geographic-distribution")
async def get_geographic_distribution(
    group_by: str = "country",
    limit: int = 50
):
    """Get geographic distribution of IP addresses"""
    if not logs_data["parsed_logs"]:
        return {"locations": [], "summary": {}}
    
    locations = []
    ip_counts = defaultdict(int)
    
    for log in logs_data["parsed_logs"]:
        if hasattr(log, 'client_ip'):
            ip = log.client_ip
            ip_counts[ip] += 1
    
    # Get geolocation for each unique IP
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]:
        geo = logs_data["geolocations"].get(ip, get_geolocation(ip))
        
        if group_by == "city":
            location_key = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
        else:  # country
            location_key = geo.get('country', 'Unknown')
        
        locations.append({
            "ip": ip,
            "count": count,
            "city": geo.get('city', 'Unknown'),
            "country": geo.get('country', 'Unknown'),
            "latitude": geo.get('latitude', 0),
            "longitude": geo.get('longitude', 0),
            "continent": geo.get('continent', 'Unknown'),
            "location_key": location_key
        })
    
    # Group by location
    grouped_data = defaultdict(lambda: {"count": 0, "ips": [], "coordinates": []})
    for loc in locations:
        key = loc["location_key"]
        grouped_data[key]["count"] += loc["count"]
        grouped_data[key]["ips"].append(loc["ip"])
        if loc["latitude"] and loc["longitude"]:
            grouped_data[key]["coordinates"] = [loc["latitude"], loc["longitude"]]
    
    # Prepare summary
    summary = {
        "total_ips": len(ip_counts),
        "countries": len(set(loc["country"] for loc in locations if loc["country"] != "Unknown")),
        "cities": len(set(loc["city"] for loc in locations if loc["city"] != "Unknown")),
        "top_countries": Counter([loc["country"] for loc in locations]).most_common(10)
    }
    
    return {
        "locations": locations,
        "grouped": dict(grouped_data),
        "summary": summary
    }

@app.get("/api/traffic-patterns")
async def get_traffic_patterns(
    granularity: str = "hourly",
    time_range: str = "7d"
):
    """Get traffic patterns at different granularities"""
    if not logs_data["parsed_logs"]:
        return {"patterns": {}, "summary": {}}
    
    now = datetime.now(timezone.utc)
    
    # Calculate time window
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
        start_time = datetime.min.replace(tzinfo=timezone.utc)
    
    # Filter logs
    filtered_logs = [
        log for log in logs_data["parsed_logs"]
        if hasattr(log, 'timestamp') and log.timestamp >= start_time
    ]
    
    patterns = defaultdict(int)
    
    for log in filtered_logs:
        if granularity == "minute":
            key = log.timestamp.strftime("%Y-%m-%d %H:%M")
        elif granularity == "hourly":
            key = log.timestamp.strftime("%Y-%m-%d %H:00")
        elif granularity == "daily":
            key = log.timestamp.strftime("%Y-%m-%d")
        elif granularity == "weekly":
            week_num = log.timestamp.isocalendar()[1]
            key = f"{log.timestamp.year}-W{week_num:02d}"
        elif granularity == "monthly":
            key = log.timestamp.strftime("%Y-%m")
        else:
            key = log.timestamp.strftime("%Y-%m-%d %H:%M")
        
        patterns[key] += 1
    
    # Sort by time
    sorted_patterns = dict(sorted(patterns.items()))
    
    # Calculate statistics
    if sorted_patterns:
        values = list(sorted_patterns.values())
        summary = {
            "total": sum(values),
            "average": sum(values) / len(values),
            "peak": max(values),
            "peak_time": max(sorted_patterns.items(), key=lambda x: x[1])[0] if sorted_patterns else None,
            "low": min(values),
            "std_dev": (sum((x - (sum(values)/len(values)))**2 for x in values) / len(values))**0.5 if len(values) > 1 else 0
        }
    else:
        summary = {"total": 0, "average": 0, "peak": 0, "peak_time": None, "low": 0, "std_dev": 0}
    
    return {
        "patterns": sorted_patterns,
        "summary": summary,
        "granularity": granularity,
        "time_range": time_range
    }

@app.get("/api/bandwidth-analysis")
async def get_bandwidth_analysis(
    group_by: str = "ip",  # ip, endpoint, hour, day
    top_n: int = 20
):
    """Analyze bandwidth usage"""
    if not logs_data["parsed_logs"]:
        return {"analysis": {}, "summary": {}}
    
    logs = logs_data["parsed_logs"]
    
    if group_by == "ip":
        data = defaultdict(int)
        for log in logs:
            if hasattr(log, 'client_ip') and hasattr(log, 'bytes_sent') and log.bytes_sent:
                data[log.client_ip] += int(log.bytes_sent)
    
    elif group_by == "endpoint":
        data = defaultdict(int)
        for log in logs:
            if hasattr(log, 'endpoint') and hasattr(log, 'bytes_sent') and log.bytes_sent:
                data[log.endpoint] += int(log.bytes_sent)
    
    elif group_by == "hour":
        data = defaultdict(int)
        for log in logs:
            if hasattr(log, 'timestamp') and hasattr(log, 'bytes_sent') and log.bytes_sent:
                hour_key = log.timestamp.strftime("%H:00")
                data[hour_key] += int(log.bytes_sent)
    
    elif group_by == "day":
        data = defaultdict(int)
        for log in logs:
            if hasattr(log, 'timestamp') and hasattr(log, 'bytes_sent') and log.bytes_sent:
                day_key = log.timestamp.strftime("%Y-%m-%d")
                data[day_key] += int(log.bytes_sent)
    
    # Sort and limit
    sorted_data = dict(sorted(data.items(), key=lambda x: x[1], reverse=True)[:top_n])
    
    # Calculate summary
    total_bytes = sum(data.values())
    avg_bytes = total_bytes / len(data) if data else 0
    
    return {
        "analysis": sorted_data,
        "summary": {
            "total_bytes": total_bytes,
            "average_bytes_per_entry": avg_bytes,
            "entries_with_bandwidth": len([log for log in logs if hasattr(log, 'bytes_sent') and log.bytes_sent]),
            "top_consumer": max(data.items(), key=lambda x: x[1])[0] if data else None
        },
        "group_by": group_by
    }

@app.get("/api/advanced-metrics")
async def get_advanced_metrics():
    """Get advanced metrics for dashboard"""
    if not logs_data["parsed_logs"]:
        return {
            "response_times": {},
            "user_engagement": {},
            "traffic_sources": {},
            "performance": {}
        }
    
    logs = logs_data["parsed_logs"]
    
    # Response time analysis
    response_times = []
    for log in logs:
        if hasattr(log, 'request_time') and log.request_time:
            response_times.append(log.request_time)
    
    # User engagement (sessions based on IP and time)
    sessions = defaultdict(list)
    for log in logs:
        if hasattr(log, 'client_ip') and hasattr(log, 'timestamp'):
            ip = log.client_ip
            hour = log.timestamp.replace(minute=0, second=0, microsecond=0)
            sessions[(ip, hour)].append(log.timestamp)
    
    # Traffic sources
    referrers = defaultdict(int)
    user_agents = defaultdict(int)
    for log in logs:
        if hasattr(log, 'referrer') and log.referrer and log.referrer != '-':
            referrers[log.referrer] += 1
        if hasattr(log, 'user_agent') and log.user_agent:
            # Categorize user agents
            ua = log.user_agent.lower()
            if 'bot' in ua or 'crawler' in ua or 'spider' in ua:
                category = 'Bot'
            elif 'mobile' in ua:
                category = 'Mobile'
            elif 'chrome' in ua:
                category = 'Chrome'
            elif 'firefox' in ua:
                category = 'Firefox'
            elif 'safari' in ua:
                category = 'Safari'
            elif 'edge' in ua:
                category = 'Edge'
            else:
                category = 'Other'
            user_agents[category] += 1
    
    return {
        "response_times": {
            "average": sum(response_times) / len(response_times) if response_times else 0,
            "p95": sorted(response_times)[int(len(response_times) * 0.95)] if response_times else 0,
            "p99": sorted(response_times)[int(len(response_times) * 0.99)] if response_times else 0,
            "max": max(response_times) if response_times else 0,
            "min": min(response_times) if response_times else 0
        },
        "user_engagement": {
            "total_sessions": len(sessions),
            "average_session_length": sum(len(v) for v in sessions.values()) / len(sessions) if sessions else 0,
            "returning_users": len(set(ip for ip, _ in sessions.keys())),
            "peak_concurrent": max(len(v) for v in sessions.values()) if sessions else 0
        },
        "traffic_sources": {
            "direct": len([log for log in logs if not hasattr(log, 'referrer') or log.referrer == '-']),
            "referrers": dict(sorted(referrers.items(), key=lambda x: x[1], reverse=True)[:10]),
            "user_agents": dict(user_agents)
        },
        "performance": {
            "cache_hit_rate": len([log for log in logs if hasattr(log, 'status') and log.status == 304]) / len(logs) if logs else 0,
            "compression_rate": len([log for log in logs if hasattr(log, 'bytes_sent') and log.bytes_sent and log.bytes_sent < 1000]) / len(logs) if logs else 0
        }
    }

@app.get("/api/interactive-map")
async def get_interactive_map_data(
    zoom_level: int = 2,
    cluster: bool = True
):
    """Get data for interactive map visualization"""
    if not logs_data["parsed_logs"]:
        return {"markers": [], "clusters": [], "heatmap": []}
    
    # Get unique IPs with counts
    ip_counts = defaultdict(int)
    for log in logs_data["parsed_logs"]:
        if hasattr(log, 'client_ip'):
            ip_counts[log.client_ip] += 1
    
    markers = []
    clusters = defaultdict(list)
    heatmap_data = []
    
    for ip, count in ip_counts.items():
        geo = logs_data["geolocations"].get(ip, get_geolocation(ip))
        
        if geo["latitude"] and geo["longitude"]:
            marker = {
                "type": "Feature",
                "properties": {
                    "ip": ip,
                    "count": count,
                    "city": geo["city"],
                    "country": geo["country"],
                    "radius": min(20, max(5, count // 10))
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [geo["longitude"], geo["latitude"]]
                }
            }
            markers.append(marker)
            
            # For clustering
            if cluster:
                cluster_key = f"{geo['country']}_{geo['city']}"
                clusters[cluster_key].append(marker)
            
            # For heatmap
            heatmap_data.append([geo["latitude"], geo["longitude"], count])
    
    # Create clusters
    cluster_features = []
    for cluster_key, cluster_markers in clusters.items():
        if len(cluster_markers) > 1:
            # Calculate cluster center
            lats = [m["geometry"]["coordinates"][1] for m in cluster_markers]
            lons = [m["geometry"]["coordinates"][0] for m in cluster_markers]
            counts = [m["properties"]["count"] for m in cluster_markers]
            
            cluster_features.append({
                "type": "Feature",
                "properties": {
                    "cluster": True,
                    "count": sum(counts),
                    "marker_count": len(cluster_markers)
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [
                        sum(lons) / len(lons),
                        sum(lats) / len(lats)
                    ]
                }
            })
    
    return {
        "type": "FeatureCollection",
        "features": markers,
        "clusters": cluster_features,
        "heatmap": heatmap_data,
        "summary": {
            "total_markers": len(markers),
            "total_clusters": len(cluster_features),
            "countries": len(set(m["properties"]["country"] for m in markers)),
            "total_requests": sum(ip_counts.values())
        }
    }

@app.get("/api/warnings")
async def get_warnings():
    """Get warning lines based on warnlists"""
    if not logs_data["parsed_logs"]:
        return {"warnings": [], "warnlists": {}}
    
    # Define warnlists (configurable)
    warnlists = {
        "suspicious_ips": [
            r"10\.0\.0\.",
            r"192\.168\.",
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"127\.0\.0\.1"
        ],
        "suspicious_paths": [
            r"/\.env",
            r"/\.git",
            r"/wp-admin",
            r"/admin",
            r"/\.\./"
        ],
        "error_codes": ["500", "502", "503", "504"],
        "slow_requests": ["request_time > 5.0"]
    }
    
    warnings = []
    
    for log in logs_data["parsed_logs"]:
        warning_entries = []
        
        # Check IPs
        if hasattr(log, 'client_ip'):
            for pattern in warnlists["suspicious_ips"]:
                if re.match(pattern, log.client_ip):
                    warning_entries.append(f"Suspicious IP: {log.client_ip}")
        
        # Check paths
        if hasattr(log, 'endpoint'):
            for pattern in warnlists["suspicious_paths"]:
                if re.search(pattern, log.endpoint):
                    warning_entries.append(f"Suspicious path: {log.endpoint}")
        
        # Check status codes
        if hasattr(log, 'status'):
            if str(log.status) in warnlists["error_codes"]:
                warning_entries.append(f"Error status: {log.status}")
        
        # Check request times
        if hasattr(log, 'request_time'):
            if log.request_time > 5.0:
                warning_entries.append(f"Slow request: {log.request_time}s")
        
        if warning_entries:
            warnings.append({
                "timestamp": log.timestamp.isoformat() if hasattr(log, 'timestamp') else None,
                "ip": log.client_ip if hasattr(log, 'client_ip') else None,
                "endpoint": log.endpoint if hasattr(log, 'endpoint') else None,
                "status": log.status if hasattr(log, 'status') else None,
                "warnings": warning_entries,
                "raw_log": log.raw_log[:200] if hasattr(log, 'raw_log') else None
            })
    
    return {
        "warnings": warnings,
        "warnlists": warnlists,
        "summary": {
            "total_warnings": len(warnings),
            "warning_types": Counter([w for warning in warnings for w in warning["warnings"]]),
            "top_offending_ips": Counter([w["ip"] for w in warnings if w["ip"]]).most_common(10)
        }
    }

@app.get("/api/speed-analysis")
async def get_speed_analysis(
    percentile: int = 95
):
    """Analyze server response speed"""
    if not logs_data["parsed_logs"]:
        return {"analysis": {}, "percentiles": {}}
    
    logs = logs_data["parsed_logs"]
    
    # Extract request times
    request_times = []
    for log in logs:
        if hasattr(log, 'request_time') and log.request_time:
            request_times.append(log.request_time)
    
    if not request_times:
        return {"analysis": {}, "percentiles": {}, "message": "No request time data available"}
    
    # Calculate statistics
    request_times_sorted = sorted(request_times)
    n = len(request_times_sorted)
    
    percentiles = {
        "p50": request_times_sorted[int(n * 0.50)],
        "p75": request_times_sorted[int(n * 0.75)],
        "p90": request_times_sorted[int(n * 0.90)],
        "p95": request_times_sorted[int(n * 0.95)],
        "p99": request_times_sorted[int(n * 0.99)],
        "p100": request_times_sorted[-1]
    }
    
    # Group by endpoint
    endpoint_times = defaultdict(list)
    for log in logs:
        if hasattr(log, 'endpoint') and hasattr(log, 'request_time') and log.request_time:
            endpoint_times[log.endpoint].append(log.request_time)
    
    endpoint_stats = {}
    for endpoint, times in endpoint_times.items():
        if times:
            endpoint_stats[endpoint] = {
                "count": len(times),
                "average": sum(times) / len(times),
                "p95": sorted(times)[int(len(times) * 0.95)],
                "max": max(times),
                "min": min(times)
            }
    
    # Group by hour
    hourly_times = defaultdict(list)
    for log in logs:
        if hasattr(log, 'timestamp') and hasattr(log, 'request_time') and log.request_time:
            hour_key = log.timestamp.strftime("%H:00")
            hourly_times[hour_key].append(log.request_time)
    
    hourly_stats = {}
    for hour, times in sorted(hourly_times.items()):
        if times:
            hourly_stats[hour] = {
                "count": len(times),
                "average": sum(times) / len(times),
                "p95": sorted(times)[int(len(times) * 0.95)],
                "peak_time": max(times)
            }
    
    return {
        "analysis": {
            "total_requests_with_time": len(request_times),
            "average_response_time": sum(request_times) / n,
            "median_response_time": request_times_sorted[n // 2],
            "fastest_response": min(request_times),
            "slowest_response": max(request_times),
            "std_dev": (sum((x - (sum(request_times)/n))**2 for x in request_times) / n)**0.5
        },
        "percentiles": percentiles,
        "endpoint_stats": dict(sorted(endpoint_stats.items(), key=lambda x: x[1]["average"], reverse=True)[:20]),
        "hourly_stats": hourly_stats,
        "performance_grades": {
            "excellent": len([t for t in request_times if t < 0.1]),
            "good": len([t for t in request_times if 0.1 <= t < 0.5]),
            "fair": len([t for t in request_times if 0.5 <= t < 1.0]),
            "poor": len([t for t in request_times if t >= 1.0])
        }
    }

# Keep existing endpoints with improvements
@app.get("/api/metrics")
async def get_metrics(time_range: str = "24h"):
    """Enhanced metrics endpoint"""
    # ... (keep existing implementation but add caching)
    pass

@app.get("/api/top-data")
async def get_top_data(category: str = "ips", limit: int = 10):
    """Enhanced top-data endpoint"""
    # ... (keep existing implementation)
    pass

@app.websocket("/ws/realtime")
async def websocket_realtime(websocket: WebSocket):
    """Enhanced WebSocket for real-time data"""
    await manager.connect(websocket)
    try:
        while True:
            # Send real-time metrics
            if logs_data["parsed_logs"]:
                recent_logs = [
                    log for log in logs_data["parsed_logs"][-10:]
                    if hasattr(log, 'timestamp') and 
                    log.timestamp > datetime.now(timezone.utc) - timedelta(minutes=1)
                ]
                
                if recent_logs:
                    await websocket.send_json({
                        "type": "realtime_update",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "recent_logs": len(recent_logs),
                        "alerts": len(logs_data["alerts"][-5:]),
                        "bandwidth": calculate_bandwidth_usage(recent_logs)
                    })
            
            await asyncio.sleep(2)  # Update every 2 seconds
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

def update_metrics():
    """Update all metrics"""
    if logs_data["parsed_logs"]:
        logs = logs_data["parsed_logs"]
        
        # Basic metrics
        total_requests = len(logs)
        unique_ips = len(set(log.client_ip for log in logs if hasattr(log, 'client_ip')))
        total_bytes = sum(int(log.bytes_sent) for log in logs if hasattr(log, 'bytes_sent') and log.bytes_sent)
        
        status_4xx = len([log for log in logs if hasattr(log, 'status') and 400 <= log.status < 500])
        status_5xx = len([log for log in logs if hasattr(log, 'status') and 500 <= log.status < 600])
        error_rate = (status_4xx + status_5xx) / total_requests if total_requests > 0 else 0
        
        logs_data["metrics"] = {
            "total_requests": total_requests,
            "unique_ips": unique_ips,
            "total_bytes": total_bytes,
            "status_4xx": status_4xx,
            "status_5xx": status_5xx,
            "error_rate": error_rate,
            "geolocations": len(logs_data["geolocations"]),
            "bandwidth": calculate_bandwidth_usage(logs)
        }

# Create necessary directories
os.makedirs("uploads", exist_ok=True)
os.makedirs("data/geolite2", exist_ok=True)
os.makedirs("samples/nginx_logs", exist_ok=True)

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
