#!/usr/bin/env python3
"""
ForenX-NGINX Sentinel Pro with Enhanced GeoIP Support
"""
# ... [Previous imports remain the same] ...
from geoip_manager import GeoIPManager

# Initialize GeoIP Manager
geoip_manager = None

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global geoip_manager
    
    # Initialize GeoIP Manager
    try:
        geoip_manager = GeoIPManager("geoip")
        if geoip_manager.initialized:
            logger.info("GeoIP Manager initialized successfully")
            
            # Log statistics
            stats = geoip_manager.get_statistics()
            logger.info(f"GeoIP Database: {stats['format']} with {stats['ip_ranges']} IP ranges")
        else:
            logger.warning("GeoIP Manager failed to initialize - geographic features will be limited")
    except Exception as e:
        logger.error(f"Error initializing GeoIP Manager: {e}")
        geoip_manager = None

@app.get("/api/geoip/statistics")
async def get_geoip_statistics():
    """Get GeoIP database statistics"""
    if not geoip_manager:
        return {"error": "GeoIP database not available"}
    
    stats = geoip_manager.get_statistics()
    return stats

@app.get("/api/geoip/lookup/{ip_address}")
async def lookup_ip(ip_address: str, detailed: bool = False):
    """Lookup IP address location"""
    if not geoip_manager:
        return {"error": "GeoIP database not available"}
    
    location = geoip_manager.get_location(ip_address)
    
    if not location:
        return {"error": "Location not found for IP address"}
    
    result = location.to_dict()
    
    if detailed:
        # Add additional information
        result.update({
            "ip": ip_address,
            "is_local": geoip_manager.is_local_ip(ip_address),
            "lookup_time": datetime.now(timezone.utc).isoformat()
        })
    
    return result

@app.get("/api/geo-distribution/enhanced")
async def get_enhanced_geo_distribution():
    """Get enhanced geographic distribution with ISP and ASN data"""
    if not logs_data["parsed_logs"] or not geoip_manager:
        return {"error": "No data or GeoIP database available"}
    
    logs = logs_data["parsed_logs"]
    
    geo_data = {
        "countries": defaultdict(int),
        "cities": defaultdict(int),
        "regions": defaultdict(int),
        "isps": defaultdict(int),
        "asns": defaultdict(int),
        "coordinates": [],
        "heatmap_data": []
    }
    
    processed_ips = set()
    
    for log in logs:
        if hasattr(log, 'client_ip'):
            ip = log.client_ip
            
            # Skip if already processed
            if ip in processed_ips:
                continue
            
            processed_ips.add(ip)
            location = geoip_manager.get_location(ip)
            
            if location:
                # Update counts
                if location.country:
                    geo_data["countries"][location.country] += 1
                if location.city:
                    geo_data["cities"][location.city] += 1
                if location.region:
                    geo_data["regions"][location.region] += 1
                if location.isp:
                    geo_data["isps"][location.isp] += 1
                if location.asn:
                    geo_data["asns"][location.asn] += 1
                
                # Add coordinate for map
                if location.latitude and location.longitude:
                    coord_key = f"{location.latitude:.4f},{location.longitude:.4f}"
                    
                    # Check if coordinate already exists
                    existing_coord = next(
                        (c for c in geo_data["coordinates"] 
                         if c["lat"] == location.latitude and c["lon"] == location.longitude),
                        None
                    )
                    
                    if existing_coord:
                        existing_coord["count"] += 1
                        existing_coord["ips"].append(ip)
                    else:
                        geo_data["coordinates"].append({
                            "lat": location.latitude,
                            "lon": location.longitude,
                            "count": 1,
                            "country": location.country,
                            "city": location.city,
                            "ips": [ip]
                        })
                    
                    # Add to heatmap data
                    geo_data["heatmap_data"].append([
                        location.latitude,
                        location.longitude,
                        1  # Weight
                    ])
    
    # Sort and limit top entries
    geo_data["top_countries"] = dict(
        sorted(geo_data["countries"].items(), key=lambda x: x[1], reverse=True)[:20]
    )
    geo_data["top_cities"] = dict(
        sorted(geo_data["cities"].items(), key=lambda x: x[1], reverse=True)[:20]
    )
    geo_data["top_isps"] = dict(
        sorted(geo_data["isps"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    geo_data["top_asns"] = dict(
        sorted(geo_data["asns"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    
    return geo_data

@app.get("/api/attack-origins")
async def get_attack_origins():
    """Get geographic origins of security attacks"""
    if not logs_data["alerts"] or not geoip_manager:
        return {"error": "No alerts or GeoIP database available"}
    
    alerts = logs_data["alerts"]
    
    attack_origins = {
        "by_country": defaultdict(lambda: {"count": 0, "types": defaultdict(int), "ips": set()}),
        "by_city": defaultdict(lambda: {"count": 0, "types": defaultdict(int), "ips": set()}),
        "by_isp": defaultdict(lambda: {"count": 0, "types": defaultdict(int), "ips": set()}),
        "coordinates": [],
        "attack_types": defaultdict(int)
    }
    
    for alert in alerts:
        ip = alert.client_ip
        attack_type = alert.attack_type.value if hasattr(alert.attack_type, 'value') else str(alert.attack_type)
        
        attack_origins["attack_types"][attack_type] += 1
        
        location = geoip_manager.get_location(ip)
        
        if location:
            # Update country stats
            if location.country:
                country_data = attack_origins["by_country"][location.country]
                country_data["count"] += 1
                country_data["types"][attack_type] += 1
                country_data["ips"].add(ip)
            
            # Update city stats
            if location.city:
                city_data = attack_origins["by_city"][f"{location.city}, {location.country}"]
                city_data["count"] += 1
                city_data["types"][attack_type] += 1
                city_data["ips"].add(ip)
            
            # Update ISP stats
            if location.isp:
                isp_data = attack_origins["by_isp"][location.isp]
                isp_data["count"] += 1
                isp_data["types"][attack_type] += 1
                isp_data["ips"].add(ip)
            
            # Add coordinate
            if location.latitude and location.longitude:
                attack_origins["coordinates"].append({
                    "lat": location.latitude,
                    "lon": location.longitude,
                    "ip": ip,
                    "attack_type": attack_type,
                    "country": location.country,
                    "city": location.city,
                    "confidence": alert.confidence
                })
    
    # Convert sets to counts
    for data_dict in [attack_origins["by_country"], attack_origins["by_city"], attack_origins["by_isp"]]:
        for key, data in data_dict.items():
            data["unique_ips"] = len(data["ips"])
            data["ips"] = list(data["ips"])[:10]  # Keep only first 10 IPs
            data["types"] = dict(data["types"])
    
    # Sort and get top entries
    attack_origins["top_countries"] = dict(
        sorted(attack_origins["by_country"].items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    )
    attack_origins["top_cities"] = dict(
        sorted(attack_origins["by_city"].items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    )
    attack_origins["top_isps"] = dict(
        sorted(attack_origins["by_isp"].items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    )
    
    return attack_origins

@app.get("/api/geoip/top-threats")
async def get_top_geo_threats(limit: int = 20):
    """Get top geographic threats with detailed information"""
    if not logs_data["parsed_logs"] or not geoip_manager:
        return {"error": "No data or GeoIP database available"}
    
    logs = logs_data["parsed_logs"]
    alerts = logs_data["alerts"]
    
    # Get all unique IPs
    all_ips = set()
    ip_request_counts = defaultdict(int)
    ip_alert_counts = defaultdict(int)
    ip_alert_types = defaultdict(lambda: defaultdict(int))
    
    # Count requests per IP
    for log in logs:
        if hasattr(log, 'client_ip'):
            ip = log.client_ip
            all_ips.add(ip)
            ip_request_counts[ip] += 1
    
    # Count alerts per IP
    for alert in alerts:
        ip = alert.client_ip
        attack_type = alert.attack_type.value if hasattr(alert.attack_type, 'value') else str(alert.attack_type)
        ip_alert_counts[ip] += 1
        ip_alert_types[ip][attack_type] += 1
    
    # Analyze top threats
    top_threats = []
    
    for ip in list(all_ips)[:limit]:  # Limit processing for performance
        location = geoip_manager.get_location(ip)
        
        if location:
            threat_score = calculate_threat_score(
                ip_request_counts.get(ip, 0),
                ip_alert_counts.get(ip, 0),
                ip_alert_types.get(ip, {})
            )
            
            top_threats.append({
                "ip": ip,
                "location": location.to_dict(),
                "requests": ip_request_counts.get(ip, 0),
                "alerts": ip_alert_counts.get(ip, 0),
                "alert_types": dict(ip_alert_types.get(ip, {})),
                "threat_score": threat_score,
                "is_high_risk": threat_score >= 0.7,
                "last_seen": get_last_seen_time(ip, logs)
            })
    
    # Sort by threat score
    top_threats.sort(key=lambda x: x["threat_score"], reverse=True)
    
    return {
        "total_ips_analyzed": len(all_ips),
        "top_threats": top_threats[:limit],
        "high_risk_count": sum(1 for t in top_threats if t["is_high_risk"]),
        "geo_distribution": {
            "countries": len(set(t["location"]["country"] for t in top_threats if t["location"]["country"])),
            "isps": len(set(t["location"]["isp"] for t in top_threats if t["location"]["isp"]))
        }
    }

def calculate_threat_score(request_count: int, alert_count: int, alert_types: Dict[str, int]) -> float:
    """Calculate threat score for an IP"""
    base_score = 0.0
    
    # Score based on alert count
    if alert_count > 0:
        base_score += min(alert_count / 10, 0.5)  # Max 0.5 for alerts
    
    # Score based on request volume (abnormal activity)
    if request_count > 1000:
        base_score += 0.2
    
    # Score based on alert types
    high_risk_types = {"SQL Injection", "XSS", "DoS", "Brute Force"}
    for alert_type in alert_types.keys():
        if alert_type in high_risk_types:
            base_score += 0.1
    
    # Normalize to 0-1 range
    return min(base_score, 1.0)

def get_last_seen_time(ip: str, logs: List[LogEntry]) -> Optional[str]:
    """Get last seen timestamp for IP"""
    ip_logs = [log for log in logs if hasattr(log, 'client_ip') and log.client_ip == ip]
    if ip_logs:
        latest = max(ip_logs, key=lambda x: x.timestamp if hasattr(x, 'timestamp') else datetime.min)
        return latest.timestamp.isoformat() if hasattr(latest, 'timestamp') else None
    return None

@app.get("/api/geoip/heatmap")
async def get_geo_heatmap():
    """Get heatmap data for visualization"""
    if not logs_data["parsed_logs"] or not geoip_manager:
        return {"error": "No data or GeoIP database available"}
    
    logs = logs_data["parsed_logs"]
    
    # Group by location for heatmap
    location_counts = defaultdict(int)
    
    for log in logs:
        if hasattr(log, 'client_ip'):
            ip = log.client_ip
            location = geoip_manager.get_location(ip)
            
            if location and location.latitude and location.longitude:
                # Round coordinates for heatmap clustering
                lat_key = round(location.latitude, 2)
                lon_key = round(location.longitude, 2)
                location_counts[(lat_key, lon_key)] += 1
    
    # Convert to heatmap format
    heatmap_data = [
        {
            "lat": lat,
            "lon": lon,
            "count": count,
            "intensity": min(count / 100, 1.0)  # Normalize intensity
        }
        for (lat, lon), count in location_counts.items()
    ]
    
    return {
        "heatmap_data": heatmap_data,
        "max_intensity": max((d["intensity"] for d in heatmap_data), default=0),
        "total_points": len(heatmap_data)
    }
