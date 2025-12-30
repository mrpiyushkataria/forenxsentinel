"""
Data models for NGINX Forensics - COMPLETE FIXED VERSION
"""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel
from enum import Enum

class LogEntry(BaseModel):
    """Parsed NGINX access log entry"""
    raw_log: str
    timestamp: datetime
    client_ip: str
    method: str
    endpoint: str
    query_params: Optional[str] = None
    protocol: str
    status: int
    bytes_sent: Optional[int] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None
    host: Optional[str] = None
    request_time: Optional[float] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def dict(self, **kwargs):
        """Override dict method to ensure datetime serialization - ADD THIS METHOD"""
        d = super().dict(**kwargs)
        # Ensure timestamp is properly serialized
        if 'timestamp' in d and isinstance(d['timestamp'], datetime):
            d['timestamp'] = d['timestamp'].isoformat()
        return d

class ErrorLogEntry(BaseModel):
    """Parsed NGINX error log entry"""
    raw_log: str
    timestamp: datetime
    level: str
    pid: int
    tid: int
    cid: int
    message: str
    client: str
    server: str
    request: str
    host: str
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def dict(self, **kwargs):
        """Override dict method to ensure datetime serialization - ADD THIS METHOD"""
        d = super().dict(**kwargs)
        if 'timestamp' in d and isinstance(d['timestamp'], datetime):
            d['timestamp'] = d['timestamp'].isoformat()
        return d

class AttackType(str, Enum):
    """Types of attacks to detect"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    PATH_TRAVERSAL = "Path Traversal"
    DOS = "Denial of Service"
    BRUTE_FORCE = "Brute Force"
    DATA_EXFILTRATION = "Data Exfiltration"
    SCANNING = "Scanning/Reconnaissance"
    EXPLOIT_ATTEMPT = "Exploit Attempt"
    SUSPICIOUS_ACTIVITY = "Suspicious Activity"

class AttackAlert(BaseModel):
    """Security alert generated from log analysis"""
    timestamp: datetime
    client_ip: str
    attack_type: AttackType
    endpoint: str
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    confidence: float  # 0.0 to 1.0
    details: str
    raw_log_sample: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def dict(self, **kwargs):
        """Override dict method to ensure datetime serialization - ADD THIS METHOD"""
        d = super().dict(**kwargs)
        if 'timestamp' in d and isinstance(d['timestamp'], datetime):
            d['timestamp'] = d['timestamp'].isoformat()
        if 'attack_type' in d and isinstance(d['attack_type'], AttackType):
            d['attack_type'] = d['attack_type'].value
        return d

class AggregatedMetrics(BaseModel):
    """Aggregated metrics for dashboard"""
    total_requests: int = 0
    unique_ips: int = 0
    total_bytes: int = 0
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    error_rate: float = 0.0
    request_methods: Dict[str, int] = {}
    top_endpoints: Dict[str, int] = {}
    top_ips: Dict[str, int] = {}
    timeframe_min: Optional[datetime] = None
    timeframe_max: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def dict(self, **kwargs):
        """Override dict method to ensure datetime serialization - ADD THIS METHOD"""
        d = super().dict(**kwargs)
        if 'timeframe_min' in d and isinstance(d['timeframe_min'], datetime):
            d['timeframe_min'] = d['timeframe_min'].isoformat()
        if 'timeframe_max' in d and isinstance(d['timeframe_max'], datetime):
            d['timeframe_max'] = d['timeframe_max'].isoformat()
        return d

class ExportRequest(BaseModel):
    """Request model for log export"""
    format: str = "csv"
    filters: Optional[Dict[str, Any]] = None
