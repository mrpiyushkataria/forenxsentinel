"""
Detection Engine - Identify attacks and suspicious patterns
"""
from typing import List, Dict, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import re
from models import LogEntry, AttackAlert, AttackType

class DetectionEngine:
    """Detect attacks and suspicious patterns in NGINX logs"""
    
    # Detection patterns
    SQL_INJECTION_PATTERNS = [
        r'union\s+select',
        r'sleep\s*\(\s*\d+\s*\)',
        r'benchmark\s*\(.*\)',
        r'(\%27)|(\')|(\-\-)',
        r'/\*.*\*/',
        r'\bor\b.*=.*\bor\b',
        r'exec\s*\(.*\)',
        r'insert\s+into',
        r'drop\s+table',
        r'select\s+.*from'
    ]
    
    XSS_PATTERNS = [
        r'<script.*?>.*?</script>',
        r'on\w+\s*=',
        r'javascript:',
        r'vbscript:',
        r'alert\s*\(.*\)',
        r'document\.\w+',
        r'window\.location',
        r'eval\s*\(.*\)'
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'etc/passwd',
        r'win\.ini',
        r'boot\.ini',
        r'/proc/self/',
        r'\.\.%2f',
        r'\.\.%5c'
    ]
    
    COMMON_EXPLOIT_PATTERNS = [
        r'phpinfo\(\)',
        r'\.env',
        r'\.git/config',
        r'\.DS_Store',
        r'wp-config\.php',
        r'config\.json',
        r'\.bak$',
        r'\.old$'
    ]
    
    BOT_USER_AGENTS = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
        'python-requests', 'java', 'go-http-client', 'node-fetch',
        'apache-httpclient', 'okhttp', 'libwww-perl'
    ]
    
    def __init__(self):
        self.compiled_patterns = {
            "sql_injection": [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS],
            "xss": [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS],
            "path_traversal": [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS],
            "common_exploits": [re.compile(p, re.IGNORECASE) for p in self.COMMON_EXPLOIT_PATTERNS]
        }
        
        # Tracking for rate-based detection
        self.ip_request_counts = defaultdict(list)
        self.endpoint_errors = defaultdict(list)
    
    def analyze_logs(self, logs: List[LogEntry]) -> List[AttackAlert]:
        """Analyze logs and generate security alerts"""
        alerts = []
        
        for log in logs:
            # Check for individual attack patterns
            log_alerts = self.check_attack_patterns(log)
            alerts.extend(log_alerts)
        
        # Check for rate-based attacks
        rate_alerts = self.check_rate_based_attacks(logs)
        alerts.extend(rate_alerts)
        
        # Check for data exfiltration
        exfiltration_alerts = self.check_data_exfiltration(logs)
        alerts.extend(exfiltration_alerts)
        
        # Check for brute force attempts
        brute_force_alerts = self.check_brute_force(logs)
        alerts.extend(brute_force_alerts)
        
        return alerts
    
    def check_attack_patterns(self, log: LogEntry) -> List[AttackAlert]:
        """Check individual log entry for attack patterns"""
        alerts = []
        
        # Combine endpoint and query for pattern matching
        full_request = log.endpoint
        if log.query_params:
            full_request += "?" + log.query_params
        
        # Check SQL Injection
        if self.detect_pattern(full_request, "sql_injection"):
            alerts.append(self.create_alert(
                log=log,
                attack_type=AttackType.SQL_INJECTION,
                confidence=0.85,
                details="SQL injection pattern detected in request"
            ))
        
        # Check XSS
        if self.detect_pattern(full_request, "xss"):
            alerts.append(self.create_alert(
                log=log,
                attack_type=AttackType.XSS,
                confidence=0.80,
                details="Cross-site scripting pattern detected"
            ))
        
        # Check Path Traversal
        if self.detect_pattern(full_request, "path_traversal"):
            alerts.append(self.create_alert(
                log=log,
                attack_type=AttackType.PATH_TRAVERSAL,
                confidence=0.90,
                details="Path traversal attempt detected"
            ))
        
        # Check Common Exploits
        if self.detect_pattern(full_request, "common_exploits"):
            alerts.append(self.create_alert(
                log=log,
                attack_type=AttackType.EXPLOIT_ATTEMPT,
                confidence=0.75,
                details="Common exploit pattern detected"
            ))
        
        # Check for suspicious user agents
        if log.user_agent and self.is_suspicious_user_agent(log.user_agent):
            alerts.append(self.create_alert(
                log=log,
                attack_type=AttackType.SCANNING,
                confidence=0.70,
                details=f"Suspicious user agent detected: {log.user_agent[:50]}"
            ))
        
        # Check for high error rates on specific endpoint (per log)
        if log.status >= 400:
            alerts.append(self.create_alert(
                log=log,
                attack_type=AttackType.SUSPICIOUS_ACTIVITY,
                confidence=0.60,
                details=f"Error {log.status} on endpoint {log.endpoint}"
            ))
        
        return alerts
    
    def check_rate_based_attacks(self, logs: List[LogEntry], 
                                time_window_minutes: int = 5,
                                request_threshold: int = 100) -> List[AttackAlert]:
        """Check for rate-based attacks (DoS, brute force)"""
        alerts = []
        
        # Group requests by IP and time window
        ip_requests = defaultdict(list)
        for log in logs:
            ip_requests[log.client_ip].append(log.timestamp)
        
        # Check each IP for high request rate
        for ip, timestamps in ip_requests.items():
            if len(timestamps) < request_threshold:
                continue
            
            # Sort timestamps
            timestamps.sort()
            
            # Check for high frequency in time window
            window_start = timestamps[0]
            requests_in_window = 0
            
            for ts in timestamps:
                if ts <= window_start + timedelta(minutes=time_window_minutes):
                    requests_in_window += 1
                else:
                    # Slide window
                    while timestamps and ts > window_start + timedelta(minutes=time_window_minutes):
                        window_start = timestamps.pop(0)
                        requests_in_window -= 1
                    requests_in_window += 1
                
                if requests_in_window >= request_threshold:
                    # Found potential DoS
                    sample_log = next(log for log in logs if log.client_ip == ip)
                    alerts.append(self.create_alert(
                        log=sample_log,
                        attack_type=AttackType.DOS,
                        confidence=0.90,
                        details=f"High request rate detected: {requests_in_window} requests in {time_window_minutes} minutes"
                    ))
                    break
        
        return alerts
    
    def check_data_exfiltration(self, logs: List[LogEntry],
                               byte_threshold: int = 10000000,  # 10MB
                               time_window_hours: int = 1) -> List[AttackAlert]:
        """Check for potential data exfiltration"""
        alerts = []
        
        # Group by IP and calculate total bytes transferred
        ip_bytes = defaultdict(int)
        ip_logs = defaultdict(list)
        
        for log in logs:
            if log.bytes_sent:
                ip_bytes[log.client_ip] += log.bytes_sent
                ip_logs[log.client_ip].append(log)
        
        # Check for high data transfer
        for ip, total_bytes in ip_bytes.items():
            if total_bytes > byte_threshold:
                # Get sample log
                sample_log = ip_logs[ip][0]
                
                # Calculate time range
                timestamps = [log.timestamp for log in ip_logs[ip]]
                time_range = max(timestamps) - min(timestamps)
                
                alerts.append(self.create_alert(
                    log=sample_log,
                    attack_type=AttackType.DATA_EXFILTRATION,
                    confidence=0.85 if time_range < timedelta(hours=time_window_hours) else 0.70,
                    details=f"Large data transfer detected: {self.format_bytes(total_bytes)} in {time_range}"
                ))
        
        return alerts
    
    def check_brute_force(self, logs: List[LogEntry],
                         error_threshold: int = 10,
                         time_window_minutes: int = 5) -> List[AttackAlert]:
        """Check for brute force attempts (multiple 401/403/404)"""
        alerts = []
        
        # Filter for error responses
        error_logs = [log for log in logs if log.status in (401, 403, 404)]
        
        # Group by IP and endpoint
        ip_endpoint_errors = defaultdict(lambda: defaultdict(list))
        
        for log in error_logs:
            key = f"{log.client_ip}:{log.endpoint}"
            ip_endpoint_errors[log.client_ip][log.endpoint].append(log.timestamp)
        
        # Check each IP+endpoint for rapid errors
        for ip, endpoints in ip_endpoint_errors.items():
            for endpoint, timestamps in endpoints.items():
                if len(timestamps) >= error_threshold:
                    # Check if errors are close in time
                    timestamps.sort()
                    time_range = timestamps[-1] - timestamps[0]
                    
                    if time_range < timedelta(minutes=time_window_minutes):
                        # Get sample log
                        sample_log = next(
                            log for log in logs 
                            if log.client_ip == ip and log.endpoint == endpoint
                        )
                        
                        alerts.append(self.create_alert(
                            log=sample_log,
                            attack_type=AttackType.BRUTE_FORCE,
                            confidence=0.95,
                            details=f"Brute force attempt: {len(timestamps)} errors in {time_range.seconds//60} minutes"
                        ))
        
        return alerts
    
    def detect_pattern(self, text: str, pattern_type: str) -> bool:
        """Check if text matches any pattern of given type"""
        if pattern_type not in self.compiled_patterns:
            return False
        
        for pattern in self.compiled_patterns[pattern_type]:
            if pattern.search(text):
                return True
        
        return False
    
    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        ua_lower = user_agent.lower()
        
        # Check for bots
        for bot in self.BOT_USER_AGENTS:
            if bot in ua_lower:
                return True
        
        # Check for missing or empty user agent
        if not user_agent or user_agent == '-':
            return True
        
        # Check for very short user agents
        if len(user_agent) < 10:
            return True
        
        return False
    
    def create_alert(self, log: LogEntry, attack_type: AttackType,
                    confidence: float, details: str) -> AttackAlert:
        """Create an attack alert"""
        return AttackAlert(
            timestamp=log.timestamp,
            client_ip=log.client_ip,
            attack_type=attack_type,
            endpoint=log.endpoint,
            user_agent=log.user_agent,
            status_code=log.status,
            confidence=confidence,
            details=details,
            raw_log_sample=log.raw_log[:200]
        )
    
    @staticmethod
    def format_bytes(bytes_num: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_num < 1024.0:
                return f"{bytes_num:.2f} {unit}"
            bytes_num /= 1024.0
        return f"{bytes_num:.2f} PB"
