"""
NGINX Log Parser - Supports multiple log formats
"""
import re
import gzip
from datetime import datetime
from typing import List, Optional
from models import LogEntry, ErrorLogEntry

class NGINXParser:
    """Parse NGINX access and error logs"""
    
    # Common NGINX log formats
    LOG_FORMATS = {
        "combined": r'(?P<ip>\S+) - - \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"',
        "main": r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+)',
        "extended": r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)" "(?P<host>.*?)"',
        "error": r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): \*(?P<cid>\d+) (?P<message>.+?), client: (?P<client>.+?), server: (?P<server>.+?), request: "(?P<request>.+?)", host: "(?P<host>.+?)"'
    }
    
    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern) 
            for name, pattern in self.LOG_FORMATS.items()
        }
    
    def detect_log_type(self, sample: str) -> str:
        """Detect log type from sample"""
        if "client:" in sample and "server:" in sample:
            return "error"
        
        # Try to match access log patterns
        for name, pattern in self.compiled_patterns.items():
            if name != "error":
                if pattern.search(sample):
                    return name
        
        # Default to combined format
        return "combined"
    
    def parse_access_log(self, log_content: str, format_name: str = "combined") -> List[LogEntry]:
        """Parse NGINX access log"""
        entries = []
        pattern = self.compiled_patterns.get(format_name, self.compiled_patterns["combined"])
        
        for line in log_content.strip().split('\n'):
            if not line.strip():
                continue
            
            match = pattern.match(line)
            if match:
                try:
                    data = match.groupdict()
                    
                    # Parse timestamp
                    timestamp_str = data.get('timestamp', '')
                    timestamp = self.parse_timestamp(timestamp_str)
                    
                    # Parse endpoint and query
                    endpoint = data.get('endpoint', '')
                    endpoint_parts = endpoint.split('?', 1)
                    path = endpoint_parts[0]
                    query = endpoint_parts[1] if len(endpoint_parts) > 1 else None
                    
                    # Create log entry
                    entry = LogEntry(
                        raw_log=line,
                        timestamp=timestamp,
                        client_ip=data.get('ip', ''),
                        method=data.get('method', ''),
                        endpoint=path,
                        query_params=query,
                        protocol=data.get('protocol', ''),
                        status=int(data.get('status', 0)),
                        bytes_sent=int(data.get('bytes', 0)) if data.get('bytes') else 0,
                        referrer=data.get('referrer', ''),
                        user_agent=data.get('user_agent', ''),
                        host=data.get('host', '')
                    )
                    
                    entries.append(entry)
                    
                except Exception as e:
                    print(f"Error parsing line: {line}")
                    print(f"Error: {e}")
                    continue
        
        return entries
    
    def parse_error_log(self, log_content: str) -> List[ErrorLogEntry]:
        """Parse NGINX error log"""
        entries = []
        pattern = self.compiled_patterns["error"]
        
        for line in log_content.strip().split('\n'):
            if not line.strip():
                continue
            
            match = pattern.match(line)
            if match:
                try:
                    data = match.groupdict()
                    
                    # Parse timestamp
                    timestamp_str = data.get('timestamp', '')
                    timestamp = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                    
                    # Create error log entry
                    entry = ErrorLogEntry(
                        raw_log=line,
                        timestamp=timestamp,
                        level=data.get('level', ''),
                        pid=int(data.get('pid', 0)),
                        tid=int(data.get('tid', 0)),
                        cid=int(data.get('cid', 0)),
                        message=data.get('message', ''),
                        client=data.get('client', ''),
                        server=data.get('server', ''),
                        request=data.get('request', ''),
                        host=data.get('host', '')
                    )
                    
                    entries.append(entry)
                    
                except Exception as e:
                    print(f"Error parsing error log line: {line}")
                    print(f"Error: {e}")
                    continue
        
        return entries
    
def parse_timestamp(self, timestamp_str: str) -> datetime:
    """Parse various timestamp formats"""
    formats = [
        "%d/%b/%Y:%H:%M:%S %z",  # 01/Jan/2024:12:34:56 +0000
        "%d/%b/%Y:%H:%M:%S",      # 01/Jan/2024:12:34:56
        "%Y-%m-%dT%H:%M:%S%z",    # 2024-01-01T12:34:56+00:00
        "%Y-%m-%d %H:%M:%S",      # 2024-01-01 12:34:56
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            # If datetime is naive (no timezone), make it UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    
    # If all else fails, return current time with UTC timezone
    return datetime.now(timezone.utc)
    
    def read_log_file(self, file_path: str) -> str:
        """Read log file, supporting .gz compression"""
        try:
            if file_path.endswith('.gz'):
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    return f.read()
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return ""
