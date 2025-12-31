"""
GeoIP Manager for ForenX-NGINX Sentinel
Supports multiple GeoIP database formats
"""
import os
import csv
import sqlite3
import ipaddress
from typing import Dict, Optional, Any, Tuple, List
import logging
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)

@dataclass
class GeoLocation:
    """Geographic location data"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None
    accuracy_radius: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "asn": self.asn,
            "timezone": self.timezone,
            "accuracy_radius": self.accuracy_radius
        }

class GeoIPManager:
    """Manage GeoIP database lookups with multiple format support"""
    
    def __init__(self, geoip_dir: str = "geoip"):
        self.geoip_dir = geoip_dir
        self.db_conn = None
        self.csv_data = None
        self.ip_ranges = []
        self.initialized = False
        
        # Supported database files
        self.supported_files = {
            'dbip': ['dbip_geo.txt', 'dbip_index.zip', 'dbip.db'],
            'maxmind': ['GeoLite2-City.mmdb', 'GeoLite2-Country.mmdb'],
            'ip2location': ['IP2LOCATION-LITE-DB.BIN', 'IP2LOCATION-LITE-DB.CSV']
        }
        
        self.detect_and_load()
    
    def detect_and_load(self):
        """Detect and load available GeoIP databases"""
        logger.info(f"Scanning {self.geoip_dir} for GeoIP databases...")
        
        # List files in geoip directory
        try:
            files = os.listdir(self.geoip_dir)
            logger.info(f"Found files: {files}")
        except FileNotFoundError:
            logger.warning(f"GeoIP directory {self.geoip_dir} not found")
            return
        
        # Try to load each supported format
        for file in files:
            file_path = os.path.join(self.geoip_dir, file)
            
            # DBIP TXT format
            if file == 'dbip_geo.txt':
                logger.info("Loading DBIP TXT format...")
                if self.load_dbip_txt(file_path):
                    self.initialized = True
                    logger.info("DBIP TXT loaded successfully")
                    break
            
            # DBIP SQLite format
            elif file.endswith('.db') and 'dbip' in file.lower():
                logger.info("Loading DBIP SQLite database...")
                if self.load_dbip_sqlite(file_path):
                    self.initialized = True
                    logger.info("DBIP SQLite loaded successfully")
                    break
            
            # MaxMind MMDB format
            elif file.endswith('.mmdb'):
                logger.info("Loading MaxMind MMDB format...")
                if self.load_maxmind_mmdb(file_path):
                    self.initialized = True
                    logger.info("MaxMind MMDB loaded successfully")
                    break
            
            # IP2Location BIN format
            elif file.endswith('.BIN') and 'ip2location' in file.lower():
                logger.info("Loading IP2Location BIN format...")
                if self.load_ip2location_bin(file_path):
                    self.initialized = True
                    logger.info("IP2Location BIN loaded successfully")
                    break
        
        if not self.initialized:
            logger.warning("No supported GeoIP database found")
        else:
            logger.info(f"GeoIP database initialized with {len(self.ip_ranges) if self.ip_ranges else 'unknown'} IP ranges")
    
    def load_dbip_txt(self, file_path: str) -> bool:
        """Load DBIP TXT format"""
        try:
            logger.info(f"Reading DBIP TXT file: {file_path}")
            
            # Parse the CSV-like format
            self.csv_data = []
            ip_ranges = []
            
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f, delimiter=',', quotechar='"')
                
                for i, row in enumerate(reader):
                    if len(row) >= 8:
                        try:
                            # Parse IP range
                            start_ip = row[0]
                            end_ip = row[1]
                            
                            # Parse location data
                            country = row[2] if row[2] else None
                            region = row[3] if len(row) > 3 and row[3] else None
                            city = row[4] if len(row) > 4 and row[4] else None
                            latitude = float(row[5]) if len(row) > 5 and row[5] else None
                            longitude = float(row[6]) if len(row) > 6 and row[6] else None
                            isp = row[7] if len(row) > 7 and row[7] else None
                            
                            # Create IP range entry
                            ip_range = {
                                'start': start_ip,
                                'end': end_ip,
                                'start_int': self.ip_to_int(start_ip),
                                'end_int': self.ip_to_int(end_ip),
                                'location': {
                                    'country': country,
                                    'region': region,
                                    'city': city,
                                    'latitude': latitude,
                                    'longitude': longitude,
                                    'isp': isp
                                }
                            }
                            
                            ip_ranges.append(ip_range)
                            
                            # Store raw data for quick lookup
                            self.csv_data.append(row)
                            
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Error parsing row {i}: {e}")
                            continue
            
            self.ip_ranges = sorted(ip_ranges, key=lambda x: x['start_int'])
            logger.info(f"Loaded {len(ip_ranges)} IP ranges from DBIP TXT")
            return True
            
        except Exception as e:
            logger.error(f"Error loading DBIP TXT: {e}")
            return False
    
    def load_dbip_sqlite(self, db_path: str) -> bool:
        """Load DBIP SQLite database"""
        try:
            self.db_conn = sqlite3.connect(db_path)
            cursor = self.db_conn.cursor()
            
            # Check if it's a DBIP database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            table_names = [t[0] for t in tables]
            
            if 'ip_ranges' in table_names:
                # DBIP format
                cursor.execute("SELECT COUNT(*) FROM ip_ranges")
                count = cursor.fetchone()[0]
                logger.info(f"Found {count} IP ranges in DBIP database")
                return True
            else:
                logger.warning("SQLite database doesn't contain expected tables")
                return False
                
        except Exception as e:
            logger.error(f"Error loading DBIP SQLite: {e}")
            return False
    
    def load_maxmind_mmdb(self, file_path: str) -> bool:
        """Load MaxMind MMDB format"""
        try:
            import geoip2.database
            self.maxmind_reader = geoip2.database.Reader(file_path)
            logger.info("MaxMind MMDB reader initialized")
            return True
        except ImportError:
            logger.warning("geoip2 package not installed")
            return False
        except Exception as e:
            logger.error(f"Error loading MaxMind MMDB: {e}")
            return False
    
    def load_ip2location_bin(self, file_path: str) -> bool:
        """Load IP2Location BIN format"""
        try:
            import ip2location
            self.ip2location_db = ip2location.IP2Location(file_path)
            logger.info("IP2Location BIN database initialized")
            return True
        except ImportError:
            logger.warning("ip2location package not installed")
            return False
        except Exception as e:
            logger.error(f"Error loading IP2Location BIN: {e}")
            return False
    
    def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location for IP address using available database"""
        if not self.initialized:
            return None
        
        # Skip local addresses
        if self.is_local_ip(ip_address):
            return None
        
        try:
            # Try DBIP TXT format first
            if self.csv_data:
                location = self.lookup_dbip_txt(ip_address)
                if location:
                    return location
            
            # Try SQLite database
            if self.db_conn:
                location = self.lookup_dbip_sqlite(ip_address)
                if location:
                    return location
            
            # Try MaxMind
            if hasattr(self, 'maxmind_reader'):
                location = self.lookup_maxmind(ip_address)
                if location:
                    return location
            
            # Try IP2Location
            if hasattr(self, 'ip2location_db'):
                location = self.lookup_ip2location(ip_address)
                if location:
                    return location
            
            return None
            
        except Exception as e:
            logger.error(f"Error looking up IP {ip_address}: {e}")
            return None
    
    def lookup_dbip_txt(self, ip_address: str) -> Optional[GeoLocation]:
        """Lookup IP in DBIP TXT format"""
        if not self.ip_ranges:
            return None
        
        ip_int = self.ip_to_int(ip_address)
        
        # Binary search through sorted IP ranges
        low, high = 0, len(self.ip_ranges) - 1
        
        while low <= high:
            mid = (low + high) // 2
            ip_range = self.ip_ranges[mid]
            
            if ip_int < ip_range['start_int']:
                high = mid - 1
            elif ip_int > ip_range['end_int']:
                low = mid + 1
            else:
                # IP found in range
                loc_data = ip_range['location']
                return GeoLocation(
                    country=loc_data.get('country'),
                    region=loc_data.get('region'),
                    city=loc_data.get('city'),
                    latitude=loc_data.get('latitude'),
                    longitude=loc_data.get('longitude'),
                    isp=loc_data.get('isp')
                )
        
        return None
    
    def lookup_dbip_sqlite(self, ip_address: str) -> Optional[GeoLocation]:
        """Lookup IP in DBIP SQLite database"""
        try:
            ip_int = self.ip_to_int(ip_address)
            cursor = self.db_conn.cursor()
            
            # Query the database
            cursor.execute("""
                SELECT country, region, city, latitude, longitude, isp
                FROM ip_ranges
                WHERE start_ip_int <= ? AND end_ip_int >= ?
                LIMIT 1
            """, (ip_int, ip_int))
            
            result = cursor.fetchone()
            if result:
                return GeoLocation(
                    country=result[0],
                    region=result[1],
                    city=result[2],
                    latitude=result[3],
                    longitude=result[4],
                    isp=result[5]
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error querying SQLite: {e}")
            return None
    
    def lookup_maxmind(self, ip_address: str) -> Optional[GeoLocation]:
        """Lookup IP in MaxMind database"""
        try:
            response = self.maxmind_reader.city(ip_address)
            
            return GeoLocation(
                country=response.country.name,
                country_code=response.country.iso_code,
                region=response.subdivisions.most_specific.name if response.subdivisions else None,
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                timezone=response.location.time_zone,
                accuracy_radius=response.location.accuracy_radius
            )
        except Exception:
            return None
    
    def lookup_ip2location(self, ip_address: str) -> Optional[GeoLocation]:
        """Lookup IP in IP2Location database"""
        try:
            result = self.ip2location_db.get_all(ip_address)
            
            return GeoLocation(
                country=result.country_long,
                country_code=result.country_short,
                region=result.region,
                city=result.city,
                latitude=result.latitude,
                longitude=result.longitude,
                isp=result.isp,
                timezone=result.timezone
            )
        except Exception:
            return None
    
    def ip_to_int(self, ip_address: str) -> int:
        """Convert IP address to integer"""
        try:
            return int(ipaddress.IPv4Address(ip_address))
        except ipaddress.AddressValueError:
            try:
                return int(ipaddress.IPv6Address(ip_address))
            except:
                return 0
    
    def is_local_ip(self, ip_address: str) -> bool:
        """Check if IP is local/private"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {
            "initialized": self.initialized,
            "format": "unknown",
            "ip_ranges": 0,
            "supported_formats": list(self.supported_files.keys())
        }
        
        if self.csv_data:
            stats.update({
                "format": "DBIP TXT",
                "ip_ranges": len(self.ip_ranges) if self.ip_ranges else len(self.csv_data)
            })
        elif self.db_conn:
            stats["format"] = "DBIP SQLite"
        elif hasattr(self, 'maxmind_reader'):
            stats["format"] = "MaxMind MMDB"
        elif hasattr(self, 'ip2location_db'):
            stats["format"] = "IP2Location BIN"
        
        return stats
    
    def close(self):
        """Close database connections"""
        if self.db_conn:
            self.db_conn.close()
        if hasattr(self, 'maxmind_reader'):
            self.maxmind_reader.close()
        if hasattr(self, 'ip2location_db'):
            del self.ip2location_db
