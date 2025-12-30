import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Upload settings
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'.log', '.txt', '.gz'}

# Max file size (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# Log format detection
LOG_FORMATS = {
    'combined': r'(?P<ip>\S+) - - \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"',
    'main': r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+)',
    'extended': r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)" "(?P<host>.*?)"',
    'error': r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): \*(?P<cid>\d+) (?P<message>.+?), client: (?P<client>.+?), server: (?P<server>.+?), request: "(?P<request>.+?)", host: "(?P<host>.+?)"'
}
