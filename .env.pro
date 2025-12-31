# Application
DEBUG=False
ENVIRONMENT=production
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1,your-domain.com

# Database
DATABASE_URL=postgresql://postgres:password@db:5432/forensics
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_CACHE_TTL=3600

# GeoIP
GEOIP_DB_PATH=/app/geoip/GeoLite2-City.mmdb

# Security
CORS_ORIGINS=["http://localhost:8080", "https://your-domain.com"]
CSRF_TRUSTED_ORIGINS=["https://your-domain.com"]
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/app/logs/app.log

# File Uploads
MAX_UPLOAD_SIZE=524288000  # 500MB
UPLOAD_DIR=/app/uploads
ALLOWED_EXTENSIONS=.log,.txt,.gz,.zip

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60

# Monitoring
ENABLE_METRICS=True
METRICS_PORT=9100

# Email (for alerts)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-password
ALERT_EMAIL=admin@your-domain.com
