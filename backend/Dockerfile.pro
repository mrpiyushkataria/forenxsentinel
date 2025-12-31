FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.pro.txt .
RUN pip install --no-cache-dir -r requirements.pro.txt

# Install GeoIP database
RUN mkdir -p /app/geoip && \
    curl -L https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb \
    -o /app/geoip/GeoLite2-City.mmdb

# Copy application
COPY . .

# Create directories
RUN mkdir -p /app/uploads /app/logs

# Set permissions
RUN chmod +x /app/start.sh

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
