#!/bin/bash

# Wait for database to be ready
echo "Waiting for database..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "Database is ready!"

# Wait for Redis
echo "Waiting for Redis..."
while ! nc -z redis 6379; do
  sleep 0.1
done
echo "Redis is ready!"

# Run database migrations
echo "Running database migrations..."
python -m alembic upgrade head

# Start the application
echo "Starting ForenX-NGINX Sentinel..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4 --log-level info
