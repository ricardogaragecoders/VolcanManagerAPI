#!/bin/sh

until cd /app
  do
    echo "Waiting for server volume..."
    sleep 2
done

echo "Running migrations..."
python manage.py migrate --noinput

python manage.py collectstatic --noinput

echo "Starting Gunicorn..."
gunicorn -k uvicorn.workers.UvicornWorker volcanmanagerapi.asgi:application --bind 0.0.0.0:8000
