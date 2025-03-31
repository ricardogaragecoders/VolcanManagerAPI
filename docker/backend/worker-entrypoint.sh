#!/bin/sh

until cd /app
do
    echo "Waiting for server volume..."
    sleep 2
done

# run a worker :)
echo "Starting Celery worker..."
celery -A volcanmanagerapi worker --loglevel=info
