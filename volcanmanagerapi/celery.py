import os
from celery import Celery
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'volcanmanagerapi.settings')
# BROKER_URL = settings.BROKER_URL

app = Celery('volcanmanagerapi')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# celery -A volcanmanagerapi worker -l INFO
# app.conf.broker_url = BROKER_URL
