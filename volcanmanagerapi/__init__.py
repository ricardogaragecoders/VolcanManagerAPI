from .celery import app as celery_app
from django.conf import settings
import pymongo
DB_MONGO_CLIENT = pymongo.MongoClient(settings.MONGO_DB['volcanmanagerapidb']['URL'], connect=False)
__all__ = ['celery_app']