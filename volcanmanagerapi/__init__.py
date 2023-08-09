
from django.conf import settings
import pymongo
DB_MONGO_CLIENT = pymongo.MongoClient(settings.MONGO_DB['volcanmanagerapidb']['URL'], connect=False)
