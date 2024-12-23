import logging
import uuid

import pytz
from bson.codec_options import CodecOptions
from django.db import models
from django.forms import model_to_dict
from django.utils.text import slugify

from common.managers import SoftDeletionManager
from volcanmanagerapi import settings

logger = logging.getLogger(__name__)


class NameStrMixin:
    def __str__(self):
        return self.name


class BaseModel(models.Model, NameStrMixin):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.ForeignKey('common.Status', on_delete=models.DO_NOTHING, blank=True, null=True)

    class Meta:
        abstract = True


class BaseModelExtra(models.Model, NameStrMixin):
    """
        Abstract base model that provides common fields for all models.

        Fields:
        - id: Unique identifier for the model (UUIDField).
        - created_at: Date and time when the model was created (DateTimeField).
        - modified_at: Date and time when the model was last modified (DateTimeField).
        - is_deleted: Boolean indicating whether the model is deleted or not (BooleanField).
    """
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = SoftDeletionManager()

    all_objects = models.Manager()

    class Meta:
        abstract = True


class BaseModelWithoutStatus(models.Model, NameStrMixin):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class BaseModelWithDeleted(models.Model, NameStrMixin):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True, db_index=True)

    class Meta:
        abstract = True


class SlugFieldMixin(models.Model, NameStrMixin):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super(SlugFieldMixin, self).save(*args, **kwargs)


class Status(SlugFieldMixin):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=45)
    slug = models.SlugField(unique=True, max_length=45)


class ModelDiffMixin(object):
    """
    A model mixin that tracks model fields' values and provide some useful api
    to know what fields have been changed.
    """

    def __init__(self, *args, **kwargs):
        super(ModelDiffMixin, self).__init__(*args, **kwargs)
        self.__initial = self._dict

    @property
    def diff(self):
        d1 = self.__initial
        d2 = self._dict
        diffs = [(k, (v, d2[k])) for k, v in d1.items() if v != d2[k]]
        return dict(diffs)

    @property
    def has_changed(self):
        return bool(self.diff)

    @property
    def changed_fields(self):
        return self.diff.keys()

    def get_field_diff(self, field_name):
        """
        Returns a diff for field if it's changed and None otherwise.
        """
        return self.diff.get(field_name, None)

    def save(self, *args, **kwargs):
        """
        Saves model and set initial state.
        """
        super(ModelDiffMixin, self).save(*args, **kwargs)
        self.__initial = self._dict

    @property
    def _dict(self):
        return model_to_dict(self, fields=[field.name for field in self._meta.fields])


# class MonitorSystem(models.Model):
#     endpoint = models.CharField(max_length=150, blank=True, null=True)
#     action = models.CharField(max_length=50, blank=True, null=True)
#     description = models.CharField(max_length=250, blank=True, null=True)
#     content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, blank=True, null=True)
#     object_id = models.PositiveIntegerField()
#     content_object = GenericForeignKey('content_type', 'object_id')
#     created_by = models.ForeignKey(User, on_delete=models.DO_NOTHING, blank=True, null=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#
#     def __str__(self):
#         return 'Action: {} Endpoint: {} Description: {}'.format(self.action, self.endpoint, self.description)

class MongoConnection:
    def __init__(self):
        self.uri = settings.MONGODB_URI
        self.db_name = settings.MONGODB_DATABASE_NAME
        self.collection = None

    def __enter__(self):
        from pymongo import MongoClient
        time_zone = pytz.timezone('America/Mexico_City')
        codec_options = CodecOptions(tz_aware=True, tzinfo=time_zone)
        self.client = MongoClient(self.uri)
        self.db = self.client.get_database(self.db_name, codec_options=codec_options)
        return self.db

    def get_collection(self, name):
       return self.db[name]

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()


class MonitorCollection:
    def __init__(self):
        self.collection_name = 'monitor'

    def insert_one(self, data):
        with MongoConnection() as db:
            collection = db[self.collection_name]
            result = collection.insert_one(data)
            return result.inserted_id

    def find(self, filters, sort='updated_at', direction=-1, per_page=20, page=0):
        with MongoConnection() as db:
            collection = db[self.collection_name]
            documents = collection.find(filters).limit(per_page).skip(per_page * page).sort(sort, direction)
            return list(documents)

    def find_all(self, filters, sort='updated_at', direction=-1):
        with MongoConnection() as db:
            collection = db[self.collection_name]
            session = None
            try:
                # Inicia la sesión explícita
                session = db.client.start_session()
                # Ejecuta la consulta con no_cursor_timeout dentro de la sesión
                data = collection.find(filters, no_cursor_timeout=True, session=session) \
                                    .sort(sort, direction).batch_size(1000)
                for item in data:
                    yield item  # Puedes cambiar el procesamiento según sea necesario

            except Exception as e:
                logger.error(e.args.__str__())
            finally:
                # Asegúrate de cerrar la sesión
                if session:
                    session.end_session()


    def find_one(self, filters):
        with MongoConnection() as db:
            collection = db[self.collection_name]
            return collection.find_one(filters)

    def count_all(self, filters):
        with MongoConnection() as db:
            collection = db[self.collection_name]
            return collection.count_documents(filters)

    def update_one(self, filters, data):
        with MongoConnection() as db:
            collection = db[self.collection_name]
            if collection.count_documents(filters):
                return collection.update_one(filters, data)
            return False

