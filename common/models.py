import logging
import uuid

from django.db import models
from django.forms import model_to_dict
from django.utils.text import slugify

from common.managers import SoftDeletionManager

logger = logging.getLogger(__name__)


class NameStrMixin:
    def __str__(self):
        return self.name


class BaseModel(models.Model, NameStrMixin):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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


class MongoConnection(object):
    def __init__(self):
        from volcanmanagerapi import DB_MONGO_CLIENT as client
        self.db = client['volcanmanagerapidb']
        self.collection = None

    def get_collection(self, name):
        self.collection = self.db[name]


class MonitorCollection(MongoConnection):

    def __init__(self):
        super(MonitorCollection, self).__init__()
        self.get_collection('monitor')

    def insert_one(self, data):
        return self.collection.insert_one(data)

    def find(self, filters, sort='updated_at', direction=-1, per_page=20, page=0):
        import pytz
        from bson.codec_options import CodecOptions
        time_zone = pytz.timezone('America/Mexico_City')
        try:
            collection = self.collection.with_options(codec_options=CodecOptions(tz_aware=True, tzinfo=time_zone))
            data = collection.find(filters).limit(per_page).skip(per_page * page).sort(sort, direction)
        except Exception as e:
            logger.error(e.args.__str__())
            data = {}
        return data

    def find_all(self, filters, sort='updated_at', direction=-1):
        import pytz
        from bson.codec_options import CodecOptions
        time_zone = pytz.timezone('America/Mexico_City')
        try:
            collection = self.collection.with_options(codec_options=CodecOptions(tz_aware=True, tzinfo=time_zone))
            data = collection.find(filters).sort(sort, direction)
        except Exception as e:
            logger.error(e.args.__str__())
            data = {}
        return data

    def find_one(self, filters):
        return self.collection.find_one(filters)

    def count_all(self, filters):
        from bson.codec_options import CodecOptions
        import pytz
        time_zone = pytz.timezone('America/Mexico_City')
        collection = self.collection.with_options(codec_options=CodecOptions(tz_aware=True, tzinfo=time_zone))
        return collection.count_documents(filters)

    def update_one(self, filters, data):
        if self.collection.count_documents(filters):
            return self.collection.update_one(filters, data)
        return False

