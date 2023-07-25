from django.db import models
from django.forms import model_to_dict
from django.utils.text import slugify


class NameStrMixin:
    def __str__(self):
        return self.name


class BaseModel(models.Model, NameStrMixin):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.ForeignKey('common.Status', on_delete=models.DO_NOTHING, blank=True, null=True)

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


