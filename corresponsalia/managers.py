from django.db import models
from django.db.models import Value
from django.db.models.functions import Concat


class CorresponsaliaManager(models.Manager):
    """
        Builds a default :class:`QuerySet` for the :class:`Corresponsalia`s
    """

    def get_queryset(self):
        return self.all_objects().filter(is_deleted=False)

    def all_objects(self):
        return super(CorresponsaliaManager, self).get_queryset().select_related(
            'company'
        )


class TransaccionCorresponsaliaManager(models.Manager):
    """
        Builds a default :class:`QuerySet` for the :class:`TransaccionCorresponsalia`s
    """

    def get_queryset(self):
        return self.all_objects().filter(is_active=True)

    def all_objects(self):
        return super(TransaccionCorresponsaliaManager, self).get_queryset().select_related(
            'corresponsalia',
            'card_bin_config',
            'currency'
        )