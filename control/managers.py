from django.db import models
from django.db.models import Value
from django.db.models.functions import Concat


class OperatorManager(models.Manager):
    """
        Builds a default :class:`QuerySet` for the :class:`Operator`s
    """

    def get_queryset(self):
        return self.all_objects().filter(is_deleted=False)

    def all_objects(self):
        return super(OperatorManager, self).get_queryset().annotate(
            operator_name=Concat('profile__first_name',
                                 Value(' '), 'profile__last_name',
                                 Value(' '), 'profile__second_last_name',)
        ).select_related(
            'profile',
            'company'
        )