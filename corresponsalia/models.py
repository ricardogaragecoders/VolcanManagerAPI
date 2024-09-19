from django.db import models

from common.models import BaseModelExtra
from corresponsalia.managers import CorresponsaliaManager


class Corresponsalia(BaseModelExtra):
    country = models.CharField(max_length=50, default='', null=True, blank=True)
    city = models.CharField(max_length=50, default='', null=True, blank=True)
    branch = models.CharField(max_length=50, default='', null=True, blank=True)
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING,
                                related_name='corresponsalias', null=True, blank=True)
    user_paycard = models.CharField(max_length=50, default='', null=True, blank=True)
    authorization = models.CharField(max_length=50, default='', null=True, blank=True)
    params = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)

    objects = CorresponsaliaManager()

    def __str__(self):
        if self.company:
            return '{0} ({1})'.format(self.branch, self.company.name).strip()
        else:
            return '{0}'.format(self.branch).strip()

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(Corresponsalia, self).save(*args, **kwargs)

    class Meta:
        ordering = ["country", "city", "branch"]

