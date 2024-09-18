from django.db import models

from common.models import BaseModelExtra
from django.utils.translation import gettext_lazy as _

from volcanmanagerapi import settings


# Create your models here.

def report_directory_path(instance, filename):
    return 'report/{0}/{1}'.format(instance.id, filename)


class ReportType(models.TextChoices):
    RT_LOGS = 'logs', _('Logs')


class Report(BaseModelExtra):
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING,
                                related_name='reports', null=True, blank=True)
    report_type = models.CharField(max_length=50, choices=ReportType.choices, default=ReportType.RT_LOGS)
    initial_date = models.DateTimeField(blank=True, null=True)
    final_date = models.DateTimeField(blank=True, null=True)
    time_zone = models.CharField(max_length=50, default=settings.DEFAULT_TIMEZONE)
    report = models.FileField(upload_to=report_directory_path, blank=True, null=True)
    params = models.JSONField(default=dict)
    is_processed = models.BooleanField(default=False)
    created_by = models.ForeignKey('users.Profile', on_delete=models.DO_NOTHING, blank=True, null=True)
    is_active = models.BooleanField(default=True)
