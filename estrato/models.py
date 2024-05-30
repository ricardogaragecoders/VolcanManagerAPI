from django.db import models

from common.models import BaseModelExtra


# Create your models here.
class EstratoApiKey(BaseModelExtra):
    # id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING,
                                related_name='api_keys', null=True, blank=True)
    volcan_issuer_id = models.CharField(max_length=100)
    url_estrato = models.URLField(blank=True, null=True)
    api_key = models.TextField(blank=True, null=True)
    header_request = models.CharField(max_length=20, default='X-Api-Key')
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(EstratoApiKey, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.volcan_issuer_id}'
