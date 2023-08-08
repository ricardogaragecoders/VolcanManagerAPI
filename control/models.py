from django.db import models

from common.models import ModelDiffMixin


class Webhook(ModelDiffMixin, models.Model):
    emisor = models.CharField(max_length=100)
    url_webhook = models.URLField(blank=True, null=True)
    key_webhook = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.active = True
        super(Webhook, self).save(*args, **kwargs)

    def __str__(self):
        return self.emisor
