import uuid
from django.db import models

from common.models import BaseModelWithDeleted, MonitorCollection


class Webhook(BaseModelWithDeleted):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    account_issuer = models.CharField(max_length=100)
    url_webhook = models.URLField(blank=True, null=True)
    key_webhook = models.CharField(max_length=100, blank=True, null=True)
    active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.active = True
        super(Webhook, self).save(*args, **kwargs)

    def __str__(self):
        return f'({self.account_issuer}) {self.url_webhook}'


class TransactionCollection(MonitorCollection):

    def __init__(self):
        super(TransactionCollection, self).__init__()
        self.get_collection('transactions')


class TransactionErrorCollection(MonitorCollection):

    def __init__(self):
        super(TransactionErrorCollection, self).__init__()
        self.get_collection('transactions_error')
