import uuid
from django.db import models

from common.models import BaseModelExtra, MonitorCollection


class Webhook(BaseModelExtra):
    # id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING,
                                related_name='webhooks', null=True, blank=True)
    account_issuer = models.CharField(max_length=100)
    url_webhook = models.URLField(blank=True, null=True)
    key_webhook = models.TextField(blank=True, null=True)
    header_webhook = models.CharField(max_length=20, default='Authorization')
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(Webhook, self).save(*args, **kwargs)

    def __str__(self):
        return f'({self.account_issuer}) {self.url_webhook}'


class TransactionCollection(MonitorCollection):

    def __init__(self):
        super(TransactionCollection, self).__init__()
        self.collection_name = 'transactions'


class NotificationCollection(MonitorCollection):
    """
        Structure of a notification

            {
                "user": {
                    "id": "xxxx-xxxx-xxxx-xxx",
                    "name": "...."
                },
                "notification": {
                    ... // message's body
                },
                "notification_type": {
                    "type": "transaction" | "paycard" | "thales",
                    "mode": "normal" | "retry" | "resend",
                    "version": 1
                },
                "delivery": {
                    "delivered": true | false,
                    "delivery_date": ....,
                    "priority": 1..5,
                    "attemps": 1...3,
                },
                "webhook": {
                    "id": "xxxxx-xxxxx-xxxx-xxxxx",
                    "url": "....",
                    "headers": "...",
                },
                "response": {
                    "code": "....",
                    "body": "...."
                },
                "dates": {
                    "created_at": ....,
                    "updated_at": ....,
                    "deleted_at": ....
                }
            }

    """

    def __init__(self):
        super(NotificationCollection, self).__init__()
        self.collection_name = 'notifications'


class TransactionErrorCollection(MonitorCollection):

    def __init__(self):
        super(TransactionErrorCollection, self).__init__()
        self.collection_name = 'transactions_error'


class DeliveryErrorCollection(MonitorCollection):

    def __init__(self):
        super(DeliveryErrorCollection, self).__init__()
        self.collection_name = 'delivery_transactions_error'
