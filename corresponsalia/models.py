from django.db import models

from common.models import BaseModelExtra, BaseModel, MonitorCollection
from corresponsalia.managers import CorresponsaliaManager, TransaccionCorresponsaliaManager
from django.utils.translation import gettext as _

class Corresponsalia(BaseModelExtra):
    description = models.CharField(max_length=50, default='', null=True, blank=True)
    country = models.CharField(max_length=50, default='', null=True, blank=True)
    city = models.CharField(max_length=50, default='', null=True, blank=True)
    branch = models.CharField(max_length=50, default='', null=True, blank=True)
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING,
                                related_name='corresponsalias', null=True, blank=True)
    user_paycard = models.CharField(max_length=50, default='', null=True, blank=True)
    pass_paycard = models.CharField(max_length=50, default='', null=True, blank=True)
    access_token_paycard = models.TextField(blank=True, null=True)
    params = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)

    objects = CorresponsaliaManager()

    def __str__(self):
        if self.company:
            return '{0} ({1})'.format(self.branch, self.company.name).strip()
        else:
            return '{0}'.format(self.branch).strip()

    @staticmethod
    def generate_credentials(username: str, password: str):
        import base64
        userpass = f'{username}:{password}'
        return base64.b64encode(userpass.encode()).decode()


    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(Corresponsalia, self).save(*args, **kwargs)

    class Meta:
        ordering = ["country", "city", "branch"]


class TransaccionCorresponsaliaStatus(models.TextChoices):
    TCS_ACTIVE = 'active', _('Activo')
    TCS_PROCESSED = 'processed', _('Procesado')
    TCS_REJECTED = 'rejected', _('Rechazado')
    TCS_ERROR = 'error', _('Error')
    TCS_RETURNED = 'returned', _('Reverso')
    TCS_ERROR_RETURNED = 'error_returned', _('Error en reverso')


class TransaccionCorresponsalia(BaseModel):
    corresponsalia = models.ForeignKey('corresponsalia.Corresponsalia', on_delete=models.DO_NOTHING,
                                        related_name='transactions', null=True, blank=True)
    card_number = models.CharField(max_length=16)
    movement_code = models.CharField(max_length=4, null=True, blank=True)
    movement_code_reverse = models.CharField(max_length=4, null=True, blank=True)
    amount = models.FloatField(default=0.0)
    reference = models.CharField(max_length=50, null=True, blank=True)
    card_bin_config = models.ForeignKey('thalesapi.CardBinConfig', on_delete=models.DO_NOTHING,
                                       related_name='transactions', null=True, blank=True)
    currency = models.ForeignKey('control.Currency', on_delete=models.DO_NOTHING,
                                        related_name='transactions', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    authorization = models.CharField(max_length=150, null=True, blank=True)
    status = models.CharField(max_length=20, choices=TransaccionCorresponsaliaStatus.choices,
                              default=TransaccionCorresponsaliaStatus.TCS_ACTIVE)

    objects = TransaccionCorresponsaliaManager()

    def __str__(self):
        return '{0}: {1} ({2})'.format(self.card_number, self.amount, self.currency).strip()

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(TransaccionCorresponsalia, self).save(*args, **kwargs)

    class Meta:
        ordering = ["created_at", "card_number", "currency"]


class TransaccionCorresponsaliaCollection(MonitorCollection):

    def __init__(self):
        super(TransaccionCorresponsaliaCollection, self).__init__()
        self.get_collection('transaccion_corresponsalia')