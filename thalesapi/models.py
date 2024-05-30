from django.db import models
import uuid
from django.utils.translation import gettext as _
from common.models import ModelDiffMixin, BaseModelWithDeleted, MonitorCollection


class CardType(models.TextChoices):
    CT_PREPAID = 'prepaid', _('Prepago')
    CT_CREDIT = 'credit', _('Credito')
    CT_OTHER = 'other', _('Otro')


class Client(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    card_name = models.CharField(max_length=50, blank=True, null=True)
    consumer_id = models.CharField(max_length=45, blank=True, null=True)
    type_identification = models.CharField(max_length=2, blank=True, null=True)
    document_identification = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return f"User: {self.card_name} consumerId: {self.consumer_id}"


class CardDetail(BaseModelWithDeleted, ModelDiffMixin):
    """
        Model CardId and CustomerId
    """
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    client = models.ForeignKey(Client, on_delete=models.DO_NOTHING, blank=True, null=True, related_name='cards')
    issuer_id = models.CharField(
        max_length=10,
        verbose_name=_('Issuer ID'),
        help_text=_("Thales Issuer ID"),
        null=False,
        blank=False
    )

    card_id = models.CharField(
        max_length=48,
        verbose_name=_('Card ID'),
        help_text=_("Generated by AZ7"),
        null=False,
        blank=False
    )

    consumer_id = models.CharField(
        max_length=64,
        verbose_name=_('Consumer ID'),
        help_text=_("Generated by AZ7"),
        null=False,
        blank=False
    )

    account_id = models.CharField(
        max_length=64,
        verbose_name=_('Account ID'),
        help_text=_("Generated by AZ7"),
        null=True,
        blank=True
    )

    card_bin = models.CharField(
        max_length=8,
        verbose_name=_('Card BIN'),
        help_text=_("Thales Card BIN"),
        null=True,
        blank=True
    )

    card_type = models.CharField(
        max_length=10,
        choices=CardType.choices,
        verbose_name=_('Card Type'),
        help_text=_("Thales Card Type"),
        default=CardType.CT_PREPAID
    )
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING, related_name='cards',
                                null=True, blank=True)
    emisor = models.CharField(
        max_length=3,
        verbose_name=_('Volcan Emisor ID'),
        help_text=_("Volcan Emisor ID"),
        default='CMF',
        null=True,
        blank=True
    )

    def __str__(self):
        return f'{self.consumer_id}: {self.card_id}'

    class Meta:
        ordering = ('-created_at',)


class ISOCountry(models.Model):
    id = models.AutoField(primary_key=True)
    code = models.CharField(max_length=4)
    country_name = models.CharField(max_length=100)
    alfa2 = models.CharField(max_length=2)
    alfa3 = models.CharField(max_length=3)

    def __str__(self):
        return self.country_name

    class Meta:
        ordering = ('country_name',)


class CardBinConfig(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    card_bin = models.CharField(
        max_length=8,
        verbose_name=_('Card BIN'),
        help_text=_("Thales Card BIN"),
        unique=True,
        null=True,
        blank=True
    )
    issuer_id = models.CharField(
        max_length=10,
        verbose_name=_('Issuer ID'),
        help_text=_("Thales Issuer ID"),
        null=False,
        blank=False
    )
    card_type = models.CharField(
        max_length=10,
        choices=CardType.choices,
        verbose_name=_('Card Type'),
        help_text=_("Thales Card Type"),
        default=CardType.CT_PREPAID
    )
    card_product_id = models.CharField(
        max_length=100,
        verbose_name=_('Card Product ID'),
        help_text=_("Thales Card Product ID"),
        null=False,
        blank=False
    )
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING, related_name='card_bin_configs',
                                null=True, blank=True)
    emisor = models.CharField(
        max_length=3,
        verbose_name=_('Volcan Emisor ID'),
        help_text=_("Volcan Emisor ID"),
        default='CMF',
        null=False,
        blank=False
    )

    def __str__(self):
        return f"{self.card_type}: {self.card_bin} - {self.emisor}"

    class Meta:
        ordering = ('card_bin',)


class DeliverOtpCollection(MonitorCollection):

    def __init__(self):
        super(DeliverOtpCollection, self).__init__()
        self.get_collection('deliver_otp')