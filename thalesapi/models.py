from django.db import models
import uuid
from django.utils.translation import gettext as _
from common.models import ModelDiffMixin, BaseModelWithDeleted


class CardType(models.TextChoices):
    CT_PREPAID = 'prepaid', _('Prepago')
    CT_CREDIT = 'credit', _('Credito')
    CT_OTHER = 'other', _('Otro')


class CardDetail(BaseModelWithDeleted, ModelDiffMixin):
    """
        Model CardId and CustomerId
    """
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
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

    card_bin = models.CharField(
        max_length=8,
        verbose_name=_('Card BIN'),
        help_text=_("Thales Card BIN"),
        null=True,
        blank=True
    )

    card_type = models.CharField(max_length=10, choices=CardType.choices, default=CardType.CT_PREPAID)

    def __str__(self):
        return f'{self.consumer_id}: {self.card_id}'

    class Meta:
        ordering = ('-created_at',)
