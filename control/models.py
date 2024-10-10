from email.policy import default

from django.db import models

from common.models import BaseModelExtra, BaseModel
from control.managers import OperatorManager


class Company(BaseModelExtra):
    name = models.CharField(max_length=40)
    volcan_issuer_id = models.CharField(max_length=3, blank=True, null=True)
    thales_issuer_id = models.CharField(max_length=30, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(Company, self).save(*args, **kwargs)

    class Meta:
        ordering = ["name"]


class Operator(BaseModelExtra):
    profile = models.OneToOneField('users.Profile', on_delete=models.CASCADE, null=True, blank=True)
    company = models.ForeignKey('control.Company', on_delete=models.DO_NOTHING, related_name='operators',
                                null=True, blank=True)
    is_active = models.BooleanField(default=True)

    objects = OperatorManager()

    def __str__(self):
        if self.company:
            return '{0} ({1})'.format(self.get_full_name(), self.company.name).strip()
        else:
            return '{0}'.format(self.get_full_name()).strip()

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(Operator, self).save(*args, **kwargs)

    def get_full_name(self):
        return self.profile.get_full_name()

    class Meta:
        ordering = ["profile__first_name", "profile__last_name"]


class Currency(BaseModel):
    name  = models.CharField(max_length=45)
    abr_code = models.CharField(max_length=3)
    number_code = models.CharField(max_length=3)
    decimals = models.SmallIntegerField(default=2)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.is_active = True
        super(Currency, self).save(*args, **kwargs)

    class Meta:
        ordering = ["abr_code"]