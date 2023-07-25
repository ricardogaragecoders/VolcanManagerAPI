import logging
import uuid

from django.contrib.auth import user_logged_in, user_logged_out, user_login_failed
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

# Create your models here.
from common.models import BaseModelWithDeleted, ModelDiffMixin, BaseModelWithoutStatus
from users.managers import ProfileManager


class Profile(ModelDiffMixin, BaseModelWithDeleted):
    CLIENT = 1
    OPERATOR = 2
    SUPERVISOR = 3
    ADMINISTRATOR = 4
    SUPERADMIN = 10
    ROLE_CHOICES = (
        (CLIENT, _('Cliente')),
        (OPERATOR, _('Operador')),
        (SUPERVISOR, _('Supervisor')),
        (ADMINISTRATOR, _('Administrador general')),
        (SUPERADMIN, _('Superadmin'))
    )
    id = models.AutoField(primary_key=True)
    unique_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=100, default='')
    last_name = models.CharField(max_length=140, default='')
    second_last_name = models.CharField(max_length=140, default='', blank=True)
    email = models.CharField(max_length=100, default='', blank=True)
    phone = models.CharField(max_length=10, blank=True, null=True)
    change_password = models.BooleanField(default=False)
    verification_phone = models.BooleanField(default=False)
    verification_email = models.BooleanField(default=False)
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=CLIENT, null=True, blank=True)

    objects = ProfileManager()

    def __str__(self):
        return self.get_full_name()

    def get_full_name(self):
        if len(self.first_name) > 0:
            return '{0} {1} {2}'.format(self.first_name, self.last_name, self.second_last_name).strip()
        else:
            return self.email

    def isClient(self, equal=False):
        if equal:
            return self.role == self.CLIENT
        else:
            return self.role >= self.CLIENT

    def IsOperator(self, equal=False):
        if equal:
            return self.role == self.OPERATOR
        else:
            return self.role >= self.OPERATOR

    def isAdminProgram(self, equal=False):
        if equal:
            return self.role == self.SUPERVISOR
        else:
            return self.role >= self.SUPERVISOR

    def isAdministrator(self, equal=False):
        if equal:
            return self.role == self.ADMINISTRATOR
        else:
            return self.role >= self.ADMINISTRATOR

    def isSuperadmin(self):
        return self.role == self.SUPERADMIN


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


class WhiteListedToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_token = models.TextField(verbose_name=_("Registration token"), blank=True, null=True)
    type_token = models.CharField(verbose_name=_("Type token"), max_length=20, blank=True, null=True)
    token = models.CharField(max_length=500, blank=True, null=True)
    refresh_token = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


class ProfileVerification(BaseModelWithoutStatus):
    VERIFICATION_PHONE = 1
    VERIFICATION_EMAIL = 2
    RECOVER_PASSWORD_PHONE = 3
    RECOVER_PASSWORD_EMAIL = 4
    CHANGE_PHONE = 5
    VERIFICATION_2FACTOR = 6
    AUTORIZATION_REDEMPTION = 7
    AUTORIZATION_TRANSFER = 8
    VERIFICATION_CHOICES = (
        (VERIFICATION_PHONE, _(u'Verificación de teléfono')),
        (VERIFICATION_EMAIL, _(u'Verificación de correo electrónico')),
        (RECOVER_PASSWORD_PHONE, _(u'Recuperar contraseña con teléfono')),
        (RECOVER_PASSWORD_EMAIL, _(u'Recuperar contraseña con correo electrónico')),
        (CHANGE_PHONE, _(u'Cambiar el numero teléfono')),
        (VERIFICATION_2FACTOR, _(u'Verificación doble factor de autentificación')),
        (AUTORIZATION_REDEMPTION, _(u'Autorización de redención')),
        (AUTORIZATION_TRANSFER, _(u'Autorización de transferencia de puntos')),
    )
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, blank=True, null=True)
    data_verification = models.CharField(max_length=150, blank=True, null=True)
    type_verification = models.SmallIntegerField(choices=VERIFICATION_CHOICES, default=VERIFICATION_PHONE)
    code = models.CharField(max_length=32, default='', blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    validity_code = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return 'Usuario: {0} Tipo: {1}'.format(self.profile.get_full_name(), self.get_type_verification_display())


@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):
    log = logging.getLogger('login_success')
    ip = request.META.get('REMOTE_ADDR')
    log.debug('login user: {user} via ip: {ip}'.format(
        user=user,
        ip=ip
    ))


@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    log = logging.getLogger('logout_success')
    ip = request.META.get('REMOTE_ADDR')
    log.debug('logout user: {user} via ip: {ip}'.format(
        user=user,
        ip=ip
    ))


@receiver(user_login_failed)
def user_login_failed_callback(sender, credentials, **kwargs):
    from common.middleware import get_request
    log = logging.getLogger('login')
    request = get_request()
    ip = request.META.get('REMOTE_ADDR')
    log.warning('{ip}: login failed for: {credentials}'.format(
        ip=ip,
        credentials=credentials,
    ))
