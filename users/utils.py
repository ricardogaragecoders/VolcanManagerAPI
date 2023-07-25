from datetime import timedelta
from typing import Union

from django.conf import settings
from django.contrib.auth import user_logged_out
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken as JwtBlacklistedToken

from common.middleware import get_request
from common.utils import get_access_token_from_request, send_email, model_code_generator, get_data_email_general
from users.models import WhiteListedToken, ProfileVerification


async def send_email_verification(user=None, profile=None, email=None):
    message = None

    if not profile:
        profile = user.profile if user else None

    if not email:
        email = user.email

    if profile:
        if len(profile.code) == 0:
            profile = set_code_and_validity_code(profile)
        d = {
            'code': profile.code,
            'validity_code': profile.validity_code,
            'created': timezone.localtime(timezone.now())
        }
        emails = [email, ]
        message = await send_email(None, emails,
                                   u'Codigo de Verificación',
                                   'email/Email-VerificationCode.html', d)
        get_request().session['code'] = 'send_verification_code_email'
    return message


def set_code_and_validity_code(verification, security=False):
    if verification:
        now = timezone.localtime(timezone.now())
        verification.code = model_code_generator(ProfileVerification, 6, code='code',
                                                 option='num') if not security else model_code_generator(
            ProfileVerification, 32, code='code')
        verification.validity_code = now + (timedelta(minutes=5) if not security else timedelta(days=1))
        verification.is_verified = False
        verification.save()
    return verification


def get_role_and_data(user, data={}):
    from .serializers import ProfileSerializer
    data['role'] = user.profile.role
    profile = ProfileSerializer(user.profile).data
    data['data'] = {'profile': profile}
    return data


def send_verification_2factor(verification: ProfileVerification,
                              resp_msg: str = '', resp_data: Union[dict, list] = {}, resp_status: int = 200):
    verification = set_code_and_validity_code(
        verification, verification.type_verification == ProfileVerification.VERIFICATION_EMAIL)
    profile = verification.profile

    import jwt
    from django.utils.http import urlencode
    token = jwt.encode({
        "code": verification.code,
        "email": verification.data_verification,
    }, settings.SECRET_KEY, algorithm="HS256")

    d = get_data_email_general()

    if verification.type_verification == ProfileVerification.VERIFICATION_EMAIL:
        header_text = u'Verificación de email'
        url_text = '{0}/#/auth/verification-code/?{1}'.format(
            settings.URL_FRONTEND, urlencode({'token': token}))
        message_text = 'Código de verificación de email'
        button_text = 'Validar email'
        response_code = 'verification_email'
    elif verification.type_verification == ProfileVerification.VERIFICATION_2FACTOR:
        header_text = u'Código de verificación'
        url_text = ''
        message_text = 'Por medio de este mensaje, le hacemos llegar el código para accesar a la plataforma.'
        button_text = ''
        response_code = 'verification_2factor'

    d.update({
        "headerText": header_text,
        "subheaderText": "",
        "titleText": f"¡Hola, {profile.get_full_name()}!",
        "messageText": message_text,
        "urlText": url_text,
        "code": verification.code,
        'validityCode': timezone.localtime(verification.validity_code).strftime("%Y-%m-%d %H:%M:%S"),
        "buttonTitleText": button_text,
    })
    try:
        sending_response = send_email(None, [verification.data_verification, ],
                                      header_text,
                                      'email/Email-VerificationCode.html', {'data': d})
        if sending_response and verification and verification.validity_code:
            resp_data['send_email'] = True
            resp_data['validity_code'] = verification.validity_code.isoformat()
            resp_data['code'] = response_code
            if settings.DEBUG:
                resp_data['push_code'] = verification.code
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.exception(e)
        resp_msg = "Error to send code"

    return resp_msg, resp_data, resp_status


def send_recover_password(verification: ProfileVerification, security: bool = False,
                          resp_msg: str = '', resp_data: Union[dict, list] = {}, resp_status: int = 200):
    verification = set_code_and_validity_code(verification, security)
    profile = verification.profile

    from django.utils.http import urlencode
    import jwt
    token = jwt.encode({
        "code": verification.code,
        "email": verification.data_verification,
    }, settings.SECRET_KEY, algorithm="HS256")

    d = get_data_email_general()

    header_text = u'Recuperar contraseña'
    url_text = '{0}/#/auth/change-password/?{1}'.format(settings.URL_FRONTEND, urlencode({'token': token}))
    button_text = u'Recuperar contraseña'
    message_text = u'Este correo electrónico ha sido enviado porque se ha recibido una solicitud ' \
                   u'para realizar un proceso de recuperación de contraseña. ' \
                   u'Si no lo ha hecho, ignore este correo electrónico.'

    d.update({
        "headerText": header_text,
        "subheaderText": "",
        "titleText": f"¡Hola, {profile.get_full_name()}!",
        "messageText": message_text,
        "urlText": url_text,
        "code": verification.code if len(verification.code) <= 10 else '',
        'validityCode': timezone.localtime(verification.validity_code).strftime("%Y-%m-%d %H:%M:%S"),
        "buttonTitleText": button_text
    })
    try:
        sending_response = send_email(None, [verification.data_verification, ],
                                      header_text,
                                      'email/Email-VerificationCode.html', {'data': d})
        if sending_response and verification and verification.validity_code:
            resp_data['validity_code'] = verification.validity_code.isoformat()
            resp_data['code'] = 'recover_password_email'
            if settings.DEBUG:
                resp_data['push_code'] = verification.code
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.exception(e)
        resp_msg = "Error to send code"
    return resp_msg, resp_data, resp_status


def logout_users_process(request=None, profile=None):
    response_message = ''
    response_status = 201
    is_logout = True
    if request:
        profile = request.user.profile

    if is_logout:
        if request:
            token = get_access_token_from_request(request)
            whitelists = None
            item = None

            if WhiteListedToken.objects.filter(user=profile.user).exists():
                if WhiteListedToken.objects.filter(user=profile.user, token=token).exists():
                    item = WhiteListedToken.objects.get(user=profile.user, token=token)
                    if item:
                        whitelists = WhiteListedToken.objects.filter(device_token=item.device_token)
                else:
                    whitelists = WhiteListedToken.objects.filter(user=profile.user)
        else:
            whitelists = None

            if WhiteListedToken.objects.filter(user=profile.user).exists():
                whitelists = WhiteListedToken.objects.filter(user=profile.user)

        if whitelists and whitelists.count():
            for whitelisted in whitelists:
                if whitelisted.refresh_token and OutstandingToken.objects.filter(
                        token=whitelisted.refresh_token).exists():
                    token = OutstandingToken.objects.get(token=whitelisted.refresh_token)
                    JwtBlacklistedToken.objects.create(token=token)

            whitelists.delete()
        from django.core.cache import cache
        key_cache = 'profile:{}'.format(profile.id)
        if key_cache in cache:
            cache.delete(key_cache)
        user_logged_out.send(sender=profile.user.__class__, request=request, user=profile.user)
        response_message = _('Existoso.')
    else:
        response_status = 400

    return response_message, {}, response_status
