import random
import string
from datetime import datetime, time
import threading

import jwt
import pytz
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler

from common.middleware import get_request


def get_letter_from_number(number):
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if number > len(letters):
        letter = 'A'
        letter += get_letter_from_number(number - len(letters))
        return letter
    else:
        return letters[number - 1]


def custom_exception_handler(exception, context):
    if isinstance(exception, APIException):
        headers = {}
        response_data = {}

        if getattr(exception, 'auth_header', None):
            headers['WWW-Authenticate'] = exception.auth_header

        if getattr(exception, 'wait', None):
            headers['Retry-After'] = '%d' % exception.wait

        data = exception.get_full_details()
        message = ''
        code = '00'

        if 'detail' in data:
            if 'code' in data['detail']:
                code = data['detail']['code']
            if 'message' in data['detail']:
                message = data['detail']['message']
        elif 'code' in data:
            code = data['code']
            if 'message' in data:
                message = data['message']

        if len(message) == 0:
            request = get_request()
            if request and request.session:
                if 'code' in request.session:
                    if isinstance(data, dict):
                        code = request.session['code']
                    del request.session['code']
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(k, str) and isinstance(v, list):
                        v = '%s' % (v[0] if not 'message' in v[0] else v[0]['message'])
                    if isinstance(k, str) and isinstance(v, str):
                        response_data['data'][k] = v

            if len(data) > 1:
                message = u"Error en la petición"
            else:
                key = list(data.keys())[0]
                # if key == 'non_field_errors':
                message = response_data['data'][key] if key in response_data['data'] else response_data['data']

        response_data['RSP_SUCCESS'] = False
        response_data['RSP_CODIGO'] = code
        response_data['RSP_DESCRIPCION'] = message

        # response_data['data']['code'] = code
        if 'data' in response_data:
            del response_data['data']

        if code == "parse_error":
            response_data['RSP_DESCRIPCION'] = 'Error en los valores recibidos'

        if code != "not_authenticated" and code != "token_not_valid":
            import logging
            logger = logging.getLogger(__name__)
            logger.exception({'RSP_CODIGO': code, 'RSP_DESCRIPCION': str(message)})

            return Response({k.lower(): v for k, v, in response_data.items()},
                            status=exception.status_code, headers=headers)
        else:
            return Response({k.lower(): v for k, v, in response_data.items()},
                            status=status.HTTP_401_UNAUTHORIZED, headers=headers)

    return exception_handler(exception, context)


def handler_exception_general(name, e):
    import logging
    logger = logging.getLogger(name)
    logger.exception(e)
    response_message = u"Error en applicación"
    response_status = 500
    return response_message, {'code': 'error_general'}, response_status


def handler_exception_404(name, lookup_field, pk, e):
    if lookup_field == 'unique_id' and not is_valid_uuid(pk):
        response_message = 'El valor {} no es valido'.format(pk)
        response_status = 404
    else:
        import logging
        logger = logging.getLogger(name)
        logger.exception(e)
        response_message = u"Registro no encontrado"
        response_status = 404
    return response_message, {'code': 'not_found'}, response_status


def get_response_data_errors(data):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, list):
                m = '' if k == 'non_field_errors' else f"{k.capitalize()}: "
                for v_i in v:
                    if len(m) == 0:
                        m += '%s ' % v_i
                    else:
                        m += '%s ' % v_i.lower()
                v = m
            if isinstance(k, str) and isinstance(v, str):
                if isinstance(data, dict):
                    data[k] = v
                else:
                    data[k] += '%s: %s' % (k, v)
    if len(data) > 0:
        key = list(data.keys())[0]
        message = data[key]
        if 'non_field_errors' in data:
            del data['non_field_errors']
    else:
        message = u"Error en la petición"
    return message, data, 422


def get_number_verification():
    s_number = str(random.random())
    return s_number[-5:]


def code_generator(characters, **kwargs):
    """
    Generate random code

    @characters: Required. Size of code generated

    @option: Optional. Type of code generated, could be ['alpha', 'num', '', None]

    return A code Alphanumeric by default or alpha|num according to the parameter option
    """
    if 'option' not in kwargs:
        possible_values = string.ascii_letters + string.digits
    elif kwargs['option'] == 'alpha':
        possible_values = string.ascii_letters
    elif kwargs['option'] == 'num':
        possible_values = string.digits
    else:
        possible_values = string.ascii_letters + string.digits

    code = ''.join(random.choice(possible_values) for _ in range(characters))
    return code


def model_code_generator(model, digits, *args, **kwargs):
    """
        Return code generator about model
    """
    field_code = kwargs['code'] if 'code' in kwargs else 'code'
    code = code_generator(digits, **kwargs)
    f = {field_code: code}
    while model.objects.filter(**f).exists():
        code = code_generator(digits, **kwargs)
        f[field_code] = code
    return code


def model_code_generator_from_slug(model, field_value, *args, **kwargs):
    """
        Return code generator from slug field
    """
    from django.utils.text import slugify
    field_code = kwargs['code'] if 'code' in kwargs else 'code'
    count = 1
    code = slugify(field_value + ' ' + str(count))
    f = {field_code: code}
    while model.objects.filter(**f).exists():
        count = 1
        code = slugify(field_value + ' ' + str(count))
        f[field_code] = code
    return code


def make_day_start(day):
    start = datetime.combine(day.date(), time.min)
    start = timezone.make_aware(start, timezone.get_current_timezone())
    return start


def make_day_end(day):
    day = datetime.combine(day, time.max)
    return timezone.make_aware(day, timezone.get_current_timezone())


def get_date_from_querystring(request, date_find, default_value=None):
    if date_find in request.GET:
        from_date_str = request.query_params.get(date_find,
                                                 (timezone.localtime(timezone.now()).date()).strftime('%d/%m/%Y'))
        return datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        return default_value


def get_time_from_querystring(request, time_find, default_value=None):
    if time_find in request.GET:
        time_str = request.query_params.get(time_find,
                                            (timezone.localtime(timezone.now()).time()).strftime('%H:%M'))
        value_time = datetime.strptime(time_str, '%H:%M')
        local_tz = pytz.timezone('America/Mexico_City')
        return value_time.replace(tzinfo=local_tz)
    else:
        return default_value


def get_datetime_from_querystring(request, date_find, default_value=None):
    if date_find in request.GET:
        from_date_str = request.query_params.get(date_find, (timezone.localtime(timezone.now())).strftime('%Y-%m-%d'))
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
        return from_date.replace(tzinfo=pytz.utc)
    else:
        return default_value


class SendEmailThread(threading.Thread):
    def __init__(self, from_email, to_emails, subject, template_name, context,
                 filename=None, file=None, mimetype=None):
        self.from_email = from_email
        self.to_emails = to_emails
        self.subject = subject
        self.template_name = template_name
        self.context = context
        self.filename = filename
        self.file = file
        self.mimetype = mimetype
        super(SendEmailThread, self).__init__()

    def run(self):
        from django.core.mail import EmailMultiAlternatives
        from common.email import attach_file_to_multipart_message
        html_content = render_template(self.template_name, self.context)
        msg = EmailMultiAlternatives(self.subject, "", self.from_email, self.to_emails)
        msg.attach_alternative(html_content, "text/html")
        attach_file_to_multipart_message(msg, settings.PATH_IMAGE_LOGO, 'volcanlogo')
        if self.filename:
            msg.attach(self.filename, self.file, self.mimetype)
        msg.send()


def send_email_new(from_email, to_emails, subject, template_name, context, *args, **kwargs):
    filename = None
    file = None
    mimetype = None
    try:
        to_emails = [email for email in to_emails if email is not None and email]
        if to_emails:
            if not from_email:
                from_email = settings.EMAIL_HOST_USER
            if 'filename' in kwargs:
                filename = kwargs.pop('filename')
                file = kwargs.pop('file')
                mimetype = kwargs.pop('mimetype')
            SendEmailThread(from_email, to_emails, subject, template_name,
                            context, filename, file, mimetype).start()
            return True
        else:
            return False
    except Exception as ex:
        print("Exception sending email, please check it")
        print(ex.args.__str__())
    return False


def render_template(template_name, context):
    from django.template.loader import get_template
    htmly = get_template(template_name)
    html_content = htmly.render(context)
    return html_content


def send_email(from_email, to_emails, subject, template_name, context, *args, **kwargs):
    sent = False
    msg = ""
    try:
        to_emails = [email for email in to_emails if email is not None and email]
        if to_emails:
            if not from_email:
                from_email = settings.EMAIL_HOST_USER
            # print "Sending email from: %s" % (from_email)
            from django.core.mail import EmailMultiAlternatives
            from django.template.loader import get_template
            from common.email import attach_file_to_multipart_message

            html_content = render_template(template_name, context)
            msg = EmailMultiAlternatives(subject, "", from_email, to_emails)
            msg.attach_alternative(html_content, "text/html")
            attach_file_to_multipart_message(msg, settings.PATH_IMAGE_LOGO, 'volcanlogo')
            if 'filename' in kwargs:
                msg.attach(kwargs.pop('filename'), kwargs.pop('file'), kwargs.get('mimetype'))
            sent = msg.send()
        else:
            sent = 'Error sin emails para ser enviados'
    except Exception as ex:
        print("Exception sending email, please check it")
        print(str(msg))
        print(ex.args.__str__())
    return sent


def get_access_token_from_request(request):
    bearer = request.META.get('HTTP_AUTHORIZATION').split(" ")
    if len(bearer) > 0:
        token = bearer[1]
    else:
        token = 'token_not_valid'
    return token


def generateUID():
    from django.utils.crypto import get_random_string
    uid = get_random_string(length=16, allowed_chars=u'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    date = datetime.now()

    result = '%s-%s-%s_%s' % (date.year, date.month, date.day, uid)

    return result


def get_data_email_general():
    return {
        "headerText": "",
        "subheaderText": "",
        "titleText": "",
        "messageText": "",
        "usernameText": "",
        "passwordText": "",
        "urlText": "",
        "buttonTitleText": "",
        "host": settings.URL_BACKEND,
        "emailContact": settings.EMAIL_CONTACT,
    }


def get_token_from_json(data):
    return jwt.encode(data, settings.SECRET_KEY, algorithm='HS256')


def get_json_from_token(token):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])


def is_valid_uuid(value):
    import uuid
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def get_month_string(digit=0, abreviature=False):
    months_abr = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul',
                  'Ago', 'Sep', 'Oct', 'Nov', 'Dic']
    months_name = ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio', 'Julio',
                   'Agosto', 'Septiempre', 'Octubre', 'Noviembre', 'Diciembre']
    return months_name[digit] if not abreviature else months_abr[digit]
