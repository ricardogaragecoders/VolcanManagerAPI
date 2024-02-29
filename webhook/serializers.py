from django.conf import settings
from rest_framework import serializers
from django.utils import timezone
from common.exceptions import CustomValidationError
from common.utils import model_code_generator, is_float
from webhook.models import Webhook


class WebhookSerializer(serializers.ModelSerializer):
    emisor = serializers.CharField(source='account_issuer', max_length=3, required=True, write_only=True)
    auth_username = serializers.CharField(max_length=45, required=False, write_only=True,
                                          allow_null=True, allow_blank=True)
    auth_password = serializers.CharField(max_length=45, required=False, write_only=True,
                                          allow_null=True, allow_blank=True)
    key_webhook = serializers.CharField(min_length=5, required=False, write_only=True,
                                        allow_null=True, allow_blank=True)
    header_webhook = serializers.CharField(max_length=20, required=False, default='Authorization', write_only=True,
                                           allow_null=True, allow_blank=True)
    activo = serializers.BooleanField(source='active', required=False, default=True, write_only=True)

    class Meta:
        model = Webhook
        fields = ('emisor', 'url_webhook', 'auth_username', 'auth_password', 'key_webhook', 'header_webhook', 'activo')

    def validate(self, data):
        data = super(WebhookSerializer, self).validate(data)
        account_issuer = data.get('account_issuer', '' if not self.instance else self.instance.account_issuer)
        url_webhook = data.get('url_webhook', '' if not self.instance else self.instance.url_webhook)
        auth_username = data.pop('auth_username', None)
        auth_password = data.pop('auth_password', None)
        key_webhook = data.get('key_webhook', '' if not self.instance else self.instance.key_webhook)
        header_webhook = data.pop('header_webhook', 'Authorization')

        if not self.instance:
            if Webhook.objects.filter(account_issuer=account_issuer, deleted_at__isnull=True).exists():
                raise CustomValidationError(
                    detail={'emisor': f'Existe un endpoint del emisor: {account_issuer.upper()}.'},
                    code='422')
        elif account_issuer and Webhook.objects.filter(account_issuer=account_issuer,
                                                       deleted_at__isnull=True).exclude(id=self.instance.id).exists():
            raise CustomValidationError(detail={'emisor': f'Existe un endpoint del emisor: {account_issuer.upper()}.'},
                                        code='422')

        if len(url_webhook) == 0:
            raise CustomValidationError(detail={'url_webhook': f'La url del webhook es requerido.'},
                                        code='422')

        if auth_username and auth_password:
            import base64
            usr_pass = bytes(f"{auth_username}:{auth_password}", 'UTF-8')
            key_webhook = base64.b64encode(usr_pass).decode('utf-8')
            key_webhook = f'Basic {key_webhook}'
            header_webhook = 'Authorization'

        if len(key_webhook) == 0:
            key_webhook = model_code_generator(model=Webhook, digits=32, code='key_webhook')
            key_webhook = f'Basic {key_webhook}'
            header_webhook = 'Authorization'

        if len(header_webhook) == 0:
            raise CustomValidationError(detail={'header_webhook': f'El nombre del header es requerido.'}, code='422')

        data['account_issuer'] = account_issuer.upper()
        data['url_webhook'] = url_webhook
        data['key_webhook'] = key_webhook
        data['header_webhook'] = header_webhook
        return data


class WebhookListSerializer(serializers.ModelSerializer):
    webhook_id = serializers.CharField(source='id')
    emisor = serializers.CharField(source='account_issuer')
    activo = serializers.BooleanField(source='active')

    class Meta:
        model = Webhook
        fields = ('webhook_id', 'emisor', 'url_webhook', 'activo')
        read_only_fields = fields


class TransactionSerializer(serializers.Serializer):
    monto = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    moneda = serializers.CharField(max_length=100, default='', required=False,allow_blank=True)
    emisor = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    estatus = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    tipo_transaccion = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    tarjeta = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    id_movimiento = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    fecha_transaccion = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    hora_transaccion = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    referencia = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    numero_autorizacion = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    codigo_autorizacion = serializers.CharField(max_length=100, default='', required=False,  allow_blank=True)
    comercio = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    pais = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    email = serializers.CharField(max_length=150, default='', required=False, allow_blank=True)
    tarjetahabiente = serializers.CharField(max_length=150, default='', required=False, allow_blank=True)
    user = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    password = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)

    class Meta:
        fields = ('monto', 'moneda', 'emisor', 'estatus', 'tipo_transaccion', 'tarjeta', 'id_movimiento',
                  'fecha_transaccion', 'hora_transaccion', 'referencia', 'numero_autorizacion', 'codigo_autorizacion',
                  'comercio', 'pais', 'email', 'tarjetahabiente', 'user', 'password')

    def validate(self, data):
        data = super(TransactionSerializer, self).validate(data)
        id_movimiento = data.get('id_movimiento', '')
        user = data.pop('user', settings.VOLCAN_USER_TRANSACTION)
        password = data.pop('password', settings.VOLCAN_PASSWORD_TRANSACTION)
        emisor = data.get('emisor', '').upper()
        monto = data.get('monto', '').lower()
        tarjeta = data.get('tarjeta', '').upper()

        if user != settings.VOLCAN_USER_TRANSACTION or password != settings.VOLCAN_PASSWORD_TRANSACTION:
            raise CustomValidationError(detail=f'Usuario y/o password incorrectos.',
                                        code='401')
        if len(emisor) == 0:
            raise CustomValidationError(detail=f'Emisor es requerido.',
                                        code='400')
        data['emisor'] = emisor

        webhook = Webhook.objects.filter(account_issuer=emisor).first()

        if not webhook:
            raise CustomValidationError(detail=f'El emisor no tiene definido un webhook.',
                                        code='400')

        if len(monto) == 0 and not is_float(monto):
            raise CustomValidationError(detail=f'Solo se aceptan valores numericos.',
                                        code='400')
        data['monto'] = monto
        if len(tarjeta) < 16:
            raise CustomValidationError(detail=f'El numero de tarjeta es requerido.',
                                        code='400')
        data['tarjeta'] = tarjeta

        if len(id_movimiento) == 0:
            import uuid
            data['id_movimiento'] = str(uuid.uuid4())

        data = {
            'user': {'name': 'webhook'},
            'notification': data.copy(),
            'notification_type': {'type': 'transaction', 'mode': 'normal', 'version': 1},
            'delivery': {
                'delivered': False,
                'delivery_date': None,
                'attempts': 0
            },
            'webhook': {
                'id': str(webhook.id),
                'url': webhook.url_webhook,
                'headers': {
                    'header': webhook.header_webhook,
                    'value': f"...{webhook.key_webhook[-4:]}"
                }
            },
            'issuer': {'issuer': emisor},
            'response': {
                'code': '',
                'body': ''
            },
            'created_at': timezone.localtime(timezone.now())
        }

        return data

class PaycardNotificationserializer(serializers.Serializer):
    prioridad = serializers.CharField(source='priority', max_length=10, default='100', required=False, allow_blank=True)
    mensaje = serializers.JSONField(source='message', required=True)
    user = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    password = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)
    emisor = serializers.CharField(max_length=100, default='', required=False, allow_blank=True)

    class Meta:
        fields = ('prioridad', 'mensaje', 'user', 'password', 'emisor')

    def validate(self, data):
        data = super(PaycardNotificationserializer, self).validate(data)
        priority = data.pop('priority', '100')
        message = data.pop('message', {'Tarjeta': '', 'IdMovimiento': ''})
        user = data.pop('user', settings.VOLCAN_USER_TRANSACTION)
        password = data.pop('password', settings.VOLCAN_PASSWORD_TRANSACTION)
        issuer = data.get('emisor', '').upper()
        id_movimiento = message['IdMovimiento']

        if user != settings.VOLCAN_USER_TRANSACTION or password != settings.VOLCAN_PASSWORD_TRANSACTION:
            raise CustomValidationError(detail=f'Usuario y/o password incorrectos.',
                                        code='401')
        if len(issuer) == 0:
            raise CustomValidationError(detail=f'Emisor es requerido.',
                                        code='400')
        webhook = Webhook.objects.filter(account_issuer=issuer).first()

        if not webhook:
            raise CustomValidationError(detail=f'El emisor no tiene definido un webhook.',
                                        code='400')
        #
        # if len(monto) == 0 and not is_float(monto):
        #     raise CustomValidationError(detail=f'Solo se aceptan valores numericos.',
        #                                 code='400')
        # data['monto'] = monto
        # if len(tarjeta) < 16:
        #     raise CustomValidationError(detail=f'El numero de tarjeta es requerido.',
        #                                 code='400')
        # data['tarjeta'] = tarjeta
        #

        if len(id_movimiento) == 0:
            import uuid
            message['IdMovimiento'] = str(uuid.uuid4())

        data = {
            'user': {'name': 'webhook'},
            'notification': message.copy(),
            'notification_type': {'type': 'paycard', 'mode': 'normal', 'version': 1, 'priority': priority},
            'delivery': {
                'delivered': False,
                'delivery_date': None,
                'attempts': 0
            },
            'webhook': {
                'id': str(webhook.id),
                'url': webhook.url_webhook,
                'headers': {
                    'header': webhook.header_webhook,
                    'value': f"...{webhook.key_webhook[-4:]}"
                }
            },
            'issuer': {'issuer': issuer },
            'response': {
                'code': '',
                'body': ''
            },
            'created_at': timezone.localtime(timezone.now())
        }

        return data
