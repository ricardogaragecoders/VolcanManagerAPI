from rest_framework import serializers

from common.exceptions import CustomValidationError
from common.utils import model_code_generator
from control.models import Webhook
from django.conf import settings


class ConsultaCuentaSerializer(serializers.Serializer):
    CUENTA = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CIF = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ID_OWNER = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DOC_IDENTIFICACION = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    MONEDA = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CUENTA', 'CIF', 'ID_OWNER', 'TIPO_IDENTIFICACION', 'DOC_IDENTIFICACION',
                  'MONEDA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaCuentaSerializer, self).validate(data)
        cuenta = data.get('CUENTA', "").strip()
        cif = data.get('CIF', "").strip()
        id_owner = data.get('ID_OWNER', "").strip()
        tipo_identificacion = data.get('TIPO_IDENTIFICACION', "").strip()
        doc_identificacion = data.get('DOC_IDENTIFICACION', "").strip()

        data['CUENTA'] = cuenta
        data['CIF'] = cif
        data['ID_OWNER'] = id_owner
        data['TIPO_IDENTIFICACION'] = tipo_identificacion
        data['DOC_IDENTIFICACION'] = doc_identificacion

        if len(cuenta) == 0 and len(cif) == 0 and len(id_owner) == 0 and len(tipo_identificacion) == 0 and len(
                doc_identificacion) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        return data


class ConsultaTarjetaSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CIF = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ID_OWNER = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DOC_IDENTIFICACION = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'CIF', 'ID_OWNER', 'TIPO_IDENTIFICACION', 'DOC_IDENTIFICACION',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaTarjetaSerializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        cif = data.get('CIF', "").strip()
        id_owner = data.get('ID_OWNER', "").strip()
        tipo_identificacion = data.get('TIPO_IDENTIFICACION', "").strip()
        doc_identificacion = data.get('DOC_IDENTIFICACION', "").strip()

        data['TARJETA'] = tarjeta
        data['CIF'] = cif
        data['ID_OWNER'] = id_owner
        data['TIPO_IDENTIFICACION'] = tipo_identificacion
        data['DOC_IDENTIFICACION'] = doc_identificacion

        if len(tarjeta) == 0 and len(cif) == 0 and len(id_owner) == 0 and len(tipo_identificacion) == 0 and len(
                doc_identificacion) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        return data


class CambioPINSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    PIN = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'PIN', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CambioPINSerializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        pin = data.get('PIN', "").strip()

        data['TARJETA'] = tarjeta
        data['PIN'] = pin

        if len(tarjeta) == 0:
            raise CustomValidationError(detail=u'El numbero de tarjeta es requerido',
                                        code='422')
        if len(pin) == 0:
            raise CustomValidationError(detail=u'El nuevo PIN es requerido',
                                        code='422')
        return data


class ExtrafinanciamientoSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    IMPORTE = serializers.FloatField(min_value=0.0, required=False, default=0.0)
    TASA = serializers.FloatField(min_value=0.0, required=False, default=0.0)
    PLAZO = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    TIPO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    COMERCIO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'MONEDA', 'IMPORTE', 'TASA', 'PLAZO', 'REFERENCIA', 'TIPO',
                  'COMERCIO', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ExtrafinanciamientoSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        amount = float(data.get('IMPORTE', 0.0))
        amounts = ("%.2f" % amount).split('.')
        tax = float(data.get('TASA', 0.0))
        taxes = ("%.2f" % tax).split('.')

        data['TARJETA'] = card
        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='422')
        # if not importe.isnumeric():
        #     raise CustomValidationError(detail=u'El importe no es numerico',
        #                                 code='400')
        data['TASA'] = taxes[0].zfill(2) + taxes[1].zfill(2)
        data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)
        return data


class WebhookSerializer(serializers.ModelSerializer):
    emisor = serializers.CharField(source='account_issuer', required=True, write_only=True)
    activo = serializers.BooleanField(source='active', required=False, default=True, write_only=True)

    class Meta:
        model = Webhook
        fields = ('emisor', 'url_webhook', 'activo')

    def validate(self, data):
        data = super(WebhookSerializer, self).validate(data)
        account_issuer = data.get('account_issuer', '' if not self.instance else self.instance.account_issuer)
        url_webhook = data.get('url_webhook', '' if not self.instance else self.instance.url_webhook)
        key_webhook = data.get('key_webhook', '' if not self.instance else self.instance.key_webhook)

        if not self.instance:
            if Webhook.objects.filter(account_issuer=account_issuer, deleted_at__isnull=True).exists():
                raise CustomValidationError(detail={'emisor': f'Existe un endpoint del emisor: {account_issuer.upper()}.'},
                                            code='422')
        elif account_issuer and Webhook.objects.filter(account_issuer=account_issuer,
                                                       deleted_at__isnull=True).exclude(id=self.instance.id).exists():
            raise CustomValidationError(detail={'emisor': f'Existe un endpoint del emisor: {account_issuer.upper()}.'},
                                        code='422')

        if len(url_webhook) == 0:
            raise CustomValidationError(detail={'url_webhook': f'La url del webhook es requerido.'},
                                        code='422')

        if len(key_webhook) == 0:
            key_webhook = model_code_generator(model=Webhook, digits=32, code='key_webhook')

        data['account_issuer'] = account_issuer
        data['url_webhook'] = url_webhook
        data['key_webhook'] = key_webhook
        return data


class WebhookListSerializer(serializers.ModelSerializer):
    rsp_webhook_id = serializers.CharField(source='id')
    rsp_emisor = serializers.CharField(source='account_issuer')
    rsp_url_webhook = serializers.CharField(source='url_webhook')
    rsp_key_webhook = serializers.CharField(source='key_webhook')
    rsp_activo = serializers.BooleanField(source='active')

    class Meta:
        model = Webhook
        fields = ('rsp_webhook_id', 'rsp_emisor', 'rsp_url_webhook', 'rsp_key_webhook', 'rsp_activo')
        read_only_fields = fields


class TransactionSerializer(serializers.Serializer):
    monto = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    moneda = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    emisor = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    estatus = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    tipo_transaccion = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    tarjeta = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    id_movimiento = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    fecha_transaccion = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    hora_transaccion = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    referencia = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    numero_autorizacion = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    codigo_autorizacion = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    comercio = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    user = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)
    password = serializers.CharField(max_length=100, default='', required=False, allow_null=True, allow_blank=True)

    def validate(self, data):
        data = super(TransactionSerializer, self).validate(data)
        user = data.pop('user', settings.VOLCAN_USER_TRANSACTION)
        password = data.pop('password', settings.VOLCAN_PASSWORD_TRANSACTION)

        if user != settings.VOLCAN_USER_TRANSACTION or password != settings.VOLCAN_PASSWORD_TRANSACTION:
            raise CustomValidationError(detail=f'Prueba de usuario y password incorrectos.',
                                        code='422')

        return data
