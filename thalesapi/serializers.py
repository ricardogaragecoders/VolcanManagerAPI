from django.conf import settings
from rest_framework import serializers

from common.exceptions import CustomValidationError
from common.utils import code_generator
from thalesapi.models import CardBinConfig, CardDetail


class VerifyCardCreditSerializer(serializers.Serializer):
    encryptedData = serializers.CharField(min_length=3, required=True, allow_blank=False, allow_null=False)
    cardId = serializers.CharField(max_length=48, required=False, default="", allow_blank=True, allow_null=True)
    cardBin = serializers.CharField(max_length=8, required=True, allow_blank=False, allow_null=False)

    class Meta:
        fields = ('encryptedData', 'cardId', 'cardBin')

    def validate(self, data):
        data = super(VerifyCardCreditSerializer, self).validate(data)
        private_key = None
        encrypted_data = data.pop('encryptedData', None)
        card_id = data.pop('cardId', None)
        card_bin = data.pop('cardBin', None)

        data['card_detail'] = CardDetail.objects.filter(card_id=card_id).first()
        data['FOLIO'] = code_generator(characters=12, option='num')
        data['USUARIO_ATZ'] = settings.VOLCAN_USUARIO_ATZ
        data['ACCESO_ATZ'] = settings.VOLCAN_ACCESO_ATZ
        data['EMISOR'] = settings.THALES_API_EMISOR_DEFAULT

        from jwcrypto import jwk, jwe
        import json
        try:
            with open(settings.PRIV_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM, "rb") as pemfile:
                private_key = jwk.JWK.from_pem(pemfile.read())
            if private_key:
                jwe_token = jwe.JWE()
                jwe_token.deserialize(encrypted_data, key=private_key)
                payload = json.loads(jwe_token.payload)
                data['TARJETA'] = payload['pan'] if 'pan' in payload else ''
                data['FECHA_EXP'] = payload['exp'] if 'exp' in payload else ''
                data['NOMBRE'] = payload['name'] if 'name' in payload else ''
                data['CVV'] = payload['cvv'] if 'cvv' in payload else ''
                if len(data['FECHA_EXP']) == 4:
                    data['FECHA_EXP'] = data['FECHA_EXP'][2:4] + data['FECHA_EXP'][0:2]
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)

        from thalesapi.utils import get_card_triple_des_process
        data['CARD_BIN'] = data['TARJETA'][0:8]
        card_az7 = get_card_triple_des_process(data['TARJETA'])
        if not card_az7:
            raise CustomValidationError(detail=u'Error en proceso de encriptado triple des', code='400')
        else:
            data['TARJETA'] = card_az7

        return data


class GetConsumerInfoSerializer(serializers.Serializer):
    cardId = serializers.CharField(max_length=48, required=False, default="", allow_blank=True, allow_null=True)
    consumerId = serializers.CharField(max_length=64, required=False, default="", allow_blank=False, allow_null=False)

    class Meta:
        fields = ('cardId', 'consumerId')

    def validate(self, data):
        data = super(GetConsumerInfoSerializer, self).validate(data)
        card_id = data.pop('cardId', None)
        consumer_id = data.pop('consumerId', None)

        data['TARJETAID'] = card_id
        if len(card_id) == 0:
            raise CustomValidationError(detail=u'TARJETAID es requerido', code='400')

        data['FOLIO'] = code_generator(characters=12, option='num')
        data['USUARIO_ATZ'] = settings.VOLCAN_USUARIO_ATZ
        data['ACCESO_ATZ'] = settings.VOLCAN_ACCESO_ATZ
        data['EMISOR'] = settings.THALES_API_EMISOR_DEFAULT

        return data


class GetDataCredentialsSerializer(serializers.Serializer):
    cardId = serializers.CharField(max_length=48, required=False, default="", allow_blank=True, allow_null=True)
    consumerId = serializers.CharField(max_length=64, required=False, default="", allow_blank=False, allow_null=False)

    class Meta:
        fields = ('cardId', 'consumerId')

    def validate(self, data):
        data = super(GetDataCredentialsSerializer, self).validate(data)
        card_id = data.pop('cardId', None)
        consumer_id = data.pop('consumerId', None)

        data['TARJETAID'] = card_id
        if len(card_id) == 0:
            raise CustomValidationError(detail=u'TARJETAID es requerido', code='400')

        data['FOLIO'] = code_generator(characters=12, option='num')
        data['USUARIO_ATZ'] = settings.VOLCAN_USUARIO_ATZ
        data['ACCESO_ATZ'] = settings.VOLCAN_ACCESO_ATZ
        data['EMISOR'] = settings.THALES_API_EMISOR_DEFAULT
        # data['AUTORIZACION'] = settings.THALESAPI_AUTORIZACION_DEFAULT

        return data


class GetDataTokenizationSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    FECHA_EXP = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    NOMBRE = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CVV = serializers.CharField(max_length=4, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    FOLIO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'FECHA_EXP', 'NOMBRE', 'CVV',
                  'FOLIO', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(GetDataTokenizationSerializer, self).validate(data)
        profile = self.context['request'].user.profile
        card = data.get('TARJETA', '').strip()
        exp_date = data.get('FECHA_EXP', '').strip()
        cvv = data.get('CVV', '').strip()
        name = data.get('NOMBRE', '').strip()
        transmitter = data.get('EMISOR', '').strip().upper()
        folio = data.get('FOLIO', '').strip()

        if len(card) == 0:
            raise CustomValidationError(detail=u'TARJETA es requerido', code='400')

        if len(exp_date) != 4:
            raise CustomValidationError(detail=u'FECHA_EXP es requerido', code='400')

        exp_date = exp_date[2:4] + exp_date[0:2]

        if len(name) <= 3:
            raise CustomValidationError(detail=u'NOMBRE es requerido', code='400')

        if not profile.isSuperadmin():
            if profile.first_name != transmitter:
                raise CustomValidationError(detail=u'EMISOR desconocido', code='400')

        if transmitter not in ['CMF',]:
            raise CustomValidationError(detail=u'EMISOR no autorizado', code='400')

        if len(folio) == 0:
            folio = code_generator(characters=12, option='num')

        data['FECHA_EXP'] = exp_date
        data['CVV'] = cvv
        data['FOLIO'] = folio
        data['EMISOR'] = transmitter
        data['USUARIO_ATZ'] = settings.VOLCAN_USUARIO_ATZ
        data['ACCESO_ATZ'] = settings.VOLCAN_ACCESO_ATZ

        return data


class GetVerifyCardSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    FECHA_EXP = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    TARJETAID = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CLIENTEID = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CUENTAID = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    ISSUER_ID = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CARD_PRODUCT_ID = serializers.CharField(max_length=100, required=False, default="", allow_blank=True)
    STATE = serializers.CharField(max_length=10, required=False, default="ACTIVE", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="CMF", allow_blank=True)
    FOLIO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'FECHA_EXP', 'TARJETAID', 'CLIENTEID', 'CUENTAID',
                  'ISSUER_ID', 'CARD_PRODUCT_ID', 'STATE','FOLIO', 'EMISOR')

    def validate(self, data):
        data = super(GetVerifyCardSerializer, self).validate(data)
        profile = self.context['request'].user.profile
        card = data.get('TARJETA', '').strip()
        exp_date = data.get('FECHA_EXP', '').strip()
        transmitter = data.get('EMISOR', '').strip().upper()
        issuer_id = data.get('ISSUER_ID', '').strip()
        card_product_id = data.get('CARD_PRODUCT_ID', '').strip()
        folio = data.get('FOLIO', '').strip()
        state = data.get('STATE', '').strip()

        if len(card) == 0:
            raise CustomValidationError(detail=u'TARJETA es requerido', code='400')

        if len(exp_date) != 4:
            raise CustomValidationError(detail=u'FECHA_EXP es requerido', code='400')

        exp_date = exp_date[2:4] + exp_date[0:2]

        if not profile.isSuperadmin():
            if profile.first_name != transmitter:
                raise CustomValidationError(detail=u'EMISOR desconocido', code='400')

        if transmitter not in ['CMF',]:
            raise CustomValidationError(detail=u'EMISOR no autorizado', code='400')

        if len(folio) == 0:
            folio = code_generator(characters=12, option='num')

        if len(issuer_id) == 0:
            issuer_id = settings.THALES_API_ISSUER_ID

        if len(card_product_id) == 0:
            card_product_id = "D1_VOLCAN_VISA_SANDBOX"

        data['FECHA_EXP'] = exp_date
        data['FOLIO'] = folio
        data['EMISOR'] = transmitter
        data['ISSUER_ID'] = issuer_id
        data['CARD_PRODUCT_ID'] = card_product_id
        data['STATE'] = state
        return data


class CardBinConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = CardBinConfig
        fields = '__all__'
