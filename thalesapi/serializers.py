from rest_framework import serializers
from decimal import Decimal, InvalidOperation, DecimalException
from common.exceptions import CustomValidationError
from django.conf import settings

from common.utils import code_generator


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

        data['FOLIO'] = code_generator(characters=12, option='num')
        data['USUARIO_ATZ'] = settings.VOLCAN_USUARIO_ATZ
        data['ACCESO_ATZ'] = settings.VOLCAN_ACCESO_ATZ
        data['EMISOR'] = 'CMF'

        from jwcrypto import jwk, jwe
        from jwcrypto.common import json_encode, json_decode
        import json
        try:
            with open(settings.PRIV_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM, "rb") as pemfile:
                private_key = jwk.JWK.from_pem(pemfile.read())
            if private_key:
                jwetoken = jwe.JWE()
                jwetoken.deserialize(encrypted_data, key=private_key)
                payload = json.loads(jwetoken.payload)
                data['TARJETA'] = payload['pan'] if 'pan' in payload else ''
                data['FECHA_EXP'] = payload['exp'] if 'exp' in payload else ''
                data['NOMBRE'] = payload['name'] if 'name' in payload else ''
                data['CVV'] = payload['cvv'] if 'cvv' in payload else ''
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)

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
        data['EMISOR'] = 'CMF'

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
        data['EMISOR'] = 'CMF'
        data['AUTORIZACION'] = ''

        return data