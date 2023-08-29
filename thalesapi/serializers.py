from rest_framework import serializers
from decimal import Decimal, InvalidOperation, DecimalException
from common.exceptions import CustomValidationError
from django.conf import settings

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

                data['pan'] = payload['pan'] if 'pan' in payload else ''
                data['exp'] = payload['exp'] if 'exp' in payload else ''
                data['name'] = payload['name'] if 'name' in payload else ''
                data['cvv'] = payload['cvv'] if 'cvv' in payload else ''
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)

        return data
