from rest_framework import serializers
from decimal import Decimal, InvalidOperation, DecimalException
from common.exceptions import CustomValidationError


class VerifyCardCreditSerializer(serializers.Serializer):
    encryptedData = serializers.CharField(min_length=3, required=True, allow_blank=False, allow_null=False)
    cardId = serializers.CharField(max_length=48, required=False, default="", allow_blank=True, allow_null=True)
    cardBin = serializers.CharField(max_length=6, required=True, allow_blank=False, allow_null=False)

    class Meta:
        fields = ('encryptedData', 'cardId', 'cardBin')

    def validate(self, data):
        data = super(VerifyCardCreditSerializer, self).validate(data)
        encrypted_data = data.pop('encryptedData', None)
        card_id = data.pop('cardId', None)
        card_bin = data.pop('cardBin', None)

        data['pan'] = 'algundato'
        data['exp'] = '0524'
        data['name'] = 'RICARDO ALCANTARA G'
        data['cvv'] = '123'

        return data
