from rest_framework import serializers
from django.conf import settings
from common.exceptions import CustomValidationError


class EstadosCuentaSerializer(serializers.Serializer):
    emisor = serializers.CharField(source='iss', max_length=3, required=False, default="", allow_blank=True)
    cuenta = serializers.CharField(source='acc', max_length=15, required=False, default="", allow_blank=True)
    fecha_de_corte = serializers.CharField(source='coD', max_length=10, required=False, default="", allow_blank=True)
    pagina = serializers.IntegerField(source='pg', required=False, default=1)

    class Meta:
        fields = ('iss', 'acc', 'coD', 'pg')

    def validate(self, data):
        data = super(EstadosCuentaSerializer, self).validate(data)
        issuer = data.get('iss', '').strip()
        date_cutoff = data.get('dc', '').strip()
        page = int(data.pop('pg', 1))

        if len(issuer) == 0:
            raise CustomValidationError(detail=u'Issuer es requerido', code='400')
        
        if len(date_cutoff) == 8:
            data['dc'] = f"{date_cutoff[:4]}-{date_cutoff[4:6]}-{date_cutoff[6:]}"

        if page >= 1:
            limit = settings.ESTRATO_LIMIT_QUERY
            data['limit'] = limit
            data['offset'] = (page - 1) * limit

        return data
