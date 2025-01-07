from rest_framework import serializers
from django.conf import settings
from common.exceptions import CustomValidationError
from control.models import Company, Operator
from estrato.models import EstratoApiKey
from users.models import RoleType


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
        date_cutoff = data.get('coD', '').strip()
        page = int(data.pop('pg', 1))

        request = self.context['request']
        if request.user.profile.role in [RoleType.OPERATOR, RoleType.SUPERVISOR, RoleType.ADMIN]:
            operator = Operator.objects.filter(profile=request.user.profile).values('company__volcan_issuer_id').first()
            if operator and operator['company__volcan_issuer_id']:
                issuer = operator['company__volcan_issuer_id']

        if issuer not in Company.objects.values_list('volcan_issuer_id', flat=True).all():
            raise CustomValidationError(detail=u'Issuer es requerido', code='400')

        if len(date_cutoff) == 8:
            data['coD'] = f"{date_cutoff[:4]}-{date_cutoff[4:6]}-{date_cutoff[6:]}"

        if page >= 1:
            limit = settings.ESTRATO_LIMIT_QUERY
            data['limit'] = limit
            data['offset'] = (page - 1) * limit

        data['iss'] = issuer
        return data


class EstratoApiKeySerializer(serializers.ModelSerializer):
    issuer_id = serializers.CharField(source='volcan_issuer_id', max_length=3, required=True, write_only=True)

    api_key = serializers.CharField(min_length=5, required=False, write_only=True,
                                    allow_null=True, allow_blank=True)
    header_request = serializers.CharField(max_length=20, required=False, default='X-Api-Key', write_only=True,
                                           allow_null=True, allow_blank=True)
    is_active = serializers.BooleanField(required=False, default=True, write_only=True)

    class Meta:
        model = EstratoApiKey
        fields = ('issuer_id', 'url_estrato',
                  'api_key', 'header_request', 'is_active')

    def validate(self, data):
        data = super(EstratoApiKeySerializer, self).validate(data)
        company = None if not self.instance else self.instance.company
        issuer_id = data.pop('volcan_issuer_id', None if not self.instance else self.instance.volcan_issuer_id)
        url_estrato = data.get('url_estrato', '' if not self.instance else self.instance.url_estrato)
        api_key = data.get('api_key', '' if not self.instance else self.instance.api_key)
        header_request = data.get('header_request', 'X-Api-Key')

        if not company or company.volcan_issuer_id != issuer_id:
            company = Company.objects.filter(volcan_issuer_id=issuer_id).first()

        if not company:
            raise CustomValidationError(
                detail={'issuer_id': f'No existe el emisor solicitado'},
                code='400')
        else:
            issuer_id = company.volcan_issuer_id

        if not self.instance:
            if EstratoApiKey.objects.filter(volcan_issuer_id=issuer_id, deleted_at__isnull=True).exists():
                raise CustomValidationError(
                    detail={'emisor': f'Existe un registro del emisor: {issuer_id.upper()}.'},
                    code='422')
        elif issuer_id and EstratoApiKey.objects.filter(volcan_issuer_id=issuer_id,
                                                        deleted_at__isnull=True).exclude(id=self.instance.id).exists():
            raise CustomValidationError(detail={'emisor': f'Existe un registro del emisor: {issuer_id.upper()}.'},
                                        code='422')

        if len(url_estrato) == 0:
            url_estrato = settings.SERVER_ESTRATO_VOLCAN_URL

        if len(api_key) == 0:
            raise CustomValidationError(detail={'api_key': f'El valor de Api Key es requerido.'}, code='422')

        if len(header_request) == 0:
            header_request = 'X-Api-Key'

        data['company'] = company
        data['volcan_issuer_id'] = issuer_id
        data['url_estrato'] = url_estrato
        data['api_key'] = api_key
        data['header_request'] = header_request
        return data


class EstratoApiKeyListSerializer(serializers.ModelSerializer):
    api_key_id = serializers.CharField(source='id')
    issuer_id = serializers.CharField(source='volcan_issuer_id')
    is_active = serializers.BooleanField(default=True)

    class Meta:
        model = EstratoApiKey
        fields = ('api_key_id', 'issuer_id', 'is_active')
        read_only_fields = fields
