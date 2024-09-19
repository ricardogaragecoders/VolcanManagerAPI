from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.exceptions import CustomValidationError
from control.models import Company
from corresponsalia.models import Corresponsalia
from thalesapi.models import CardBinConfig, CardType


class CodigoMovimientoSerializer(serializers.Serializer):
    codigo = serializers.CharField(max_length=10)
    descripcion = serializers.CharField(max_length=255)


class ConfigCorresponsaliaSerializer(serializers.ModelSerializer):
    pais = serializers.CharField(source='country', max_length=50, allow_null=True, allow_blank=True)
    ciudad = serializers.CharField(source='city', max_length=50, allow_null=True, allow_blank=True)
    sucursal = serializers.CharField(source='branch', max_length=50, allow_null=True, allow_blank=True)
    bines = serializers.ListField(child=serializers.CharField(max_length=6), required=False, default=[], allow_null=True, allow_empty=True)
    productos = serializers.ListField(child=serializers.CharField(max_length=10), required=False, default=[], allow_null=True, allow_empty=True)
    monedas = serializers.ListField( child=serializers.CharField(max_length=3), required=False, default=[], allow_null=True, allow_empty=True)
    usuario_paycard = serializers.CharField(source='user_paycard', max_length=50, required=False, default='', allow_null=True, allow_blank=True)
    codigos_movimiento = CodigoMovimientoSerializer(many=True, required=False, default=[], allow_null=True)
    emisor = serializers.CharField(max_length=3, allow_null=True, allow_blank=True)
    autorizacion = serializers.CharField(source='authorization', required=False, default='', max_length=50, allow_null=True, allow_blank=True)

    class Meta:
        model = Corresponsalia
        fields = ('pais', 'ciudad', 'sucursal', 'bines', 'productos', 'monedas',
                  'usuario_paycard', 'codigos_movimiento', 'autorizacion',  'emisor')

    def validate(self, data):
        data = super(ConfigCorresponsaliaSerializer, self).validate(data)
        request = self.context['request']
        user = request.user
        company = None if not self.instance else self.instance.company
        params = {} if not self.instance else self.instance.params
        if len(params) == 0:
            params['bines'] = []
            params['products'] = []
            params['movements_code'] = []
            params['currencies'] = []
        issuer_id = data.pop('emisor', None)
        bines = data.pop('bines', params['bines'])
        products = data.pop('productos', params['products'])
        movements_code = data.pop('codigos_movimiento', params['movements_code'])
        currencies = data.pop('monedas', params['currencies'])
        user_paycard = data.get('user_paycard', '' if not self.instance else self.instance.user_paycard)

        if not self.instance or issuer_id:
            company = Company.objects.filter(volcan_issuer_id=issuer_id).first()

        if not company:
            raise CustomValidationError(detail={'emisor': _('Emisor no encontrado.')},
                                        code='issuer_not_found')

        if len(products) > 0:
            for product in products:
                if product == 'CREDITO':
                    cards_bin = CardBinConfig.objects.values_list('card_bin', flat=True).filter(
                        card_type=CardType.CT_CREDIT, emisor=company.volcan_issuer_id)
                    bines = list(set(bines + [item for item in cards_bin]))
                if product == 'PREPAGO':
                    cards_bin = CardBinConfig.objects.values_list('card_bin', flat=True).filter(
                        card_type=CardType.CT_PREPAID, emisor=company.volcan_issuer_id)
                    bines = list(set(bines + [item for item in cards_bin]))

        if len(bines) == 0:
            raise CustomValidationError(detail={'bines': _('Necesita enviar un bin o producto.')},
                                        code='bines_reequired')
        if 'PREPAGO' in products:
            if len(movements_code) == 0:
                raise CustomValidationError(detail={'movements_code': _('Necesitas enviar codigos de movimiento.')},
                                            code='movements_code_reequired')
            if len(user_paycard) == 0:
                raise CustomValidationError(detail={'usuario_paycard': _('Usuario paycard es requerido.')},
                                            code='usuario_paycard_reequired')

        if len(currencies) == 0:
            raise CustomValidationError(detail={'monedas': _('Necesitas agregar una moneda.')},
                                        code='currencies_reequired')

        params['bines'] = bines
        params['products'] = products
        params['movements_code'] = movements_code
        params['currencies'] = currencies
        data['params'] = params
        data['company'] = company
        return data


class CorresponsaliaSimpleSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='id')
    pais = serializers.CharField(source='country')
    ciudad = serializers.CharField(source='city')
    sucursal = serializers.CharField(source='branch')
    usuario_paycard = serializers.CharField(source='user_paycard')
    autorizacion = serializers.CharField(source='authorization')
    emisor = serializers.CharField(source='company.volcan_issuer_id')

    class Meta:
        model = Corresponsalia
        fields = ('id_corresponsalia', 'pais', 'ciudad', 'sucursal',
                  'usuario_paycard', 'autorizacion', 'emisor')
        read_only_fields = fields


class CorresponsaliaResponseSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='id')
    pais = serializers.CharField(source='country')
    ciudad = serializers.CharField(source='city')
    sucursal = serializers.CharField(source='branch')
    emisor = serializers.CharField(source='company.volcan_issuer_id')

    class Meta:
        model = Corresponsalia
        fields = ('id_corresponsalia', 'pais', 'ciudad', 'sucursal', 'emisor')
        read_only_fields = fields


class CorresponsaliaSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='id')
    pais = serializers.CharField(source='country')
    ciudad = serializers.CharField(source='city')
    sucursal = serializers.CharField(source='branch')
    bines = serializers.ListField(source='params.bines', child=serializers.CharField(max_length=6))
    productos = serializers.ListField(source='params.products', child=serializers.CharField(max_length=10))
    monedas = serializers.ListField(source='params.currencies', child=serializers.CharField(max_length=3))
    usuario_paycard = serializers.CharField(source='user_paycard')
    codigos_movimiento = CodigoMovimientoSerializer(many=True, source='params.movements_code')
    autorizacion = serializers.CharField(source='authorization')
    emisor = serializers.CharField(source='company.volcan_issuer_id')

    class Meta:
        model = Corresponsalia
        fields = ('id_corresponsalia', 'bines', 'productos', 'monedas',
                  'usuario_paycard', 'codigos_movimiento', 'pais',
                  'ciudad', 'sucursal', 'emisor', 'autorizacion')
        read_only_fields = fields
