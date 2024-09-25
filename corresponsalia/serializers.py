import logging
from decimal import Decimal

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.exceptions import CustomValidationError
from control.models import Company, Currency
from corresponsalia.models import Corresponsalia, TransaccionCorresponsalia
from thalesapi.models import CardBinConfig, CardType
from thalesapi.utils import get_card_triple_des_process

logger = logging.getLogger(__name__)

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


class TransaccionCorresponsaliaSerializer(serializers.ModelSerializer):
    id_transaccion = serializers.UUIDField(source='id')
    corresponsalia = serializers.SerializerMethodField(read_only=True)
    tarjeta = serializers.CharField(source='card_number', required=False, allow_blank=True, allow_null=True, default='')
    moneda = serializers.SerializerMethodField(read_only=True)
    codigo_movimiento = serializers.CharField(source='movement_code', required=False, allow_blank=True, allow_null=True, default='')
    importe = serializers.CharField(source='amount', required=False, allow_blank=True, allow_null=True, default='')
    referencia_numerica = serializers.CharField(source='reference', required=False, allow_blank=True, allow_null=True, default='')
    card_bin = serializers.SerializerMethodField(read_only=True)
    transcciones = serializers.SerializerMethodField(read_only=True)
    estatus = serializers.CharField(source='status')
    fecha_creacion = serializers.DateTimeField(source='created_at')

    class Meta:
        model = TransaccionCorresponsalia
        fields = ('id_transaccion', 'id_corresponsalia',
                  'tarjeta', 'moneda', 'codigo_movimiento', 'importe',
                  'referencia_numerica', 'card_bin', 'transcciones',
                  'estatus', 'fecha_creacion')
        read_only_fields = fields

    def get_corresponsalia(self, instance):
        corresponsalia = instance.corresponsalia
        if corresponsalia:
            return {
                'id': str(corresponsalia.id),
                'pais': corresponsalia.country,
                'ciudad': corresponsalia.city,
                'sucursal': corresponsalia.branch
            }
        return None

    def get_moneda(self, instance):
        currency = instance.currency
        if currency:
            return {
                'code': currency.abr_code,
                'number': currency.number_code,
                'name': currency.name
            }
        return None

    def get_card_bin(self, instance):
        card_bin_config = instance.card_bin_config
        if card_bin_config:
            return {
                'BIN': card_bin_config.card_bin,
                'tipo': card_bin_config.get_card_type_display(),
                'emisor': card_bin_config.issuer_id
            }
        return None

    def get_transacciones(self, instance):
        return {}


class CreateTransaccionCorresponsaliaSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='corresponsalia_id', allow_null=True)
    tarjeta = serializers.CharField(source='card_number', required=False, allow_blank=True, allow_null=True, default='')
    moneda = serializers.CharField(source='currency_str', required=False, allow_blank=True, allow_null=True, default='')
    codigo_movimiento = serializers.CharField(source='movement_code', required=False, allow_blank=True, allow_null=True,
                                              default='')
    importe = serializers.CharField(source='amount', required=False, allow_blank=True, allow_null=True, default='')
    referencia_numerica = serializers.CharField(source='reference', required=False, allow_blank=True, allow_null=True,
                                                default='')

    class Meta:
        model = TransaccionCorresponsalia
        fields = ('id_corresponsalia', 'tarjeta', 'moneda', 'codigo_movimiento',
                  'importe', 'referencia_numerica')


    def validate(self, data):
        data = super(CreateTransaccionCorresponsaliaSerializer, self).validate(data)
        request = self.context['request']
        corresponsalia_id = data.pop('corresponsalia_id', None)
        card_number = data.get('card_number', None)
        currency_str = data.pop('currency_str', None)
        # movement_code = data.get('movement_code', None)
        amount = data.get('amount', None)
        # reference = data.get('reference', None)
        user = request.user

        try:
            corresponsalia = Corresponsalia.objects.get(id=corresponsalia_id)
        except Corresponsalia.DoesNotExist:
            raise CustomValidationError(detail={'id_corresponsalia': _('Corresponsalia no encontrada.')},
                                        code='corresponsalia_not_found')

        if isinstance(card_number, str) and card_number.isnumeric() and len(card_number) == 16:
            card_number = get_card_triple_des_process(card_number, is_descript=False)

        card_real = get_card_triple_des_process(card_number, is_descript=True)

        try:
            card_bin_config = CardBinConfig.objects.get(card_bin=card_real[0:8])
        except CardBinConfig.DoesNotExist:
            logger.info(f"card_bin={card_real[0:8]}")
            raise CustomValidationError(detail={'tarjeta': _('BIN no encontrado.')},
                                        code='card_bin_config_not_found')

        if isinstance(currency_str, str) and currency_str.isnumeric() and len(currency_str) == 3:
            currency = Currency.objects.filter(number_code=currency_str).first()
        else:
            currency = Currency.objects.filter(abr_code=currency_str).first()

        if card_bin_config.card_bin not in corresponsalia.params['bines']:
            raise CustomValidationError(detail={'tarjeta': _('Corresponsalia no esta configurada con el BIN.')},
                                        code='card_bin_config_not_found')

        if currency.number_code not in corresponsalia.params['currencies']:
            raise CustomValidationError(detail={'moneda': _('Corresponsalia no esta configurada con la moneda.')},
                                        code='currency_not_found')

        data['corresponsalia'] = corresponsalia
        data['currency'] = currency
        data['card_real'] = card_real
        data['card_bin_config'] = card_bin_config

        if '.' in amount:
            data['amount'] = Decimal(amount)
        elif currency.decimals > 0 and len(amount) >= (currency.decimals + 1):
            length = len(amount)
            value_s = "%s.%s" % (amount[0:length - currency.decimals], amount[length - currency.decimals:length])
            data['amount'] = Decimal(value_s)
        else:
            data['amount'] = amount

        return data



class TransaccionCorresponsaSimpleliaSerializer(serializers.ModelSerializer):
    id_transaccion = serializers.UUIDField(source='id')
    id_corresponsalia = serializers.UUIDField(source='corresponsalia_id')
    tarjeta = serializers.CharField(source='card_number')
    moneda = serializers.CharField(source='currency.number_code')
    codigo_movimiento = serializers.CharField(source='movement_code')
    importe = serializers.CharField(source='amount')
    referencia_numerica = serializers.CharField(source='reference')
    estatus = serializers.CharField(source='status')
    fecha_creacion = serializers.DateTimeField(source='created_at')

    class Meta:
        model = TransaccionCorresponsalia
        fields = ('id_transaccion', 'id_corresponsalia', 'tarjeta', 'moneda', 'codigo_movimiento',
                  'importe', 'referencia_numerica', 'estatus', 'fecha_creacion')
        read_only_fields = fields