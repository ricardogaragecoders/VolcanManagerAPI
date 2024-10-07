import logging
from decimal import Decimal

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.exceptions import CustomValidationError
from common.utils import code_generator
from control.models import Company, Currency
from corresponsalia.models import Corresponsalia, TransaccionCorresponsalia, TransaccionCorresponsaliaStatus
from thalesapi.models import CardBinConfig, CardType
from thalesapi.utils import get_card_triple_des_process

logger = logging.getLogger(__name__)

class CodigoMovimientoSerializer(serializers.Serializer):
    codigo = serializers.CharField(source='code')
    tipo = serializers.CharField(source='type')
    descripcion = serializers.CharField(source='description')

class ConfiguracionCorresponsaliaItemSerializer(serializers.Serializer):
    bin = serializers.CharField()
    producto = serializers.CharField(source='product')
    monedas = serializers.ListField(
        child=serializers.CharField(), source='currencies'
    )
    codigos_movimiento = serializers.ListField(
        child=CodigoMovimientoSerializer(), source='movement_codes'
    )

class CreateCorresponsaliaSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='id', read_only=True)
    descripcion = serializers.CharField(source='description', max_length=50, allow_null=True, allow_blank=True)
    pais = serializers.CharField(source='country', max_length=50, allow_null=True, allow_blank=True)
    ciudad = serializers.CharField(source='city', max_length=50, allow_null=True, allow_blank=True)
    sucursal = serializers.CharField(source='branch', max_length=50, allow_null=True, allow_blank=True)
    configuracion = ConfiguracionCorresponsaliaItemSerializer(source='configuration', many=True)
    usuario_paycard = serializers.CharField(source='user_paycard', max_length=50, required=False, default='',
                                            allow_null=True, allow_blank=True)
    password_paycard = serializers.CharField(source='pass_paycard', write_only=True,
                                             allow_null=True, allow_blank=True)
    emisor = serializers.CharField(source='company.volcan_issuer_id', max_length=3,
                                   allow_null=True, allow_blank=True)

    class Meta:
        model = Corresponsalia
        fields = ('id_corresponsalia','descripcion', 'pais', 'ciudad', 'sucursal',
                  'configuracion', 'usuario_paycard', 'password_paycard', 'emisor')

    def validate(self, data):
        data = dict(super(CreateCorresponsaliaSerializer, self).validate(data))
        request = self.context['request']
        user = request.user
        company = None if not self.instance else self.instance.company
        params = {} if not self.instance else self.instance.params
        configuration = data.pop('configuration',
                          params['configuration'] if 'configuration' in params else [])
        issuer_id = data.pop('emisor', None)
        user_paycard = data.get('user_paycard', '' if not self.instance else self.instance.user_paycard)
        pass_paycard = data.get('pass_paycard', None)

        if not self.instance or issuer_id:
            company = Company.objects.filter(volcan_issuer_id=issuer_id).first()

        if not company:
            raise CustomValidationError(detail={'emisor': _('Emisor no encontrado.')},
                                        code='issuer_not_found')
        has_prepaid = False
        currencies = [currency for currency in Currency.objects.values_list('number_code', flat=True).all()]
        for index,  item in enumerate(configuration):
            if 'bin' in item:
                card_bin_config = CardBinConfig.objects.filter(card_bin=item['bin'],
                                                               emisor=company.volcan_issuer_id.upper()).first()
                if not card_bin_config:
                    raise CustomValidationError(detail={
                        'configuracion': _(
                            f"El BIN {item['bin']} no esta configurado con el emisor {company.volcan_issuer_id.upper()}."
                        )},
                        code='bin_not_found')
                if card_bin_config.card_type == CardType.CT_PREPAID:
                    has_prepaid = True
                item['product'] = card_bin_config.get_card_type_display()
            else:
                raise CustomValidationError(detail={'configuracion': _(f"El BIN es requerido")},
                                            code='bin_required')

            if 'currencies' in item and len(item['currencies']) > 0:
                for currency in item['currencies']:
                    if currency not in currencies:
                        raise CustomValidationError(detail={
                            'configuracion': _(
                                f"La moneda {currency} no esta configurada en el sistema.")},
                            code='currency_not_found')
            else:
                raise CustomValidationError(detail={'monedas': _(f"Las monedas son requerida(s)")},
                                            code='currencies_required')

            if 'movement_codes' not in item or len(item['movement_codes']) == 0:
                raise CustomValidationError(detail={
                    'configuracion': _(
                        f"codigos de movimiento son requerdo")},
                    code='movement_codes_required')
            # guardamos los cambios
            configuration[index] = item

        if pass_paycard:
            params['credentials'] = Corresponsalia.generate_credentials(user_paycard, pass_paycard)

        if has_prepaid:
            if 'credentials' not in params or len(params['credentials']) == 0:
                raise CustomValidationError(detail={
                    'pass_paycard': _(f"Paycard credentials required")},
                    code='paycard_credentials_required')

        params['configuration'] = configuration
        data['params'] = params
        data['company'] = company
        return data

class CorresponsaliaCompleteSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='id')
    descripcion = serializers.CharField(source='description')
    pais = serializers.CharField(source='country')
    ciudad = serializers.CharField(source='city')
    sucursal = serializers.CharField(source='branch')
    configuracion = ConfiguracionCorresponsaliaItemSerializer(source='params.configuration', many=True)
    usuario_paycard = serializers.CharField(source='user_paycard')
    emisor = serializers.CharField(source='company.volcan_issuer_id')

    class Meta:
        model = Corresponsalia
        fields = ('id_corresponsalia', 'descripcion', 'pais', 'ciudad', 'sucursal',
                  'configuracion', 'usuario_paycard', 'emisor')
        read_only_fields = fields

class CorresponsaliaSimpleSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='id')
    descripcion = serializers.CharField(source='description')
    pais = serializers.CharField(source='country')
    ciudad = serializers.CharField(source='city')
    sucursal = serializers.CharField(source='branch')
    emisor = serializers.CharField(source='company.volcan_issuer_id')

    class Meta:
        model = Corresponsalia
        fields = ('id_corresponsalia', 'descripcion', 'pais', 'ciudad', 'sucursal', 'emisor')
        read_only_fields = fields




class TransaccionCorresponsaliaSerializer(serializers.ModelSerializer):
    id_transaccion = serializers.UUIDField(source='id')
    corresponsalia = CorresponsaliaSimpleSerializer(read_only=True)
    tarjeta = serializers.CharField(source='card_number', required=False, allow_blank=True, allow_null=True, default='')
    moneda = serializers.SerializerMethodField(read_only=True)
    codigo_movimiento = serializers.CharField(source='movement_code', required=False, allow_blank=True, allow_null=True, default='')
    importe = serializers.CharField(source='amount', required=False, allow_blank=True, allow_null=True, default='')
    referencia_numerica = serializers.CharField(source='reference', required=False, allow_blank=True, allow_null=True, default='')
    card_bin = serializers.SerializerMethodField(read_only=True)
    transacciones = serializers.SerializerMethodField(read_only=True)
    estatus = serializers.CharField(source='status')
    fecha_creacion = serializers.DateTimeField(source='created_at')

    class Meta:
        model = TransaccionCorresponsalia
        fields = ('id_transaccion', 'corresponsalia',
                  'tarjeta', 'moneda', 'codigo_movimiento', 'importe',
                  'referencia_numerica', 'card_bin', 'transacciones',
                  'estatus', 'params', 'fecha_creacion')
        read_only_fields = fields

    # def get_corresponsalia(self, instance):
    #     corresponsalia = instance.corresponsalia
    #     if corresponsalia:
    #         return {
    #             'id': str(corresponsalia.id),
    #             'descripcion': corresponsalia.description,
    #             'pais': corresponsalia.country,
    #             'ciudad': corresponsalia.city,
    #             'sucursal': corresponsalia.branch
    #         }
    #     return None

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
                'emisor': card_bin_config.emisor
            }
        return None

    def get_transacciones(self, instance):
        from .models import TransaccionCorresponsaliaCollection
        db = TransaccionCorresponsaliaCollection()
        queryset = db.find({'transaction_id': str(instance.id)}, 'created_at', 1)
        transactions_data = []
        for item in queryset:
            transactions_data.append({
                "id": str(item['_id']),
                "request_data": item['request_data'],
                "response_data": item['response_data'],
                "created_at": item['created_at']
            })
        return transactions_data


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
        # request = self.context['request']
        corresponsalia_id = data.pop('corresponsalia_id', None)
        card_number = data.get('card_number', None)
        currency_str = data.pop('currency_str', '').upper()
        movement_code = data.get('movement_code', None)
        amount = data.get('amount', None)
        reference = data.get('reference', '')
        # user = request.user

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

        if not currency:
            raise CustomValidationError(detail={'moneda': _(f'Moneda {currency_str} no identificada')},
                                        code='currency_not_found')

        is_bin_found = False
        movement_code_item = None
        for config in corresponsalia.params['configuration']:
            if config['bin'] == card_bin_config.card_bin:
                is_bin_found = True
                if currency.number_code not in config['currencies']:
                    raise CustomValidationError(
                        detail={'moneda': _('Corresponsalia no esta configurada con la moneda.')},
                        code='currency_not_found')
                for movement_item in config['movement_codes']:
                    if movement_item['code'] == movement_code:
                        movement_code_item = movement_item

                if not movement_code_item:
                    raise CustomValidationError(
                        detail={'codigo_movimiento': _('Codigo de movimiento no configurado con BIN.')},
                        code='movement_code_not_found')

        if not is_bin_found:
            raise CustomValidationError(detail={'tarjeta': _('Corresponsalia no esta configurada con el BIN.')},
                                        code='card_bin_config_not_found')

        data['corresponsalia'] = corresponsalia
        data['currency'] = currency
        # data['card_real'] = card_real
        data['card_bin_config'] = card_bin_config
        data['reference'] = code_generator(10, option='num') if len(reference) == 0 else reference
        data['params'] = {'movement_code': movement_code_item}

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



class CreateTransaccionReversoCorresponsaliaSerializer(serializers.ModelSerializer):
    id_corresponsalia = serializers.UUIDField(source='corresponsalia_id', allow_null=True)
    tarjeta = serializers.CharField(source='card_number', required=False, allow_blank=True, allow_null=True, default='')
    autorizacion = serializers.CharField(source='authorization', required=False, allow_blank=True, allow_null=True,
                                         default='')

    class Meta:
        model = TransaccionCorresponsalia
        fields = ('id_corresponsalia', 'tarjeta', 'autorizacion')

    def validate(self, data):
        data = super(CreateTransaccionReversoCorresponsaliaSerializer, self).validate(data)
        corresponsalia_id = data.pop('corresponsalia_id', None)
        card_number = data.pop('card_number', None)
        authorization = data.pop('authorization', None)

        try:
            corresponsalia = Corresponsalia.objects.get(id=corresponsalia_id)
        except Corresponsalia.DoesNotExist:
            raise CustomValidationError(detail={'id_corresponsalia': _('Corresponsalia no encontrada.')},
                                        code='corresponsalia_not_found')

        try:
            transaction_corresponsalia = TransaccionCorresponsalia.objects.get(corresponsalia=corresponsalia,
                                                                               card_number=card_number,
                                                                               authorization=authorization)
        except TransaccionCorresponsalia.DoesNotExist:
            raise CustomValidationError(detail={'autorizacion': _('Autorizacion no fue encontrada.')},
                                        code='authorization_not_found')

        if transaction_corresponsalia.status == TransaccionCorresponsaliaStatus.TCS_RETURNED:
            raise CustomValidationError(detail={'status': _('Transaccion ha sido reversada.')},
                                        code='transaction_returned')

        # Pasaron las validaciones, por lo tanto se pueden actualizar el movement_code_reverse
        # recogemos el movement_code_item
        movement_code_item = transaction_corresponsalia.params['movement_code']
        movement_code_reverse_item = None
        reverse_type = f"Reverso{movement_code_item['type']}"
        for config in corresponsalia.params['configuration']:
            if config['bin'] == transaction_corresponsalia.card_bin_config.card_bin:
                for movement_item in config['movement_codes']:
                    if movement_item['type'] == reverse_type:
                        movement_code_reverse_item = movement_item

                if not movement_code_reverse_item:
                    raise CustomValidationError(
                        detail={'movement_code_reverse': _('Codigo de movimiento para reverso no configurado en BIN.')},
                        code='movement_code_reverse_not_found')

        data['corresponsalia'] = corresponsalia
        transaction_corresponsalia.params['movement_code_reverse'] = movement_code_reverse_item
        transaction_corresponsalia.save()
        data['transaction_corresponsalia'] = transaction_corresponsalia
        return data