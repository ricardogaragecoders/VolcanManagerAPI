from rest_framework import serializers
from decimal import Decimal, InvalidOperation, DecimalException
from common.exceptions import CustomValidationError


def get_decimal_from_request_data(data, field):
    try:
        s_field = data.get(field, '')
        if isinstance(s_field, str):
            if len(s_field) > 0:
                s_field = Decimal(s_field)
            else:
                s_field = Decimal('0')
        else:
            s_field = Decimal(s_field)
        return s_field
    except (InvalidOperation, DecimalException) as e:
        raise CustomValidationError(detail=f"{field}: error en conversion de valor a decimal",
                                    code='422')


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
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    PIN = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
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
                                        code='400')
        if len(pin) == 0:
            raise CustomValidationError(detail=u'El nuevo PIN es requerido',
                                        code='400')
        return data


class ExtrafinanciamientoSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    IMPORTE = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    TASA = serializers.CharField(max_length=5, required=False, default="", allow_blank=True, allow_null=True)
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
        amounts = ("%.2f" % get_decimal_from_request_data(data, 'IMPORTE')).split('.')
        taxes = ("%.2f" % get_decimal_from_request_data(data, 'TASA')).split('.')

        data['TARJETA'] = card
        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        # if not importe.isnumeric():
        #     raise CustomValidationError(detail=u'El importe no es numerico',
        #                                 code='400')
        data['TASA'] = taxes[0].zfill(2) + taxes[1].zfill(2)
        data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)
        return data


class CambioLimitesSerializer(serializers.Serializer):
    CUENTA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    LIMITE_CR = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    LIMITE_CON = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    LIMITE_EXTRA = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CUENTA', 'TARJETA', 'LIMITE_CR', 'LIMITE_CON', 'LIMITE_EXTRA', 'MONEDA', 'REFERENCIA',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CambioLimitesSerializer, self).validate(data)
        account = data.get('CUENTA', "").strip()
        card = data.get('TARJETA', "").strip()
        limits_cr = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_CR')).split('.')
        limits_con = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_CON')).split('.')
        limits_extra = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_EXTRA')).split('.')

        data['TARJETA'] = card
        data['CUENTA'] = account
        if len(card) == 0 and len(account) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta o cuenta es requerido',
                                        code='400')
        data['LIMITE_CR'] = limits_cr[0].zfill(17) + limits_cr[1].zfill(2)
        data['LIMITE_CON'] = limits_con[0].zfill(17) + limits_con[1].zfill(2)
        data['LIMITE_EXTRA'] = limits_extra[0].zfill(17) + limits_extra[1].zfill(2)
        return data


class CambioEstatusTDCSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    CUENTA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    ESTATUS = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    MOTIVO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'CUENTA', 'MOTIVO', 'REFERENCIA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CambioEstatusTDCSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        account = data.get('CUENTA', "").strip()

        data['TARJETA'] = card
        data['CUENTA'] = account
        if len(card) == 0 and len(account) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta o cuenta es requerido',
                                        code='400')
        return data


class ReposicionTarjetasSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    TIPO_USO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    TARJETA_ASIGNADA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    MOTIVO_REPO = serializers.CharField(max_length=30, required=False, default="", allow_blank=True)
    OFICINA_ENTREGA = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    NOMBRE_TARJETA = serializers.CharField(max_length=30, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'TIPO_USO', 'EMISION', 'TARJETA_ASIGNADA', 'MOTIVO_REPO', 'OFICINA_ENTREGA',
                  'NOMBRE_TARJETA', 'REFERENCIA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ReposicionTarjetasSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        card_assigned = data.get('TARJETA_ASIGNADA', "").strip()

        data['TARJETA'] = card
        data['TARJETA_ASIGNADA'] = card_assigned
        if len(card) == 0 or len(card_assigned) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta o tarjeta asignada es requerido',
                                        code='400')
        return data
