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
                s_field = ""
        else:
            s_field = Decimal(s_field)
        return s_field
    except (InvalidOperation, DecimalException) as e:
        raise CustomValidationError(detail=f"{field}: error en conversion de valor a decimal",
                                    code='422')


class CreacionEnteSerializer(serializers.Serializer):
    CIF = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    PERSONERIA = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOCUMENTO_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PRIMER_NOMBRE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    SEGUNDO_NOMBRE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    PRIMER_APELLIDO = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    SEGUNDO_APELLIDO = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    APELLIDO_CASADA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    FECHA_NACIMIENTO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    SEXO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    ESTADO_CIVIL = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    PROFESION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    SEGURO_SOCIAL = serializers.CharField(max_length=25, required=False, default="", allow_blank=True)
    PAIS_NACIMIENTO = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    PAIS_RESIDENCIA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    NACIONALIDAD = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_PROVINCIA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_CANTON = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    CODIGO_DISTRITO = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    DIRECCION_1 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CODIGO_POSTAL = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    TELEFONO_CASA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    CELULAR = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    TELEFONO_OFICINA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMAIL_PERSONAL = serializers.CharField(max_length=100, required=False, default="", allow_blank=True)
    EMAIL_OFICINA = serializers.CharField(max_length=100, required=False, default="", allow_blank=True)
    LUGAR_TRABAJO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    DIRECCION_1_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    PUESTO = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    INGRESO_MENSUAL = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    FECHA_INGRESO_TRABAJO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    OFICINA_EXT = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    NOMBRE_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    CEDULA_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_PADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_PADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_MADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_MADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    TIPO_GESTION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CIF', 'PERSONERIA', 'TIPO_IDENTIFICACION', 'DOCUMENTO_IDENTIFICACION',
                  'PRIMER_NOMBRE', 'SEGUNDO_NOMBRE', 'PRIMER_APELLIDO', 'SEGUNDO_APELLIDO', 'APELLIDO_CASADA',
                  'FECHA_NACIMIENTO', 'SEXO', 'ESTADO_CIVIL', 'PROFESION', 'SEGURO_SOCIAL', 'PAIS_NACIMIENTO',
                  'PAIS_RESIDENCIA', 'NACIONALIDAD', 'CODIGO_PROVINCIA', 'CODIGO_CANTON', 'CODIGO_DISTRITO',
                  'DIRECCION_1', 'DIRECCION_2', 'CODIGO_POSTAL', 'TELEFONO_CASA', 'CELULAR', 'TELEFONO_OFICINA',
                  'EMAIL_PERSONAL', 'EMAIL_OFICINA', 'LUGAR_TRABAJO', 'DIRECCION_1_TRABAJO', 'DIRECCION_2_TRABAJO',
                  'PUESTO', 'INGRESO_MENSUAL', 'FECHA_INGRESO_TRABAJO', 'OFICINA_EXT', 'NOMBRE_CONYUGUE',
                  'APELLIDO_CONYUGUE', 'CEDULA_CONYUGUE', 'NOMBRE_PADRE', 'APELLIDO_PADRE', 'NOMBRE_MADRE',
                  'APELLIDO_MADRE', 'TIPO_GESTION', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')


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
        amount = get_decimal_from_request_data(data, 'IMPORTE')
        tax = get_decimal_from_request_data(data, 'TASA')
        if isinstance(amount, Decimal):
            amounts = ("%.2f" % amount ).split('.')
            data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)

        if isinstance(tax, Decimal):
            taxes = ("%.2f" % tax).split('.')
            data['TASA'] = taxes[0].zfill(2) + taxes[1].zfill(2)

        data['TARJETA'] = card

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        # if not importe.isnumeric():
        #     raise CustomValidationError(detail=u'El importe no es numerico',
        #                                 code='400')
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
        limite_cr = get_decimal_from_request_data(data, 'LIMITE_CR')
        limite_con = get_decimal_from_request_data(data, 'LIMITE_CON')
        limite_extra = get_decimal_from_request_data(data, 'LIMITE_EXTRA')

        if isinstance(limite_cr, Decimal):
            limits_cr = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_CR')).split('.')
            data['LIMITE_CR'] = limits_cr[0].zfill(17) + limits_cr[1].zfill(2)

        if isinstance(limite_con, Decimal):
            limits_con = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_CON')).split('.')
            data['LIMITE_CON'] = limits_con[0].zfill(17) + limits_con[1].zfill(2)

        if isinstance(limite_extra, Decimal):
            limits_extra = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_EXTRA')).split('.')
            data['LIMITE_EXTRA'] = limits_extra[0].zfill(17) + limits_extra[1].zfill(2)

        data['TARJETA'] = card
        data['CUENTA'] = account

        if len(card) == 0 and len(account) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta o cuenta es requerido',
                                        code='400')
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
        # card_assigned = data.get('TARJETA_ASIGNADA', "").strip()

        data['TARJETA'] = card
        # data['TARJETA_ASIGNADA'] = card_assigned
        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        return data


class GestionTransaccionesSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    TRANSACCION = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    IMPORTE = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    FECHA_TRX = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    HORA_TRX = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    CVV2 = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    FECVENTO = serializers.CharField(max_length=4, required=False, default="", allow_blank=True)
    CHEQUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PLAZA = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    NO_FINANCIAMIENTO = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    DOC_OPER = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    AUTORIZACION = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    COMERCIO = serializers.CharField(max_length=24, required=False, default="", allow_blank=True)
    CIUDAD = serializers.CharField(max_length=13, required=False, default="", allow_blank=True)
    PAIS = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    SUCURSAL = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'TRANSACCION', 'IMPORTE', 'MONEDA', 'FECHA_TRX', 'HORA_TRX', 'CVV2', 'FECVENTO',
                  'CHEQUE', 'PLAZA', 'NO_FINANCIAMIENTO', 'REFERENCIA', 'DOC_OPER', 'AUTORIZACION',
                  'COMERCIO', 'CIUDAD', 'PAIS', 'SUCURSAL', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(GestionTransaccionesSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()

        amount = get_decimal_from_request_data(data, 'IMPORTE')

        if isinstance(amount, Decimal):
            amounts = ("%.2f" % amount ).split('.')
            data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        # if not importe.isnumeric():
        #     raise CustomValidationError(detail=u'El importe no es numerico',
        #                                 code='400')

        data['TARJETA'] = card

        return data
