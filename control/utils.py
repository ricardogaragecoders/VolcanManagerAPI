import json
import requests
from django.conf import settings
import logging
from common.utils import get_response_data_errors
from control.serializers import ConsultaCuentaSerializer, ConsultaTarjetaSerializer, \
    CambioPINSerializer, ExtrafinanciamientoSerializer, CambioLimitesSerializer, CambioEstatusTDCSerializer, \
    ReposicionTarjetasSerializer, CreacionEnteSerializer, GestionTransaccionesSerializer, ConsultaMovimientosSerializer, \
    IntraExtrasSerializer, ConsultaPuntosSerializer, AltaCuentaTarjetaSerializer

logger = logging.getLogger(__name__)


def get_float_from_numeric_str(value: str) -> str:
    from decimal import Decimal
    try:
        length = len(value)
        assert length >= 4, "El valor no tiene el minimo de largo"
        if '.' not in value:
            value_s = "%s.%s" % (value[0:length-2], value[length-2:length])
            value_f = Decimal(value_s)
        else:
            value_f = Decimal(value)
        if value_f > Decimal('0'):
            return '%04.2f' % value_f
        else:
            return '%05.2f' % value_f
    except AssertionError:
        return value
    except TypeError:
        return ""


def get_volcan_api_headers():
    return {
        'Content-Type': 'application/json'
    }


def process_volcan_api_request(data, url, request, times=0):
    headers = get_volcan_api_headers()
    data_json = json.dumps(data)
    print(f"Request: {url}")
    print(f"Data json: {data_json}")
    try:
        r = requests.post(url=url, data=data_json, headers=headers)
        response_status = r.status_code
        if 200 <= response_status <= 299:
            response_data = r.json()
            if len(response_data) == 0:
                print(f"Response: empty")
                response_data = {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}
            else:
                print(f"Response: {response_data}")
        elif response_status == 404:
            response_data = {'RSP_CODIGO': '404', 'RSP_DESCRIPCION': 'Recurso no disponible'}
            print(f"Response: 404 Recurso no disponible")
        else:
            response_data = {'RSP_CODIGO': str(response_status), 'RSP_DESCRIPCION': 'Error desconocido'}
            print(f"Response: {str(response_status)} Error desconocido")
            print(f"Data server: {str(r.text)}")
        response_message = ''
    except requests.exceptions.Timeout:
        response_data = {'RSP_CODIGO': "408",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (Timeout)'}
        response_status = 408
        response_message = 'Error de conexion con servidor VOLCAN (Timeout)'
        print(response_message)
    except requests.exceptions.TooManyRedirects:
        response_data = {'RSP_CODIGO': "429",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (TooManyRedirects)'}
        response_status = 429
        response_message = 'Error de conexion con servidor VOLCAN (TooManyRedirects)'
        print(response_message)
    except requests.exceptions.RequestException as e:
        response_data = {'RSP_CODIGO': "400",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (RequestException)'}
        response_status = 400
        response_message = 'Error de conexion con servidor VOLCAN (RequestException)'
        print(response_message)
    except Exception as e:
        print("Error peticion")
        print(e.args.__str__())
        response_status = 500
        response_message = 'error'
        response_data = {'RSP_CODIGO': '500', 'RSP_DESCRIPCION': e.args.__str__()}

    return response_message, response_data, response_status


def creation_ente(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Alta_Ente_1'
    serializer = CreacionEnteSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION', 'RSP_ENTEID']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def creation_cta_tar(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_Alta_Cuenta_1'
    serializer = AltaCuentaTarjetaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION', 'RSP_CUENTA']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def consulta_cuenta(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_Consulta_Cuenta_1'
    serializer = ConsultaCuentaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_CUENTAS' in resp[1]:
                    accounts = []
                    for account in resp[1]['RSP_CUENTAS']:
                        if 'RSP_CUENTA' in account and len(account['RSP_CUENTA']) > 0:
                            data_item = {k.lower(): v for k, v in account.items()}
                            for k2, v2 in data_item.items():
                                length = len(v2)
                                if (length == 4 or length == 19) and v2.isnumeric():
                                    v2 = get_float_from_numeric_str(v2)
                                    data_item[k2] = v2
                            accounts.append(data_item)
                    resp[1]['RSP_CUENTAS'] = accounts
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def extrafinanciamientos(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Extrafinanciamiento_1'
    serializer = ExtrafinanciamientoSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_IMPORTE' in resp[1]:
                    resp[1]['RSP_IMPORTE'] = get_float_from_numeric_str(resp[1]['RSP_IMPORTE'])
                if 'RSP_CUOTA' in resp[1]:
                    resp[1]['RSP_CUOTA'] = get_float_from_numeric_str(resp[1]['RSP_CUOTA'])
                if 'RSP_TASA' in resp[1]:
                    resp[1]['RSP_TASA'] = get_float_from_numeric_str(resp[1]['RSP_TASA'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def intrafinanciamientos(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Intrafinanciamiento_1'
    serializer = ExtrafinanciamientoSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_IMPORTE' in resp[1]:
                    resp[1]['RSP_IMPORTE'] = get_float_from_numeric_str(resp[1]['RSP_IMPORTE'])
                if 'RSP_CUOTA' in resp[1]:
                    resp[1]['RSP_CUOTA'] = get_float_from_numeric_str(resp[1]['RSP_CUOTA'])
                if 'RSP_TASA' in resp[1]:
                    resp[1]['RSP_TASA'] = get_float_from_numeric_str(resp[1]['RSP_TASA'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def consulta_tarjetas(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Consulta_Tarjetas_1'
    serializer = ConsultaTarjetaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_TARJETAS' in resp[1]:
                    cards = []
                    for card in resp[1]['RSP_TARJETAS']:
                        if 'RSP_TARJETA' in card and len(card['RSP_TARJETA']) > 0:
                            cards.append({k.lower(): v for k, v in card.items()})
                    resp[1]['RSP_TARJETAS'] = cards
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def cambio_pin(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Cambio_PIN_1'
    serializer = CambioPINSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' and int(resp[1]['RSP_CODIGO']) == 0:
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def cambio_limites(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Cambio_limites_1'
    serializer = CambioLimitesSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' and int(resp[1]['RSP_CODIGO']) == 0:
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_LIMITE_CR' in resp[1]:
                    resp[1]['RSP_LIMITE_CR'] = get_float_from_numeric_str(resp[1]['RSP_LIMITE_CR'])
                if 'RSP_LIMITE_CON' in resp[1]:
                    resp[1]['RSP_LIMITE_CON'] = get_float_from_numeric_str(resp[1]['RSP_LIMITE_CON'])
                if 'RSP_LIMITE_EXTRA' in resp[1]:
                    resp[1]['RSP_LIMITE_EXTRA'] = get_float_from_numeric_str(resp[1]['RSP_LIMITE_EXTRA'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def cambio_estatus_tdc(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Cambio_estatus_TDC_1'
    serializer = CambioEstatusTDCSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' and int(resp[1]['RSP_CODIGO']) == 0:
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def reposicion_tarjetas(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Reposicion_Tarjetas_1'
    serializer = ReposicionTarjetasSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' and int(resp[1]['RSP_CODIGO']) == 0:
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def gestion_transacciones(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_GestionTrx_1'
    serializer = GestionTransaccionesSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_IMPORTE' in resp[1]:
                    resp[1]['RSP_IMPORTE'] = get_float_from_numeric_str(resp[1]['RSP_IMPORTE'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def consulta_movimientos(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_ConsultaMov_1'
    serializer = ConsultaMovimientosSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                for k1, v1 in resp[1].items():
                    if '.' in v1 and len(v1) == 21:
                        resp[1][k1] = get_float_from_numeric_str(v1)
                if 'RSP_WSMOVIMIENTOS' in resp[1]:
                    movements = []
                    for movement in resp[1]['RSP_WSMOVIMIENTOS']:
                        for k2, v2 in movement.items():
                            if '.' in v2 and len(v2) == 21:
                                movement[k2] = get_float_from_numeric_str(v2)
                        if 'RSP_NUM_TARJETA' in movement and len(movement['RSP_NUM_TARJETA']) > 0:
                            movements.append({k.lower(): v for k, v in movement.items()})
                    resp[1]['RSP_WSMOVIMIENTOS'] = movements
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def consulta_puntos(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_ConsultaPuntos_1'
    serializer = ConsultaPuntosSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_SALDO_PUNTOS' in resp[1]:
                    resp[1]['RSP_SALDO_PUNTOS'] = get_float_from_numeric_str(resp[1]['RSP_SALDO_PUNTOS'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def intra_extras(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_Intra_Extras'
    serializer = IntraExtrasSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_IMPORTE' in resp[1]:
                    resp[1]['RSP_IMPORTE'] = get_float_from_numeric_str(resp[1]['RSP_IMPORTE'])
                if 'RSP_TASA' in resp[1]:
                    resp[1]['RSP_TASA'] = get_float_from_numeric_str(resp[1]['RSP_TASA'])
                if 'RSP_COUTA' in resp[1]:
                    resp[1]['RSP_COUTA'] = get_float_from_numeric_str(resp[1]['RSP_COUTA'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def intra_extras_mock(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_Intra_Extras'
    serializer = IntraExtrasSerializer(data=data)
    if serializer.is_valid():
        data = serializer.validated_data
        resp = ['', {}, 200]
        resp[1] = {
            'RSP_ERROR': 'OK',
            'RSP_CODIGO': '0000000',
            'RSP_DESCRIPCION': 'Aprobado',
            'RSP_CUENTA': '',
            'RSP_TARJETA': data.get('TARJETA'),
            'RSP_IMPORTE': data.get('IMPORTE'),
            'RSP_PLAN': data.get('CODIGO_PLAN'),
            'RSP_TASA': '2400',
            'RSP_PLAZO': data.get('PLAZO'),
            'RSP_CUOTA': '0000000000000000100',
            'RSP_DISPONIBLE': '',
            'RSP_MONEDA': data.get('MONEDA'),
            'RSP_REFERENCIA': data.get('REFERENCIA'),
            'RSP_AUTORIZ': '',
            'RSP_NOEXTRA': '',
            'RSP_CUENTA_IBAN': '',
            'RSP_NOMBRE_DEL_TH': '',
            'RSP_VENDEDOR': data.get('VENDEDOR'),
        }

        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_IMPORTE' in resp[1]:
                    resp[1]['RSP_IMPORTE'] = get_float_from_numeric_str(resp[1]['RSP_IMPORTE'])
                if 'RSP_TASA' in resp[1]:
                    resp[1]['RSP_TASA'] = get_float_from_numeric_str(resp[1]['RSP_TASA'])
                if 'RSP_COUTA' in resp[1]:
                    resp[1]['RSP_COUTA'] = get_float_from_numeric_str(resp[1]['RSP_COUTA'])
            elif resp[1]['RSP_ERROR'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}, resp[2]
            elif len(resp[1]['RSP_ERROR']) > 0 and resp[1]['RSP_CODIGO'] == '':
                return resp[0], {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Transaccion erronea'}, resp[2]
            else:
                resp_copy = resp[1].copy()
                for k in resp[1].keys():
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp
