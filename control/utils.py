import json
import logging
from datetime import datetime

import newrelic.agent
import pytz
import requests
from django.conf import settings
from django.core.cache import cache

from common.utils import get_response_data_errors
from control.serializers import ConsultaCuentaSerializer, ConsultaTarjetaSerializer, \
    CambioPINSerializer, ExtrafinanciamientoSerializer, CambioLimitesSerializer, CambioEstatusTDCSerializer, \
    ReposicionTarjetasSerializer, CreacionEnteSerializer, GestionTransaccionesSerializer, ConsultaMovimientosSerializer, \
    IntraExtrasSerializer, ConsultaPuntosSerializer, AltaCuentaTarjetaSerializer, ConsultaIntraExtraF1Serializer, \
    ConsultaTransaccionesXFechaSerializer, ConsultaCVV2Serializer, CreacionEnteSectorizacionSerializer, \
    ConsultaEnteSerializer, ConsultaEstadoCuentaSerializer, ConsultaCobranzaSerializer, AltaPolizaSerializer, \
    ConsultaPolizaSerializer, IntraExtraEspecialSerializer, ConsultaIntraExtraEsquemaSerializer, \
    ConsultaEsquemasFinanciamientoSerializer, RefinanciamientoSerializer

logger = logging.getLogger(__name__)


def print_error_control(response_data=None, e=None):
    if e:
        error_string = e.args.__str__()
        logger.error(error_string)
    if response_data:
        logger.error(response_data)


def get_float_from_numeric_str(value: str) -> str:
    from decimal import Decimal
    try:
        length = len(value)
        is_positive = ''
        if length >= 3 and value[-1] in ["}", "-"]:
            value = value.replace("}", "")
            value = value.replace("-", "")
            length = len(value)
            is_positive = "-"
        if '.' not in value:
            assert length >= 4, "El valor no tiene el minimo de largo"
            value_s = "%s.%s" % (value[0:length - 2], value[length - 2:length])
            value_f = Decimal(value_s)
        else:
            value_f = Decimal(value)
        if value_f > Decimal('0'):
            return f'{is_positive}{value_f:04.2f}'
        else:
            return f'{is_positive}{value_f:05.2f}'
    except AssertionError:
        return value
    except TypeError:
        return ""


def mask_card(card):
    means_access = card
    if len(means_access) > 0:
        data_means_access = ''
        largo = len(means_access)
        residue = largo % 4
        separator = residue if residue > 0 else 4
        for index in range(0, largo):
            if index < (largo - 4):
                data_means_access += '*'
            else:
                data_means_access += means_access[index]
            if separator == 1:
                data_means_access += ' '
                separator = 4
            else:
                separator -= 1

        return data_means_access.strip()
    return ''


def get_volcan_api_headers():
    return {
        'Content-Type': 'application/json; charset=utf-8',
    }


@newrelic.agent.background_task()
def process_volcan_api_request(data, url, request, headers=None, times=0):
    response_data = dict()
    response_status = 0
    response_message = ''
    if not headers:
        headers = get_volcan_api_headers()
    data_json = json.dumps(data)
    logger.info(f"Request: {url}")
    logger.info(f"Request json: {data_json}")
    try:
        r = requests.post(url=url, data=data_json, headers=headers)
        response_status = r.status_code
        if 'Content-Type' in r.headers:
            if 'application/json' in r.headers['Content-Type']:
                response_data = r.json() if response_status != 204 else {}
            else:
                logger.info(f"Response headers: {r.headers}")
                response_data = r.content
        logger.info(f"Response {str(response_status)}: {response_data}")
        logger.info(f"Response encoding: {r.encoding}")

        if 200 <= response_status <= 299:
            if len(response_data) == 0:
                logger.info(f"Response: empty")
                response_data = {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}
        elif response_status == 404:
            response_data = {'RSP_CODIGO': '404', 'RSP_DESCRIPCION': 'Recurso no disponible'}
            logger.info(f"Response: 404 Recurso no disponible")
        else:
            response_data = {'RSP_CODIGO': str(response_status), 'RSP_DESCRIPCION': 'Error desconocido'}
        response_message = ''
    except requests.exceptions.Timeout:
        response_data = {'RSP_CODIGO': "408",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (Timeout)'}
        response_status = 408
        response_message = 'Error de conexion con servidor VOLCAN (Timeout)'
        print_error_control(response_data=response_data)
    except requests.exceptions.TooManyRedirects:
        response_data = {'RSP_CODIGO': "429",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (TooManyRedirects)'}
        response_status = 429
        response_message = 'Error de conexion con servidor VOLCAN (TooManyRedirects)'
        print_error_control(response_data=response_data)
    except requests.exceptions.RequestException as e:
        response_data = {'RSP_CODIGO': "400",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (RequestException)'}
        response_status = 400
        response_message = 'Error de conexion con servidor VOLCAN (RequestException)'
        print_error_control(response_data=response_data, e=e)
    except Exception as e:
        print("Error peticion")
        response_status = 500
        response_message = 'error'
        response_data = {'RSP_CODIGO': '500', 'RSP_DESCRIPCION': e.args.__str__()}
        print_error_control(response_data=response_data, e=e)
    finally:
        newrelic.agent.add_custom_attributes(
            [
                ("request.url", url),
                ("request.emisor", data['EMISOR'] if 'EMISOR' in data else ''),
                ("response.code", response_status),
                # ("response.json", response_data),
            ]
        )
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
    api_url = f'{url_server}{settings.URL_AZ7_ALTA_ENTE}'
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


def creation_ente_sectorizacion(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_ALTA_ENTE_SECTORIZACION}'
    serializer = CreacionEnteSectorizacionSerializer(data=data)
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
    api_url = f'{url_server}{settings.URL_AZ7_ALTA_CUENTA}'
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
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_CUENTA}'
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
                                is_positive = ''
                                if k2.upper() in ["RSP_TASA_INTERES", "RSP_TASA_MORA"] and length == 2:
                                    v2 = f"00{v2}" if v2.isnumeric() else v2
                                    length = len(v2)

                                if k2.upper() in ["RSP_LIMITE_CRED", "RSP_DEB_TRAN", "RSP_CRE_TRAN", "RSP_SALDO",
                                                  "RSP_DISP_EFE", "RSP_DISP_COM", "RSP_DISP_EXT", "RSP_IMP_VENC",
                                                  "RSP_PGO_MIN", "RSP_PGO_CONTADO", "RSP_SLD_PTOS",
                                                  "RSP_TASA_INTERES", "RSP_TASA_MORA"] and length >= 3:
                                    if v2[-1] in ["}", "-"]:
                                        v2 = v2.replace("}", "")
                                        v2 = v2.replace("-", "")
                                        is_positive = "-"
                                    if v2.isnumeric() or "." in v2:
                                        v2 = get_float_from_numeric_str(f"{v2}{is_positive}")
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
    api_url = f'{url_server}{settings.URL_AZ7_EXTRA_FINANCIAMIENTO}'
    serializer = ExtrafinanciamientoSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (
                    resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
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
    api_url = f'{url_server}{settings.URL_AZ7_INTRA_FINANCIAMIENTO}'
    serializer = ExtrafinanciamientoSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (
                    resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
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
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_TARJETAS}'
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
    api_url = f'{url_server}{settings.URL_AZ7_CAMBIO_PIN}'
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
    api_url = f'{url_server}{settings.URL_AZ7_CAMBIO_LIMITES}'
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
    api_url = f'{url_server}{settings.URL_AZ7_CAMBIO_ESTATUS_TDC}'
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
    api_url = f'{url_server}{settings.URL_AZ7_REPOSICION_TARJETAS}'
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
    api_url = f'{url_server}{settings.URL_AZ7_GESTION_TRANSACCIONES}'
    serializer = GestionTransaccionesSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (
                    resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
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


def consulta_ente(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTAR_ENTE}'
    serializer = ConsultaEnteSerializer(data=data)
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
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTAR_MOVIMIENTOS}'
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
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTAR_PUNTOS}'
    serializer = ConsultaPuntosSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (
                    resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
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
    api_url = f'{url_server}{settings.URL_AZ7_INTRAS_EXTRAS}'
    serializer = IntraExtrasSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (
                    resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
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
    api_url = f'{url_server}{settings.URL_AZ7_INTRAS_EXTRAS}'
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
            if resp[1]['RSP_ERROR'].upper() == 'OK' or (
                    resp[1]['RSP_CODIGO'].isnumeric() and int(resp[1]['RSP_CODIGO']) == 0):
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


def consulta_intra_extra_f1(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_INTRA_EXTRA}'
    serializer = ConsultaIntraExtraF1Serializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_MOCONF' in resp[1]:
                    cards = []
                    for card in resp[1]['RSP_MOCONF']:
                        if 'RSP_CUENTA' in card and len(card['RSP_CUENTA']) > 0:
                            data_item = {k.lower(): v for k, v in card.items()}
                            for k2, v2 in data_item.items():
                                length = len(v2)
                                is_positive = ''
                                if k2.upper() in ["RSP_TASA"] and length == 2:
                                    v2 = f"00{v2}" if v2.isnumeric() else v2
                                    length = len(v2)
                                if k2.upper() in ["RSP_IMPORTE", "RSP_TASA", "RSP_CUOTA_ACT", "RSP_CAPITAL_PAG",
                                                  "RSP_INTERES_PAG", "RSP_SLD_CAPITAL"] and length >= 3:
                                    if v2[-1] in ["}", "-"]:
                                        v2 = v2.replace("}", "")
                                        v2 = v2.replace("-", "")
                                        is_positive = "-"
                                    if v2.isnumeric() or "." in v2:
                                        v2 = get_float_from_numeric_str(f"{v2}{is_positive}")
                                        data_item[k2] = v2
                            cards.append(data_item)
                    resp[1]['RSP_MOCONF'] = cards
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


def consulta_transaciones_x_fecha(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_TRANSACCION_X_FECHA}'
    serializer = ConsultaTransaccionesXFechaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_MOCONS' in resp[1]:
                    items = []
                    for trns in resp[1]['RSP_MOCONS']:
                        if 'RSP_NUM_MOV' in trns and len(trns['RSP_NUM_MOV']) > 0:
                            data_item = {k.lower(): v for k, v in trns.items()}
                            for k2, v2 in data_item.items():
                                length = len(v2)
                                is_positive = ''
                                if k2.upper() in ["RSP_TASA_MOV", "RSP_TASA_MORA", "RSP_COD_COM"] and length == 2:
                                    v2 = f"00{v2}" if v2.isnumeric() else v2
                                    length = len(v2)
                                if k2.upper() in ["RSP_MONTO_ORIG", "RSP_TASA_MOV",
                                                  "RSP_TASA_MORA", "RSP_COD_COM"] and length >= 3:
                                    if v2[-1] in ["}", "-"]:
                                        v2 = v2.replace("}", "")
                                        v2 = v2.replace("-", "")
                                        is_positive = "-"
                                    if v2.isnumeric():
                                        v2 = get_float_from_numeric_str(f"{v2}{is_positive}")
                                        data_item[k2] = v2
                            items.append(data_item)
                    resp[1]['RSP_MOCONS'] = items
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


def consulta_cvv2(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_CVV2}'
    serializer = ConsultaCVV2Serializer(data=data)
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
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def consulta_estado_cuenta(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_ESTADO_CUENTA}'
    serializer = ConsultaEstadoCuentaSerializer(data=data)
    if serializer.is_valid():
        tz_mx = pytz.timezone('America/Mexico_City')
        now_mx = datetime.now().astimezone(tz_mx)
        cache_key = f"consulta_estado_cuenta:{now_mx.year}:{now_mx.month}:" + ":".join(
            str(value) for value in serializer.validated_data.values() if
            value is not None and len(str(value).strip()) > 0
        )
        respuesta_cacheada = cache.get(cache_key)
        if respuesta_cacheada is None:
            resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
            if 'RSP_ERROR' in resp[1] and resp[1]['RSP_ERROR'].upper() == 'OK':
                set_cache_estados_cuenta(cache_key, now_mx, resp)
        else:
            resp = respuesta_cacheada

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

def set_cache_estados_cuenta(cache_key, now_mx, resp):
    if now_mx.day in [11, 23] and now_mx.hour >= 4:
        timeout = 0  # Invalida la cache al establecer timeout a 0, forzando una nueva consulta la próxima vez.
    else:
        # Calcula el timeout hasta las 4:00 am del día 11 o 23
        proximo_dia_invalidacion = 11 if now_mx.day < 11 else (23 if now_mx.day < 23 else None)

        if proximo_dia_invalidacion:
            fecha_invalidacion = now_mx.replace(day=proximo_dia_invalidacion, hour=4, minute=0, second=0, microsecond=0)
            timeout = (fecha_invalidacion - now_mx).total_seconds()
        else:
            timeout = 86400 * 10  # 10 dias. Ajusta si es necesario.
    cache.set(cache_key, resp, timeout)
    return True



def consulta_cobranza(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_COBRANZA}'
    serializer = ConsultaCobranzaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if 'RSP_SALDOS' in resp[1]:
                    items = []
                    for balance in resp[1]['RSP_SALDOS']:
                        if 'RSP_MONEDA' in balance and len(balance['RSP_MONEDA']) > 0:
                            data_item = {k.lower(): v for k, v in balance.items()}
                            for k2, v2 in data_item.items():
                                length = len(v2)
                                is_positive = ''

                                # if k2.upper() in ["RSP_TASA_MOV", "RSP_TASA_MORA", "RSP_COD_COM"] and length == 2:
                                #     v2 = f"00{v2}" if v2.isnumeric() else v2
                                #     length = len(v2)
                                if k2.upper() not in ["RSP_MONEDA", "RSP_TASA_INTERES",
                                                      "RSP_TASA_MORA", "RSP_CANTIDAD_IV"] and length >= 3:
                                    if v2 == ".00":
                                        v2 = "0.00"
                                    if v2[-1] in ["}", "-"]:
                                        v2 = v2.replace("}", "")
                                        v2 = v2.replace("-", "")
                                        is_positive = "-"
                                    if '.' in v2 or v2.isnumeric():
                                        v2 = get_float_from_numeric_str(f"{v2}{is_positive}")
                                        data_item[k2] = v2
                            items.append(data_item)
                    resp[1]['RSP_SALDOS'] = items
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


def alta_poliza(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_ALTA_POLIZA}'
    serializer = AltaPolizaSerializer(data=data)
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
                    if k not in ['RSP_ERROR', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                        del resp_copy[k]
                return resp[0], resp_copy, resp[2]
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp


def consulta_poliza(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_POLIZA}'
    serializer = ConsultaPolizaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                for k1, v1 in resp[1].items():
                    if '.' in v1 and len(v1) == 21:
                        resp[1][k1] = get_float_from_numeric_str(v1)
                if 'RSP_POLIZAS' in resp[1]:
                    polizes = []
                    for polize in resp[1]['RSP_POLIZAS']:
                        for k2, v2 in polize.items():
                            if '.' in v2 and len(v2) == 21:
                                polize[k2] = get_float_from_numeric_str(v2)
                        if 'RSP_NUM_POL' in polize and len(polize['RSP_NUM_POL']) > 0:
                            polizes.append({k.lower(): v for k, v in polize.items()})
                    resp[1]['RSP_POLIZAS'] = polizes
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


def intra_extra_especial(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_INTRA_EXTRA_ESPECIAL}'
    serializer = IntraExtraEspecialSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                for k1, v1 in resp[1].items():
                    if '.' in v1 and len(v1) == 21:
                        resp[1][k1] = get_float_from_numeric_str(v1)
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


def consulta_intra_extra_esquema(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_INTRA_EXTRA_ESQUEMA}'
    serializer = ConsultaIntraExtraEsquemaSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                for k1, v1 in resp[1].items():
                    if '.' in v1 and len(v1) == 21:
                        resp[1][k1] = get_float_from_numeric_str(v1)
                if 'RSP_INTRACON' in resp[1]:
                    movements = []
                    for movement in resp[1]['RSP_INTRACON']:
                        for k2, v2 in movement.items():
                            if '.' in v2 and len(v2) == 21:
                                movement[k2] = get_float_from_numeric_str(v2)
                        if 'RSP_TARJETA' in movement and len(movement['RSP_TARJETA']) > 0:
                            movements.append({k.lower(): v for k, v in movement.items()})
                    resp[1]['RSP_INTRACON'] = movements
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


def consulta_esquemas_financiamiento(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_ESQUEMAS_FINANCIAMIENTO}'
    serializer = ConsultaEsquemasFinanciamientoSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                for k1, v1 in resp[1].items():
                    if '.' in v1 and len(v1) == 21:
                        resp[1][k1] = get_float_from_numeric_str(v1)
                if 'RSP_INTRACON' in resp[1]:
                    movements = []
                    for movement in resp[1]['RSP_INTRACON']:
                        for k2, v2 in movement.items():
                            if '.' in v2 and len(v2) == 21:
                                movement[k2] = get_float_from_numeric_str(v2)
                        if 'RSP_TARJETA' in movement and len(movement['RSP_TARJETA']) > 0:
                            movements.append({k.lower(): v for k, v in movement.items()})
                    resp[1]['RSP_INTRACON'] = movements
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


def refinanciamiento(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_REFINANCIAMIENTO}'
    serializer = RefinanciamientoSerializer(data=data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
        if 'RSP_ERROR' in resp[1]:
            if resp[1]['RSP_ERROR'].upper() == 'OK':
                resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
                for k1, v1 in resp[1].items():
                    if '.' in v1 and len(v1) == 21:
                        resp[1][k1] = get_float_from_numeric_str(v1)
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


def corresponsalia(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CORRESPONSALIA}'
    serializer = ConsultaPolizaSerializer(data=request_data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp
