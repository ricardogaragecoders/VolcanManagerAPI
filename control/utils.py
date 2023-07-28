import json
import requests
from django.conf import settings

from common.utils import get_response_data_errors
from control.serializers import ConsultaCuentaSerializer


def get_volcan_api_headers():
    return {
        'Content-Type': 'application/json'
    }


def process_volcan_api_request(data, url, request, times=0):
    headers = get_volcan_api_headers()
    if settings.DEBUG:
        print(data)
        print(url)
    try:
        r = requests.post(url=url, data=json.dumps(data), headers=headers)
        response_status = r.status_code
        if 200 <= response_status <= 299:
            response_data = r.json()
            if len(response_data) == 0:
                response_data = {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}
            else:
                print(response_data)
        elif response_status == 404:
            response_data = {'RSP_CODIGO': '404', 'RSP_DESCRIPCION': 'Recurso no disponible'}
        else:
            print(r.text)
            response_data = {'RSP_CODIGO': str(response_status), 'RSP_DESCRIPCION': 'Error desconocido'}
        response_message = ''
    except requests.exceptions.Timeout:
        response_data = {'RSP_CODIGO': "408",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (Timeout)'}
        response_status = 408
        response_message = 'Error de conexion con servidor VOLCAN (Timeout)'
    except requests.exceptions.TooManyRedirects:
        response_data = {'RSP_CODIGO': "429",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (TooManyRedirects)'}
        response_status = 429
        response_message = 'Error de conexion con servidor VOLCAN (TooManyRedirects)'
    except requests.exceptions.RequestException as e:
        response_data = {'RSP_CODIGO': "400",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (RequestException)'}
        response_status = 400
        response_message = 'Error de conexion con servidor VOLCAN (RequestException)'
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
        request_data = request.data
    else:
        request_data = kwargs['request_data']
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_URL
    api_url = url_server + '/web/services/Alta_Ente_1'
    resp = process_volcan_api_request(data=data, url=api_url, request=request, times=times)
    if 'RSP_ERROR' in resp[1] and resp[1]['RSP_ERROR'].upper() == 'OK':
        resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
    return resp


def creation_cta_tar(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data
    else:
        request_data = kwargs['request_data']
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_URL
    api_url = url_server + '/web/services/Alta_Cuenta_1'
    resp = process_volcan_api_request(data=data, url=api_url, request=request, times=times)
    if 'RSP_ERROR' in resp[1]:
        if resp[1]['RSP_ERROR'].upper() == 'OK':
            resp[1]['RSP_DESCRIPCION'] = u'Transacción aprobada'
        elif 'RSP_TARJETA' in resp[1]:
            del resp[1]['RSP_TARJETA']
    return resp


def consulta_cuenta(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data
    else:
        request_data = kwargs['request_data']
    request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    data = {k.upper(): v for k, v in request_data.items()}
    url_server = settings.SERVER_VOLCAN_URL
    api_url = url_server + '/web/services/Consulta_Cuenta_1'
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
                            accounts.append({k.lower(): v for k, v in account.items()})
                    resp[1]['RSP_CUENTAS'] = accounts
            else:
                resp = dict(resp)
                resp[1] = {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp
