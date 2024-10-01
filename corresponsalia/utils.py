import json
import logging

import newrelic.agent
import requests

from control.utils import get_volcan_api_headers

logger = logging.getLogger(__name__)


@newrelic.agent.background_task()
def process_az7_api_request(data, url, request=None, headers=None, method='POST', cert=None, times=0):
    response_data = {}
    response_status = 0
    response = None
    headers = headers or get_volcan_api_headers()
    data_json = json.dumps(data, indent=4) if isinstance(data, dict) else data
    try:
        response = requests.request(method=method, url=url, headers=headers, data=data_json, cert=cert)
        response_status = response.status_code

        if response.headers.get('Content-Type', '').startswith('application/json'):
            response_data = response.json() if response_status != 204 else {}
        else:
            response_data = response.content

        if response_status in [200, 201, 204]:
            if not response_data:
                response_data = {'RSP_CODIGO': '400',
                                 'RSP_DESCRIPCION': 'Respuesta sin datos, posible error en datos de origen'}
        else:
            if response_status == 404:
                response_data = {'RSP_CODIGO': '404', 'RSP_DESCRIPCION': 'Recurso no disponible'}
            else:
                response_data = {'RSP_CODIGO': str(response_status), 'RSP_DESCRIPCION': 'Error desconocido'}

    except requests.exceptions.Timeout:
        response_data = {'RSP_CODIGO': "408", 'RSP_DESCRIPCION': 'Error de conexión (Timeout)'}
        response_status = 408
    except requests.exceptions.TooManyRedirects:
        response_data = {'RSP_CODIGO': "429", 'RSP_DESCRIPCION': 'Demasiadas redirecciones'}
        response_status = 429
    except requests.exceptions.RequestException as e:
        response_data = {'RSP_CODIGO': "400", 'RSP_DESCRIPCION': 'Error de conexión'}
        response_status = 400
        logger.error(f"RequestException: {e}")
    except Exception as e:
        response_status = 500
        s_exception = str(e)
        response_data = {'RSP_CODIGO': '500', 'RSP_DESCRIPCION': s_exception}
        logger.error(f"Unexpected error: {s_exception}")
    finally:
        # Registro de detalles de la solicitud y respuesta
        logger.info(f"Request URL: {url}")
        logger.info(f"Request payload: {data_json}")
        if response:
            logger.info(f"Response headers: {response.headers}")
            logger.info(f"Response status: {response_status}")
            logger.info(f"Response data: {response_data}")
            logger.info(f"Response encoding: {response.encoding}")

        # Registrar atributos personalizados en NewRelic
        newrelic.agent.add_custom_attributes([
            ("request.url", url),
            ("request.emisor", data.get('EMISOR', '')),
            ("response.code", response_status),
        ])

        return response_data, response_status

@newrelic.agent.background_task()
def process_parabilia_api_request(data, url, request=None, headers=None, method='POST', cert=None, times=0):
    response_data = {}
    response_status = 0
    response = None
    headers = headers or get_volcan_api_headers()
    data_json = json.dumps(data, indent=4) if isinstance(data, dict) else data
    try:
        response = requests.request(method=method, url=url, headers=headers, data=data_json, cert=cert)
        response_status = response.status_code

        if response.headers.get('Content-Type', '').startswith('application/json'):
            response_data = response.json() if response_status != 204 else {}
        else:
            response_data = response.content

        if response_status in [200, 201, 204]:
            if not response_data:
                response_data = {'CodRespuesta': '400',
                                 'DescRespuesta': 'Respuesta sin datos, posible error en datos de origen'}
        else:
            if response_status == 404:
                response_data = {'CodRespuesta': '404', 'DescRespuesta': 'Recurso no disponible'}
            else:
                response_data = {'CodRespuesta': str(response_status), 'DescRespuesta': 'Error desconocido'}

    except requests.exceptions.Timeout:
        response_data = {'CodRespuesta': "408", 'DescRespuesta': 'Error de conexión (Timeout)'}
        response_status = 408
    except requests.exceptions.TooManyRedirects:
        response_data = {'CodRespuesta': "429", 'DescRespuesta': 'Demasiadas redirecciones'}
        response_status = 429
    except requests.exceptions.RequestException as e:
        response_data = {'CodRespuesta': "400", 'DescRespuesta': 'Error de conexión'}
        response_status = 400
        logger.error(f"RequestException: {e}")
    except Exception as e:
        response_status = 500
        s_exception = str(e)
        response_data = {'CodRespuesta': '500', 'DescRespuesta': s_exception}
        logger.error(f"Unexpected error: {s_exception}")
    finally:
        # Registro de detalles de la solicitud y respuesta
        logger.info(f"Request URL: {url}")
        logger.info(f"Request payload: {data_json}")
        if response:
            logger.info(f"Response headers: {response.headers}")
            logger.info(f"Response status: {response_status}")
            logger.info(f"Response data: {response_data}")
            logger.info(f"Response encoding: {response.encoding}")

        # Registrar atributos personalizados en NewRelic
        newrelic.agent.add_custom_attributes([
            ("request.url", url),
            ("request.emisor", data.get('EMISOR', '')),
            ("response.code", response_status),
        ])

        return response_data, response_status