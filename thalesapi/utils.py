import json
import requests
from django.conf import settings

from common.utils import get_response_data_errors
from control.utils import get_volcan_api_headers
from thalesapi.serializers import VerifyCardCreditSerializer


def get_str_from_date_az7(s_date):
    if len(s_date) >= 8:
        return f"{s_date[0:4]}-{s_date[4:6]}-{s_date[6:8]}"
    else:
        return s_date


def is_card_bin_valid(card_bin):
    return card_bin in ['53876436', '53139427', '53139435', '53139497', '53582937']


def get_thales_api_headers(request=None):
    return request.headers


def process_prepaid_api_request(data, url, request, http_verb='POST'):
    response_data = dict()
    response_status = 500
    headers = get_thales_api_headers(request)
    if settings.DEBUG:
        print(f"Request: {url}")
        print(f"Headers: {request.headers}")
        print(f"Data json: {data}")
    try:
        if http_verb == 'POST':
            r = requests.post(url=url, data=data, headers=headers)
        else:
            r = requests.get(url=url, headers=headers)
        response_status = r.status_code
        if 200 <= response_status <= 299:
            response_data = r.json()
            if len(response_data) == 0:
                print(f"Response: empty")
                response_data = {'error': 'Error en datos de origen'}
            else:
                print(f"Response: {response_data}")
        elif response_status == 404:
            response_data = {'error': 'Recurso no disponible'}
            print(f"Response: 404 Recurso no disponible")
        else:
            response_data = {'error': 'Error desconocido'}
            print(f"Response: {str(response_status)} Error desconocido")
            print(f"Data server: {str(r.text)}")
    except requests.exceptions.Timeout:
        response_data, response_status = {'error': 'Error de conexion con servidor VOLCAN (Timeout)'}, 408
        print(response_data)
    except requests.exceptions.TooManyRedirects:
        response_data, response_status = {'error': 'Error de conexion con servidor VOLCAN (TooManyRedirects)'}, 429
        print(response_data)
    except requests.exceptions.RequestException as e:
        response_data, response_status = {'error': 'Error de conexion con servidor VOLCAN (RequestException)'}, 400
        print(response_data)
    except Exception as e:
        response_data, response_status = {'error': e.args.__str__()}, 500
        print(response_data)
    finally:
        return response_data, response_status


def process_volcan_api_request(data, url, request, times=0):
    response_data = dict()
    response_status = 500
    headers = get_volcan_api_headers()
    data_json = json.dumps(data)
    if settings.DEBUG:
        print(f"Request: {url}")
        print(f"Headers: {request.headers}")
        print(f"Data json: {data_json}")
    try:
        r = requests.post(url=url, data=data_json, headers=headers)
        response_status = r.status_code
        if 200 <= response_status <= 299:
            response_data = r.json()
            if len(response_data) == 0:
                print(f"Response: empty")
                response_data = {'error': 'Error en datos de origen'}
            else:
                print(f"Response: {response_data}")
        elif response_status == 404:
            response_data = {'error': 'Recurso no disponible'}
            print(f"Response: 404 Recurso no disponible")
        else:
            response_data = {'error': 'Error desconocido'}
            print(f"Response: {str(response_status)} Error desconocido")
            print(f"Data server: {str(r.text)}")
    except requests.exceptions.Timeout:
        response_data, response_status = {'error': 'Error de conexion con servidor VOLCAN (Timeout)'}, 408
        print(response_data)
    except requests.exceptions.TooManyRedirects:
        response_data, response_status = {'error': 'Error de conexion con servidor VOLCAN (TooManyRedirects)'}, 429
        print(response_data)
    except requests.exceptions.RequestException as e:
        response_data, response_status = {'error': 'Error de conexion con servidor VOLCAN (RequestException)'}, 400
        print(response_data)
    except Exception as e:
        response_data, response_status = {'error': e.args.__str__()}, 500
        print(response_data)
    finally:
        return response_data, response_status


def post_verify_card_credit(request, *args, **kwargs):
    response_data = dict()
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    url_server = settings.SERVER_VOLCAN_URL
    api_url = f'{url_server}/web/services/Thales_Verify_Card'
    serializer = VerifyCardCreditSerializer(data=request_data)
    if serializer.is_valid():
        response_data, response_status = process_volcan_api_request(data=serializer.validated_data,
                                                                    url=api_url, request=request)
        # aqui falta hacer el proceso para cambiar la respuesta como la necesita Thales
        if response_status == 200:
            if 'RSP_ERROR' in response_data and response_data['RSP_ERROR'].upper() == 'OK':
                data = {
                    "cardId": response_data['cardId'] if 'cardId' in response_data else '',
                    "consumerId": response_data['consumerId'] if 'consumerId' in response_data else '',
                    "accountId": response_data['accountId'] if 'accountId' in response_data else '',
                    "verificationResults": {
                        "securityCode": {
                            "valid": ('valid_cvv' in response_data and response_data['valid_cvv'] == 'OK'),
                            "verificationAttemptsExceeded": (
                                    'num_attemps' in response_data and response_data['num_attemps'] != 'OK')
                        },
                        "card": {
                            "lostOrStolen": ('lost_stolen' in response_data and response_data['lost_stolen'] != 'OK'),
                            "expired": ('expired' in response_data and response_data['expired'] != 'OK'),
                            "invalid": ('invalid' in response_data and response_data['invalid'] != 'OK'),
                            "fraudSuspect": False
                        }
                    }
                }
                response_data = data
            else:
                response_status = 400
                response_data = {'error': response_data['RSP_DESCRIPCION']}
    else:
        response_message, response_data, response_status = get_response_data_errors(serializer.errors)
        response_data, response_status = {'error': response_message}, 400
    return response_data, response_status


def post_verify_card_prepaid(request, *args, **kwargs):
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    url_server = settings.SERVER_VOLCAN_URL
    api_url = f'{url_server}/web/services/Prepaid_Verify_Card'
    response_data, response_status = process_prepaid_api_request(data=request_data, url=api_url, request=request)
    return response_data, response_status


def get_consumer_information_credit(request, *args, **kwargs):
    card_detail = kwargs.get('card_detail')
    url_server = settings.SERVER_VOLCAN_URL
    api_url = f'{url_server}/web/services/Thales_Get_Consumer_Info'
    data = {'cardId': card_detail.card_id, 'consumerId': card_detail.consumer_id}
    response_data, response_status = process_volcan_api_request(data=data, url=api_url, request=request)
    if response_status == 200:
        if 'RSP_ERROR' in response_data and response_data['RSP_ERROR'].upper() == 'OK':
            data = {
                "language": "en-US",
                "firstName": response_data['firstName'] if 'firstName' in response_data else '',
                "middleName": response_data['middleName'] if 'middleName' in response_data else '',
                "lastName": response_data['lastName'] if 'lastName' in response_data else '',
                "dateOfBirth": get_str_from_date_az7(
                    response_data['dateOfBirth']) if 'dateOfBirth' in response_data else '',
                "title": "Mr.",
                "email": response_data['email'] if 'email' in response_data else '',
                "mobilePhoneNumber": {
                    "countryCode": "+507",
                    "phoneNumber": response_data['mobilePhoneNumber'] if 'mobilePhoneNumber' in response_data else ''
                },
                "residencyAddress": {
                    "line1": response_data['line_1'] if 'line_1' in response_data else '',
                    "line2": response_data['line_2'] if 'line_2' in response_data else '',
                    "city": response_data['city'] if 'city' in response_data else '',
                    "state": response_data['state'] if 'state' in response_data else '',
                    "zipCode": response_data['zipCode'] if 'zipCode' in response_data else '',
                    "countryCode": "PA"
                }
            }
            response_data = data
        else:
            response_status = 400
            response_data = {'error': response_data['RSP_DESCRIPCION']}
    return response_data, response_status


def get_consumer_information_prepaid(request, *args, **kwargs):
    url_server = settings.SERVER_VOLCAN_URL
    api_url = f'{url_server}/web/services/Prepaid_Get_Consumer_Info'
    response_data, response_status = process_prepaid_api_request(data=dict(), url=api_url,
                                                                 request=request, http_verb='GET')
    return response_data, response_status


def get_card_credentials_credit(request, *args, **kwargs):
    card_detail = kwargs.get('card_detail')
    url_server = settings.SERVER_VOLCAN_URL
    api_url = f'{url_server}/web/services/Thales_Get_Card_Credentials'
    data = {'cardId': card_detail.card_id, 'consumerId': card_detail.consumer_id}
    response_data, response_status = process_volcan_api_request(data=data, url=api_url, request=request)
    if response_status == 200:
        if 'RSP_ERROR' in response_data and response_data['RSP_ERROR'].upper() == 'OK':
            # falta el proceso de encriptacion para Thales
            data = {
                "pan": response_data['pan'] if 'pan' in response_data else '',
                "exp": response_data['exp'] if 'exp' in response_data else '',
                "name": response_data['name'] if 'name' in response_data else '',
                "cvv": response_data['cvv'] if 'cvv' in response_data else ''
            }
            response_data = {'encryptedData': data}
        else:
            response_status = 400
            response_data = {'error': response_data['RSP_DESCRIPCION']}
    return response_data, response_status


def get_card_credentials_prepaid(request, *args, **kwargs):
    url_server = settings.SERVER_VOLCAN_URL
    api_url = f'{url_server}/web/services/Prepaid_Get_Card_Credentials'
    response_data, response_status = process_prepaid_api_request(data=dict(), url=api_url,
                                                                 request=request, http_verb='GET')
    return response_data, response_status
