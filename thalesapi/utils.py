import json
import requests
from django.conf import settings

from common.utils import get_response_data_errors
from control.utils import get_volcan_api_headers
from thalesapi.serializers import VerifyCardCreditSerializer, GetConsumerInfoSerializer, GetDataCredentialsSerializer


def get_str_from_date_az7(s_date):
    if len(s_date) >= 8:
        return f"{s_date[0:4]}-{s_date[4:6]}-{s_date[6:8]}"
    else:
        return s_date


def is_card_bin_valid(card_bin):
    return card_bin in ['53876436', '53139427', '53139435', '53139497', '53582937']


def get_thales_api_headers(request=None):
    if request and request.headers:
        x_correlation_id = request.headers['X-Correlation-Id'] if 'X-Correlation-Id' in request.headers else ''
    else:
        x_correlation_id = ''

    return {
        'X-Correlation-Id': x_correlation_id,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


def get_value_by_default(value, default=''):
    if len(value) > 0:
        return value
    else:
        return default


def get_card_triple_des_process(card_data, is_descript=False):
    try:
        from Crypto.Cipher import DES3

        key = bytes.fromhex(settings.AZ7_SECRET_KEY)
        des3 = DES3.new(key, DES3.MODE_ECB)

        if not is_descript:
            card = bytes.fromhex(card_data)
            enc_bytes = des3.encrypt(card)
            enc_buf = ''.join(["%02X" % x for x in enc_bytes]).strip()
            return str(enc_buf)
        else:
            card_az7 = bytes.fromhex(card_data)
            enc_bytes = des3.decrypt(card_az7)
            enc_buf = ''.join(["%02X" % x for x in enc_bytes]).strip()
            return str(enc_buf)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.exception(e)
        return None


def process_prepaid_api_request(data, url, request, http_verb='POST'):
    response_data = dict()
    response_status = 500
    headers = get_thales_api_headers(request)
    print(f"Request: {url}")
    print(f"Headers: {headers}")
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
    print(f"Request: {url}")
    print(f"Headers: {headers}")
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
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/VerifyCard_1'
    serializer = VerifyCardCreditSerializer(data=request_data)
    if serializer.is_valid():
        response_data, response_status = process_volcan_api_request(data=serializer.validated_data,
                                                                    url=api_url, request=request)
        # aqui falta hacer el proceso para cambiar la respuesta como la necesita Thales
        if response_status == 200:
            if 'RSP_ERROR' in response_data and response_data['RSP_ERROR'].upper() == 'OK':
                data = {
                    "cardId": response_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in response_data else '',
                    "consumerId": response_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in response_data else '',
                    "accountId": response_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in response_data else '',
                    "verificationResults": {
                        "securityCode": {
                            "valid": ('RSP_VALID_CVV' in response_data and response_data['RSP_VALID_CVV'] == '1'),
                            "verificationAttemptsExceeded": (
                                    'RSP_NUM_ATTEMPS' in response_data and response_data['RSP_NUM_ATTEMPS'] != '0')
                        },
                        "card": {
                            "lostOrStolen": (
                                    'RSP_LOST_STOLEN' in response_data and response_data['RSP_LOST_STOLEN'] != '1'),
                            "expired": ('RSP_EXPIRADA' in response_data and response_data['RSP_EXPIRADA'] != '1'),
                            "invalid": ('RSP_TAR_VALID' in response_data and response_data['RSP_TAR_VALID'] != '1'),
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
    url_server = settings.SERVER_VOLCAN_PAYCARD_URL
    api_url = f'{url_server}{request.path}'
    data_json = json.dumps(request_data)
    response_data, response_status = process_prepaid_api_request(data=data_json, url=api_url, request=request)
    return response_data, response_status


def get_consumer_information_credit(request, *args, **kwargs):
    card_detail = kwargs.get('card_detail')
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/Volcan_GetConsumer_1'
    data = {'cardId': card_detail.card_id, 'consumerId': card_detail.consumer_id}
    serializer = GetConsumerInfoSerializer(data=data)
    if serializer.is_valid():
        response_data, response_status = process_volcan_api_request(data=serializer.validated_data, url=api_url,
                                                                    request=request)
        if response_status == 200:
            if 'RSP_ERROR' in response_data and response_data['RSP_ERROR'].upper() == 'OK':
                city = get_value_by_default(response_data['RSP_CIUDAD'], default=u'Panamá') if 'RSP_CIUDAD' in response_data else u'Panamá'
                state = get_value_by_default(response_data['RSP_ESTADO'], default=u'Panamá') if 'RSP_ESTADO' in response_data else u'Panamá'
                zip_code = get_value_by_default(response_data['RSP_CPOSTAL'], default='7215') if 'RSP_CPOSTAL' in response_data else '7215'
                data = {
                    "language": "en-US",
                    "firstName": response_data['RSP_NOMBRE1'] if 'RSP_NOMBRE1' in response_data else '',
                    "middleName": response_data['RSP_NOMBRE2'] if 'RSP_NOMBRE2' in response_data else '',
                    "lastName": response_data['RSP_APELLIDO1'] if 'RSP_APELLIDO1' in response_data else '',
                    "dateOfBirth": get_str_from_date_az7(
                        response_data['RSP_FECHA_NAC']) if 'RSP_FECHA_NAC' in response_data else '',
                    "title": "Mr.",
                    "email": response_data['RSP_MAIL'] if 'RSP_MAIL' in response_data else '',
                    "mobilePhoneNumber": {
                        "countryCode": "+507",
                        "phoneNumber": response_data['RSP_TELEFONO'] if 'RSP_TELEFONO' in response_data else ''
                    },
                    "residencyAddress": {
                        "line1": response_data['RSP_DIRECCION1'] if 'RSP_DIRECCION1' in response_data else '',
                        "line2": response_data['RSP_DIRECCION2'] if 'RSP_DIRECCION2' in response_data else '',
                        "city": city,
                        "state": state,
                        "zipCode": zip_code,
                        "countryCode": "PA"
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


def get_consumer_information_prepaid(request, *args, **kwargs):
    url_server = settings.SERVER_VOLCAN_PAYCARD_URL
    api_url = f'{url_server}{request.get_full_path()}'
    response_data, response_status = process_prepaid_api_request(data=dict(), url=api_url,
                                                                 request=request, http_verb='GET')
    return response_data, response_status


def get_card_credentials_credit(request, *args, **kwargs):
    card_detail = kwargs.get('card_detail')
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}/web/services/GetCardCredentials_1'
    data = {'cardId': card_detail.card_id, 'consumerId': card_detail.consumer_id}
    serializer = GetDataCredentialsSerializer(data=data)
    if serializer.is_valid():
        response_data, response_status = process_volcan_api_request(data=serializer.validated_data, url=api_url,
                                                                    request=request)
        if response_status == 200:
            if 'RSP_ERROR' in response_data and response_data['RSP_ERROR'].upper() == 'OK':
                from jwcrypto import jwk, jwe
                payload = {
                    "pan": response_data['RSP_TARJETA'] if 'RSP_TARJETA' in response_data else '',
                    "exp": response_data['RSP_VENCIMIENTO'] if 'RSP_VENCIMIENTO' in response_data else '',
                    "name": response_data['RSP_NOMBRE'] if 'RSP_NOMBRE' in response_data else '',
                    "cvv": response_data['RSP_CVV'] if 'RSP_CVV' in response_data else ''
                }

                card_real = get_card_triple_des_process(payload['pan'], is_descript=True)
                if card_real:
                    payload['pan'] = card_real
                    payload = json.dumps(payload)
                    print(payload)
                    public_key = None
                    with open(settings.PUB_KEY_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pemfile:
                        public_key = jwk.JWK.from_pem(pemfile.read())
                    if public_key:
                        protected_header_back = {
                            "alg": "ECDH-ES",
                            "enc": "A256GCM",
                            "kid": settings.THALESAPI_ENCRYPTED_K01_KID
                        }
                        jwetoken = jwe.JWE(payload.encode('utf-8'), recipient=public_key,
                                           protected=protected_header_back)
                        enc = jwetoken.serialize(compact=True)
                        response_data = {'encryptedData': enc}
                else:
                    response_status = 400
                    response_data = {'error': 'Error en proceso de desincriptacion triple des'}
            else:
                response_status = 400
                response_data = {'error': response_data['RSP_DESCRIPCION']}
    else:
        response_message, response_data, response_status = get_response_data_errors(serializer.errors)
        response_data, response_status = {'error': response_message}, 400
    return response_data, response_status


def get_card_credentials_credit_testing(request, *args, **kwargs):
    response_data = request.data
    from jwcrypto import jwk, jwe
    payload = {
        "pan": response_data['RSP_TARJETA'] if 'RSP_TARJETA' in response_data else '',
        "exp": response_data['RSP_VENCIMIENTO'] if 'RSP_VENCIMIENTO' in response_data else '',
        "name": response_data['RSP_NOMBRE'] if 'RSP_NOMBRE' in response_data else '',
        "cvv": response_data['RSP_CVV'] if 'RSP_CVV' in response_data else ''
    }
    card_real = get_card_triple_des_process(payload['pan'], is_descript=True)
    if card_real:
        payload['pan'] = card_real
        payload = json.dumps(payload)
        print(payload)
        public_key = None
        with open(settings.PUB_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM, "rb") as pemfile:
            public_key = jwk.JWK.from_pem(pemfile.read())
        if public_key:
            protected_header_back = {
                "alg": "ECDH-ES",
                "enc": "A256GCM"
            }
            jwetoken = jwe.JWE(payload.encode('utf-8'), recipient=public_key, protected=protected_header_back)
            enc = jwetoken.serialize(compact=True)
            response_data = {'encryptedData': enc}
        return response_data, 200
    else:
        response_status = 400
        response_data = {'error': 'Error en proceso de desincriptacion triple des'}
        return response_data, response_status


def get_card_credentials_prepaid(request, *args, **kwargs):
    url_server = settings.SERVER_VOLCAN_PAYCARD_URL
    api_url = f'{url_server}{request.path}'
    response_data, response_status = process_prepaid_api_request(data=dict(), url=api_url,
                                                                 request=request, http_verb='GET')
    return response_data, response_status
