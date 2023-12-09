from rest_framework.exceptions import ParseError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from common.views import CustomViewSet
from thalesapi.models import CardType, CardDetail, CardBinConfig
from thalesapi.serializers import GetDataTokenizationSerializer, CardBinConfigSerializer
from thalesapi.utils import is_card_bin_valid
from users.permissions import IsVerified, IsOperator, IsSupervisor
from volcanmanagerapi import settings


class CardBinConfigApiView(CustomViewSet):
    """
    get:
        Return all CardBinConfig
    post:
        Create a new CardBinConfig
    update:
        Update a CardBinConfig
    """
    serializer_class = CardBinConfigSerializer
    model_class = CardBinConfig
    permission_classes = (IsAuthenticated, IsVerified, IsSupervisor)
    field_pk = 'card_bin_config_id'


# Create your views here.
class ThalesApiView(CustomViewSet):
    permission_classes = (AllowAny,)
    http_method_names = ['post', 'get', 'options', 'head']

    def control_action(self, request, control_function, *args, **kwargs):
        response_data = dict()
        response_status = 200
        try:
            response_data, response_status = control_function(request, *args, **kwargs)
        except ParseError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)
            response_data = {'error': "%s" % e}
            response_status = 400
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)
            response_data = {'error': f"Error en aplicación: {e.args.__str__()}"}
            response_status = 500
        finally:
            return response_data, response_status

    def post_verify_card(self, request, *args, **kwargs):
        issuer_id = kwargs.get('issuer_id', '')
        if 'request_data' not in kwargs:
            request_data = request.data.copy()
        else:
            request_data = kwargs['request_data'].copy()
        print('Verify Card')
        print(request_data)

        if 'cardBin' in request_data and is_card_bin_valid(request_data['cardBin']):
            # aqui revisamos si es credito o prepago
            card_bin = request_data['cardBin']
            card_type = CardType.CT_PREPAID if card_bin in '53876436' else CardType.CT_CREDIT
            if card_type == CardType.CT_CREDIT:
                from thalesapi.utils import post_verify_card_credit
                response_data, response_status = self.control_action(request=request,
                                                                     control_function=post_verify_card_credit,
                                                                     request_data=request_data,
                                                                     *args, **kwargs)
            else:
                from thalesapi.utils import post_verify_card_prepaid
                response_data, response_status = self.control_action(request=request,
                                                                     control_function=post_verify_card_prepaid,
                                                                     request_data=request_data,
                                                                     *args, **kwargs)
            if response_status == 200:
                CardDetail.objects.get_or_create(consumer_id=response_data['consumerId'],
                                                 card_id=response_data['cardId'],
                                                 issuer_id=issuer_id,
                                                 account_id=response_data['accountId'],
                                                 card_bin=card_bin,
                                                 card_type=card_type)
        else:
            response_data, response_status = {'error': 'Datos incompletos'}, 400
        return Response(data=response_data, status=response_status)

    def get_consumer_information(self, request, *args, **kwargs):
        consumer_id = kwargs.get('consumer_id', '')
        card_id = request.query_params.get('cardId', None)
        issuer_id = kwargs.get('issuer_id', '')
        print("Get Consumer Info")
        print(request.get_full_path())
        if not card_id:
            card_detail = CardDetail.objects.filter(consumer_id=consumer_id, issuer_id=issuer_id).first()
        else:
            card_detail = CardDetail.objects.filter(consumer_id=consumer_id, card_id=card_id,
                                                    issuer_id=issuer_id).first()
        if card_detail:
            if card_detail.card_type == CardType.CT_CREDIT:
                from thalesapi.utils import get_consumer_information_credit
                response_data, response_status = self.control_action(request=request,
                                                                     control_function=get_consumer_information_credit,
                                                                     card_detail=card_detail,
                                                                     *args, **kwargs)
            else:
                from thalesapi.utils import get_consumer_information_prepaid
                response_data, response_status = self.control_action(request=request,
                                                                     control_function=get_consumer_information_prepaid,
                                                                     *args, **kwargs)
        else:
            response_data, response_status = {'error': f'Registro no encontrado'}, 404
        return Response(data=response_data, status=response_status)

    def get_card_credentials(self, request, *args, **kwargs):
        card_id = kwargs.get('card_id', '')
        issuer_id = kwargs.get('issuer_id', '')
        card_detail = CardDetail.objects.filter(card_id=card_id, issuer_id=issuer_id).first()
        if card_detail:
            if card_detail.card_type == CardType.CT_CREDIT:
                from thalesapi.utils import get_card_credentials_credit
                response_data, response_status = self.control_action(request=request,
                                                                     control_function=get_card_credentials_credit,
                                                                     card_detail=card_detail,
                                                                     *args, **kwargs)
            else:
                from thalesapi.utils import get_card_credentials_prepaid
                response_data, response_status = self.control_action(request=request,
                                                                     control_function=get_card_credentials_prepaid,
                                                                     *args, **kwargs)
        else:
            response_data, response_status = {'error': f'Registro no encontrado'}, 404
        return Response(data=response_data, status=response_status)

    def post_notify_card_operation(self, request, *args, **kwargs):
        # from thalesapi.utils import get_card_credentials_credit_testing

        return Response(status=204)

    def get_card_credentials_testing(self, request, *args, **kwargs):
        from thalesapi.utils import get_card_credentials_credit_testing
        response_data, response_status = self.control_action(request=request,
                                                             control_function=get_card_credentials_credit_testing,
                                                             *args, **kwargs)
        return Response(data=response_data, status=response_status)


class ThalesApiViewPrivate(ThalesApiView):
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    serializer_class = GetDataTokenizationSerializer

    def get_card_data_tokenization_v1(self, request, *args, **kwargs):
        from django.conf import settings
        from control.utils import process_volcan_api_request
        from common.utils import get_response_data_errors
        request_data = request.data.copy()
        request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
        request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
        data = {k.upper(): v for k, v in request_data.items()}
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            url_server = settings.SERVER_VOLCAN_AZ7_URL
            api_url = f'{url_server}{settings.URL_THALES_API_VERIFY_CARD}'
            resp_msg, response_data, response_status = process_volcan_api_request(data=serializer.validated_data,
                                                                                  url=api_url, request=request, times=0)
            if response_status == 200:
                if response_data['RSP_ERROR'].upper() == 'OK' or len(response_data['RSP_TARJETAID']) > 0:
                    response_data['RSP_ERROR'] = 'OK'
                    response_data['RSP_CODIGO'] = '0000000000'
                    response_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
                data = {
                    'RSP_ERROR': response_data['RSP_ERROR'],
                    'RSP_CODIGO': response_data['RSP_CODIGO'],
                    'RSP_DESCRIPCION': response_data['RSP_DESCRIPCION'],
                    'rsp_folio': response_data['RSP_FOLIO'],
                    "cardId": response_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in response_data else '',
                    "consumerId": response_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in response_data else '',
                    "accountId": response_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in response_data else ''
                }
                response_data = data
        else:
            resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
            response_data, response_status = {}, 400
        return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)

    def get_card_data_tokenization_v2(self, request, *args, **kwargs):
        from django.conf import settings
        from control.utils import process_volcan_api_request
        from common.utils import get_response_data_errors
        request_data = request.data.copy()
        request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
        request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
        data = {k.upper(): v for k, v in request_data.items()}
        serializer = self.get_serializer(data=data)
        response_data = {}
        if serializer.is_valid():
            url_server = settings.SERVER_VOLCAN_AZ7_URL
            api_url = f'{url_server}{settings.URL_THALES_API_VERIFY_CARD}'
            validated_data = serializer.validated_data
            resp_msg, resp_data, response_status = process_volcan_api_request(data=validated_data,
                                                                              url=api_url, request=request, times=0)
            if response_status == 200:
                if resp_data['RSP_ERROR'].upper() == 'OK' or len(resp_data['RSP_TARJETAID']) > 0:
                    resp_data['RSP_ERROR'] = 'OK'
                    resp_data['RSP_CODIGO'] = '0000000000'
                    resp_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if resp_data['RSP_ERROR'] == 'OK':
                    resp = self.register_consumer_thalesapi(response_data=resp_data, validated_data=validated_data)
                    if resp[1] == 200:
                        response_data = {
                            'RSP_ERROR': resp_data['RSP_ERROR'],
                            'RSP_CODIGO': resp_data['RSP_CODIGO'],
                            'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'],
                            'rsp_folio': resp_data['RSP_FOLIO'],
                            "cardId": resp_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in resp_data else '',
                            "consumerId": resp_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in resp_data else '',
                            "accountId": resp_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in resp_data else ''
                        }
                    else:
                        response_data = resp[0]
                        response_status = resp[1]
                else:
                    response_data = {
                        'RSP_ERROR': resp_data['RSP_ERROR'],
                        'RSP_CODIGO': resp_data['RSP_CODIGO'],
                        'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION']
                    }
        else:
            resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
            # response_data, response_status = {}, 400
        return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)

    def get_url_thales_register_customer_with_cards(self, issuer_id, consumer_id):
        url = settings.URL_THALES_REGISTER_CONSUMER_CARDS
        url = url.replace('{issuerId}', issuer_id)
        url = url.replace('{consumerId}', consumer_id)
        return url

    def get_authorization_token(self, response_data=None, issuer_id=None):
        from .utils import process_volcan_api_request
        from django.conf import settings
        from datetime import datetime, timedelta
        import jwt
        if not issuer_id:
            issuer_id = settings.THALES_API_ISSUER_ID
        jwt_token = None
        url = settings.URL_THALES_AUTHORIZATION_TOKEN

        auth_data = {
            "iss": issuer_id,
            "sub": issuer_id,
            "exp": int((datetime.utcnow() + timedelta(minutes=15)).timestamp()),
            "aud": f"https://{settings.THALES_API_AUD}"
        }

        print(f'Data to Auth: {auth_data}')

        with open(settings.PRIV_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pemfile:
            private_key = pemfile.read()
        with open(settings.PUB_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pemfile:
            public_key = pemfile.read()
        if private_key:
            headers = {
                "alg": "ES256",
                "typ": "JWT",
                "kid": settings.THALESAPI_ENCRYPTED_K06_AUTH_KID
            }
            jwt_token = jwt.encode(payload=auth_data, key=private_key, algorithm="ES256", headers=headers)

        if public_key and jwt_token:
            decoded = jwt.decode(jwt=jwt_token, key=public_key, algorithms=["ES256"],
                                 audience=f"https://{settings.THALES_API_AUD}", issuer=issuer_id)
            print(f"Descifrar: {decoded}")

        if jwt_token:
            payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token
            }
            headers = {
                "x-correlation-id": response_data['RSP_FOLIO'] if response_data else '12345',
                # "Prefer": "code=200",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            cert = (settings.SSL_CERTIFICATE_THALES_CRT, settings.SSL_CERTIFICATE_THALES_KEY)
            resp_data, resp_status = process_volcan_api_request(data=payload, url=url, headers=headers, cert=cert)
            if resp_status == 200:
                return resp_data['access_token'] if 'access_token' in resp_data else None
        return None

    def register_consumer_thalesapi(self, response_data={}, validated_data={}):
        from .utils import process_volcan_api_request
        from jwcrypto import jwk, jwe
        from thalesapi.utils import get_card_triple_des_process
        import json
        from django.conf import settings
        resp_status = 400

        card_real = get_card_triple_des_process(validated_data['TARJETA'], is_descript=True)
        card_bin_config = CardBinConfig.objects.filter(card_bin=str(card_real[0:8])).first()
        if card_bin_config:
            print(f"CardBinConfig --> {card_bin_config}")
        issuer_id = settings.THALES_API_ISSUER_ID if not card_bin_config else card_bin_config.issuer_id
        card_product_id = 'D1_VOLCAN_VISA_SANDBOX' if not card_bin_config else card_bin_config.card_product_id
        if not card_real:
            return None
        card_exp = validated_data['FECHA_EXP'][2:4] + validated_data['FECHA_EXP'][0:2]
        encrypted_data = {
            "pan": card_real,
            "exp": card_exp
        }
        encrypted_data = json.dumps(encrypted_data)
        print(f'EncryptedData: {encrypted_data}')

        access_token = self.get_authorization_token(response_data=response_data, issuer_id=issuer_id)
        # return {'access_token': access_token}, 200

        if access_token:
            url = self.get_url_thales_register_customer_with_cards(issuer_id=issuer_id,
                                                                   consumer_id=response_data['RSP_CLIENTEID'])

            public_key = None
            payload = {}
            with open(settings.PUB_KEY_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pemfile:
                public_key = jwk.JWK.from_pem(pemfile.read())
            if public_key:
                protected_header_back = {
                    "alg": "ECDH-ES",
                    "enc": "A256GCM",
                    "kid": settings.THALESAPI_ENCRYPTED_K01_KID
                }
                jwe_token = jwe.JWE(encrypted_data.encode('utf-8'),
                                    recipient=public_key, protected=protected_header_back)
                enc = jwe_token.serialize(compact=True)

                payload = {
                    "cards": [{
                        "cardId": response_data['RSP_TARJETAID'],
                        "accountId": response_data['RSP_CUENTAID'],
                        "cardProductId": card_product_id,
                        "state": "INACTIVE",
                        "encryptedData": enc
                    }]
                }
            headers = {
                "x-correlation-id": response_data['RSP_FOLIO'] if response_data else '12345',
                # "Prefer": "",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}"
            }
            cert = (settings.SSL_CERTIFICATE_THALES_CRT, settings.SSL_CERTIFICATE_THALES_KEY)
            resp_data, resp_status = process_volcan_api_request(data=payload, url=url, headers=headers, method='PUT', cert=cert)
            if resp_status == 204:
                return resp_data, 200
            else:
                return resp_data, resp_status
        return None, 400
