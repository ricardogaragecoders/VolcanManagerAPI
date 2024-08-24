import logging

from rest_framework.exceptions import ParseError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from common.views import CustomViewSet
from control.utils import mask_card
from thalesapi.models import CardType, CardDetail, CardBinConfig, Client
from thalesapi.serializers import GetDataTokenizationSerializer, CardBinConfigSerializer, GetVerifyCardSerializer, \
    GetDataTokenizationPaycardSerializer
from thalesapi.utils import is_card_bin_valid, get_access_token_paycard, get_credentials_paycad, \
    get_url_thales_register_customer_with_cards, get_card_bin_config, get_or_create_card_client, \
    get_card_client
from users.permissions import IsVerified, IsOperator, IsSupervisor

logger = logging.getLogger(__name__)


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

    def clear_cache(self):
        from django.core.cache import cache
        if 'cards-bin' in cache:
            cache.delete('cards-bin')
        if 'cards-bin-prepaid' in cache:
            cache.delete('cards-bin-prepaid')
        if 'cards-bin-credit' in cache:
            cache.delete('cards-bin-credit')

    def clear_cache_bin(self, card_bin):
        from django.core.cache import cache
        if card_bin in cache:
            cache.delete(card_bin)

    def perform_create(self, request, *args, **kwargs):
        super(CardBinConfigApiView, self).perform_create(request=request, *args, **kwargs)
        self.clear_cache()
        self.clear_cache_bin(self.serializer.data['card_bin'])

    def perform_update(self, request, *args, **kwargs):
        super(CardBinConfigApiView, self).perform_update(request=request, *args, **kwargs)
        self.clear_cache()
        self.clear_cache_bin(self.serializer.data['card_bin'])


class ThalesApiView(CustomViewSet):
    permission_classes = (AllowAny,)
    http_method_names = ['post', 'get', 'options', 'head']

    def control_action(self, request, control_function, *args, **kwargs):
        response_data = dict()
        response_status = 200
        try:
            response_data, response_status = control_function(request, *args, **kwargs)
        except ParseError as e:
            logger.exception(e)
            response_data = {'error': "%s" % e}
            response_status = 400
        except Exception as e:
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
        logger.info('Verify Card')
        logger.info(request_data)

        if 'cardBin' in request_data and is_card_bin_valid(request_data['cardBin']):
            # aqui revisamos si es credito o prepago
            card_bin = request_data['cardBin']
            card_bin_config = get_card_bin_config(key_cache=card_bin)
            # card_type = CardType.CT_PREPAID if card_bin in '53876436' else CardType.CT_CREDIT
            if card_bin_config['card_type'] == CardType.CT_CREDIT:
                from thalesapi.utils import post_verify_card_credit
                request_data['emisor'] = card_bin_config['emisor']
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
                if response_status == 200 and 'error' in response_data and response_data['error'] is None:
                    del response_data['error']
            code_error = response_data.pop('code_error', 0)
            card_bin = response_data.pop('cardBin', card_bin)
            card_name = response_data.pop('cardName', '')
            card_detail = response_data.pop('cardDetail', None)
            if code_error == 0 and response_status == 200:
                card_detail = card_detail if card_detail else CardDetail.objects.select_related('client').filter(
                                                                card_id=response_data['cardId']).first()
                if not card_detail:
                    card_detail, created = CardDetail.objects.get_or_create(card_id=response_data['cardId'],
                                                                            consumer_id=response_data['consumerId'],
                                                                            account_id=response_data['accountId'],
                                                                            issuer_id=issuer_id,
                                                                            card_bin=card_bin,
                                                                            card_type=card_bin_config['card_type'],
                                                                            emisor=card_bin_config['emisor'])
                client = card_detail.client if card_detail else None
                try:
                    if not client:
                        client = get_or_create_card_client(card_name=card_name, card_detail=card_detail)
                    response_data['consumerId'] = client.consumer_id
                except AssertionError as e:
                    logger.info(f"Error al crear el cliente: {e.args.__str__()}")
                    client = Client.objects.create(consumer_id=response_data['consumerId'],
                                                   card_name=card_name, type_identification='TT',
                                                   document_identification=response_data['cardId'])
                    card_detail.client = client
                    card_detail.save()
            else:
                if card_detail and card_detail.client and 'consumerId' in response_data:
                    response_data['consumerId'] = card_detail.client.consumer_id
        else:
            response_data, response_status = {'error': 'Datos incompletos'}, 400

        logger.info(f"Response Verify Card: {response_data}")
        return Response(data=response_data, status=response_status)

    def get_consumer_information(self, request, *args, **kwargs):
        consumer_id = kwargs.get('consumer_id', '')
        card_id = request.query_params.get('cardId', None)
        issuer_id = kwargs.get('issuer_id', '')
        card_detail = None
        logger.info("Get Consumer Info")
        logger.info(request.get_full_path())
        # buscar el cliente primero
        if card_id:
            card_detail = CardDetail.objects.select_related('client').filter(
                card_id=card_id, issuer_id=issuer_id).first()
            client = card_detail.client if card_detail.client else get_or_create_card_client(card_detail=card_detail)
        elif client := Client.objects.filter(consumer_id=consumer_id).first():
            card_detail = CardDetail.objects.filter(client=client).first()
        else:
            client = get_card_client(consumer_id=consumer_id)
            if client:
                card_detail = CardDetail.objects.filter(client=client, consumer_id=consumer_id).first()
            else:
                card_detail = CardDetail.objects.filter(issuer_id=issuer_id, consumer_id=consumer_id).first()

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
                                                                     card_detail=card_detail,
                                                                     client=client,
                                                                     *args, **kwargs)
                if response_status == 200 and 'error' in response_data and response_data['error'] is None:
                    del response_data['error']
        else:
            response_data, response_status = {'error': f'Registro no encontrado'}, 404

        logger.info(f"Response Consumer info: {response_data}")
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
                if response_status == 200 and 'error' in response_data and response_data['error'] is None:
                    del response_data['error']
        else:
            response_data, response_status = {'error': f'Registro no encontrado'}, 404
        logger.info(f"Response Card Credentials: {response_data}")
        return Response(data=response_data, status=response_status)

    def post_deliver_otp(self, request, *args, **kwargs):
        consumer_id = kwargs.get('consumer_id', '')
        card_id = request.query_params.get('cardId', None)
        issuer_id = kwargs.get('issuer_id', '')
        logger.info("Deliver OTP")
        logger.info(request.get_full_path())

        if card_id:
            card_detail = CardDetail.objects.filter(card_id=card_id, issuer_id=issuer_id).first()
            # client = Client.objects.filter(cards__id=card_detail.id).first()
        elif client := Client.objects.filter(consumer_id=consumer_id).first():
            card_detail = CardDetail.objects.filter(client=client).first()
        else:
            client = get_card_client(consumer_id=consumer_id)
            if client:
                card_detail = CardDetail.objects.filter(client=client, consumer_id=consumer_id).first()
            else:
                card_detail = client.cards.filter(consumer_id=consumer_id, issuer_id=issuer_id).first()

        if card_detail:
            from thalesapi.utils import post_deliver_otp
            response_data, response_status = self.control_action(request=request,
                                                                 control_function=post_deliver_otp,
                                                                 card_detail=card_detail,
                                                                 *args, **kwargs)
        else:
            response_data, response_status = {'error': f'Registro no encontrado'}, 404

        logger.info(f"Response Deliver OTP: {response_data}")
        if response_status in [201, 200, 204]:
            return Response(status=204)
        else:
            return Response(data=response_data, status=response_status)

    def post_notify_card_operation(self, request, *args, **kwargs):
        # from thalesapi.utils import get_card_credentials_credit_testing
        try:
            data = request.data.copy()
            logger.info(f"Request Notify Card: {data}")
        except Exception as e:
            logger.info(f"Error Notify Card: {e.args.__str__()}")
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

    def get_card_data_tokenization(self, request, *args, **kwargs):
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
            validated_data = serializer.validated_data.copy()
            client = validated_data.pop('client', None)
            resp_msg, resp_data, response_status = process_volcan_api_request(data=validated_data,
                                                                              url=api_url, request=request, times=0)
            if response_status == 200:
                if resp_data['RSP_ERROR'].upper() == 'OK' or len(resp_data['RSP_TARJETAID']) > 0:
                    resp_data['RSP_ERROR'] = 'OK'
                    resp_data['RSP_CODIGO'] = '0000000000'
                    resp_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if resp_data['RSP_ERROR'] == 'OK':
                    obj_data = {
                        'tarjeta': validated_data['TARJETA'],
                        'fecha_exp': validated_data['FECHA_EXP'],
                        'folio': resp_data['RSP_FOLIO'],
                        "card_id": resp_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in resp_data else '',
                        "consumer_id": resp_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in resp_data else '',
                        "account_id": resp_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in resp_data else '',
                        "issuer_id": settings.THALES_API_ISSUER_ID,
                        "card_product_id": 'D1_VOLCAN_VISA_SANDBOX',
                        "client": client,
                        "state": "ACTIVE"
                    }
                    resp = self.register_consumer_thalesapi(**obj_data)
                    if resp[1] == 200:
                        response_data = {
                            'RSP_ERROR': resp_data['RSP_ERROR'],
                            'RSP_CODIGO': resp_data['RSP_CODIGO'],
                            'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'],
                            'rsp_folio': resp_data['RSP_FOLIO'],
                            "cardId": resp_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in resp_data else '',
                            # "consumerId": resp_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in resp_data else '',
                            "consumerId": client.consumer_id,
                            "accountId": resp_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in resp_data else ''
                        }
                    else:
                        response_data = resp[0]
                        response_status = resp[1]
                        if 'error' in response_data:
                            response_data = {
                                'RSP_ERROR': 'RC',
                                'RSP_CODIGO': f"{response_status}",
                                'RSP_DESCRIPCION': response_data['error']
                            }
                            response_status = 200
                else:
                    response_data = {
                        'RSP_ERROR': resp_data['RSP_ERROR'] if resp_data['RSP_ERROR'] != '' else 'RC',
                        'RSP_CODIGO': resp_data['RSP_CODIGO'] if resp_data['RSP_CODIGO'] != '' else '400',
                        'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'] if resp_data[
                                                                               'RSP_DESCRIPCION'] != '' else 'Error en datos de origen'
                    }
        else:
            resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
            # response_data, response_status = {}, 400
        logger.info(f"Response Card Data Tokenizacion: {response_data}")
        return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)

    def get_card_data_tokenization_paycard(self, request, *args, **kwargs):
        from django.conf import settings
        from control.utils import process_volcan_api_request
        from common.utils import get_response_data_errors
        request_data = request.data.copy()
        access_token_paycard = get_access_token_paycard()
        if not access_token_paycard:
            return self.get_response(status=400, message='No fue posible hacer login a AZ7')
        self.serializer_class = GetDataTokenizationPaycardSerializer
        data = {k.upper(): v for k, v in request_data.items()}
        serializer = self.get_serializer(data=data)
        response_data = {}
        if serializer.is_valid():
            url_server = settings.SERVER_VOLCAN_PAYCARD_URL
            api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_TOKEN_TARJETA}'
            validated_data = serializer.validated_data.copy()
            client = validated_data.pop('client', None)
            card = validated_data.pop('card', request_data['tarjeta'])
            fecha_exp = validated_data.pop('FECHA_EXP', request_data['fecha_exp'])
            folio = validated_data.pop('FOLIO', '12345')
            headers = {
                'Credenciales': get_credentials_paycad(),
                'Authorization': f"{access_token_paycard}",
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            resp_msg, resp_data, response_status = process_volcan_api_request(data=validated_data, headers=headers,
                                                                              url=api_url, request=request, times=0)
            if response_status == 200:
                if resp_data['CodRespuesta'] == '0000' or len(resp_data['CardID']) > 0:
                    resp_data['RSP_ERROR'] = 'OK'
                    resp_data['RSP_CODIGO'] = '0000000000'
                    resp_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
                if resp_data['RSP_ERROR'] == 'OK':
                    obj_data = {
                        'tarjeta': card,
                        'fecha_exp': fecha_exp,
                        'folio': folio,
                        "card_id": resp_data['CardID'] if 'CardID' in resp_data else '',
                        "consumer_id": resp_data['ConsumerID'] if 'ConsumerID' in resp_data else '',
                        "account_id": resp_data['AccountID'] if 'AccountID' in resp_data else '',
                        "issuer_id": settings.THALES_API_ISSUER_ID,
                        "card_product_id": 'D1_VOLCAN_VISA_SANDBOX',
                        "client": client,
                        "state": "ACTIVE"
                    }
                    resp = self.register_consumer_thalesapi(**obj_data)
                    if resp[1] == 200:
                        response_data = {
                            'RSP_ERROR': 'OK',
                            'RSP_CODIGO': '00000000',
                            'RSP_DESCRIPCION': 'Transaccion aprobada',
                            'rsp_folio': folio,
                            "cardId": resp_data['CardID'] if 'CardID' in resp_data else '',
                            # "consumerId": resp_data['ConsumerID'] if 'ConsumerID' in resp_data else '',
                            "consumerId": client.consumer_id,
                            "accountId": resp_data['AccountID'] if 'AccountID' in resp_data else ''
                        }
                    else:
                        response_data = resp[0]
                        response_status = resp[1]
                        if 'error' in response_data:
                            response_data = {
                                'RSP_ERROR': 'RC',
                                'RSP_CODIGO': f"{response_status}",
                                'RSP_DESCRIPCION': response_data['error']
                            }
                            response_status = 200
                else:
                    response_data = {
                        'RSP_ERROR': resp_data['RSP_ERROR'] if resp_data['RSP_ERROR'] != '' else 'RC',
                        'RSP_CODIGO': resp_data['RSP_CODIGO'] if resp_data['RSP_CODIGO'] != '' else '400',
                        'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'] if resp_data[
                                                                               'RSP_DESCRIPCION'] != '' else 'Error en datos de origen'
                    }
        else:
            resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
            # response_data, response_status = {}, 400
        logger.info(f"Response Card Data Tokenizacion: {response_data}")
        return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)

    def get_authorization_token(self, folio=None, issuer_id=None):
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
        if settings.DEBUG:
            logger.debug(f'Data to Auth: {auth_data}')
        else:
            logger.info(f"AUD https://{settings.THALES_API_AUD}")

        with open(settings.PRIV_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pem_file:
            private_key = pem_file.read()
        with open(settings.PUB_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pem_file:
            public_key = pem_file.read()
        if private_key:
            headers = {
                "alg": "ES256",
                "typ": "JWT",
                "kid": settings.THALES_API_ENCRYPTED_K06_AUTH_KID
            }
            jwt_token = jwt.encode(payload=auth_data, key=private_key, algorithm="ES256", headers=headers)

        if public_key and jwt_token:
            decoded = jwt.decode(jwt=jwt_token, key=public_key, algorithms=["ES256"],
                                 audience=f"https://{settings.THALES_API_AUD}", issuer=issuer_id)
            if settings.DEBUG:
                logger.debug(f"Descifrar: {decoded}")
            else:
                logger.info(f"Descifrar: Ok")

        if jwt_token:
            payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token
            }
            headers = {
                "x-correlation-id": folio if folio else '12345',
                # "Prefer": "code=200",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            # cert = None
            cert = (settings.SSL_CERTIFICATE_THALES_CRT, settings.SSL_CERTIFICATE_THALES_KEY)
            resp_data, resp_status = process_volcan_api_request(data=payload, url=url, headers=headers, cert=cert)
            if resp_status == 200:
                return resp_data['access_token'] if 'access_token' in resp_data else None
        return None

    def register_consumer_thalesapi(self, *args, **kwargs):
        from .utils import process_volcan_api_request
        from jwcrypto import jwk, jwe
        from thalesapi.utils import get_card_triple_des_process
        import json
        from django.conf import settings
        card_bin_config = None
        resp_status = 400
        tarjeta = kwargs.get('tarjeta', '')
        fecha_exp = kwargs.get('fecha_exp', '0000')
        folio = kwargs.get('folio', '123456789')
        issuer_id = kwargs.get('issuer_id', settings.THALES_API_ISSUER_ID)
        card_product_id = kwargs.get('card_product_id', 'D1_VOLCAN_VISA_SANDBOX')
        card_id = kwargs.get('card_id', '')
        account_id = kwargs.get('account_id', '')
        consumer_id = kwargs.get('consumer_id', '')
        client = kwargs.get('client', None)
        identification = kwargs.get('identification', '')
        find_card_bin_configuration = kwargs.get('find_card_bin_configuration', True)

        if not client:
            client = get_card_client(identification=identification)

        if settings.DEBUG:
            logger.debug(f"Register Consumer Data: {kwargs}")
        else:
            logger.info(f'Register Consumer Data: {{"tarjeta": "{tarjeta}", "folio": "{folio}"}}')

        card_real = get_card_triple_des_process(tarjeta, is_descript=True)
        if not card_real:
            logger.warning(f'Tarjeta: {kwargs.get("tarjeta", "")} no pudo ser desincriptada')
            return None
        if find_card_bin_configuration:
            card_bin_config = CardBinConfig.objects.filter(card_bin=str(card_real[0:8])).first()
            if card_bin_config:
                if settings.DEBUG:
                    logger.debug(f"CardBinConfig --> {card_bin_config}")
                else:
                    logger.info(
                        f"CardBinConfig --> {str(card_bin_config.id)} {card_bin_config.card_type} {card_bin_config.emisor}")
                issuer_id = card_bin_config.issuer_id
                card_product_id = card_bin_config.card_product_id
        card_exp = fecha_exp[2:4] + fecha_exp[0:2]

        encrypted_data = {
            "pan": card_real,
            "exp": card_exp
        }
        encrypted_data = json.dumps(encrypted_data)
        if settings.DEBUG:
            logger.debug(f'EncryptedData: {encrypted_data}')
        else:
            logger.info(f'EncryptedData: {{"pan": "{mask_card(card_real)}", "exp": "{card_exp}"}}')

        access_token = self.get_authorization_token(folio=folio, issuer_id=issuer_id)
        # return {'access_token': access_token}, 200

        if access_token:
            url = get_url_thales_register_customer_with_cards(issuer_id=issuer_id, consumer_id=client.consumer_id)

            public_key = None
            payload = {}
            with open(settings.PUB_KEY_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pem_file:
                public_key = jwk.JWK.from_pem(pem_file.read())
            if public_key:
                protected_header_back = {
                    "alg": "ECDH-ES",
                    "enc": "A256GCM",
                    "kid": settings.THALES_API_ENCRYPTED_K01_KID
                }
                jwe_token = jwe.JWE(encrypted_data.encode('utf-8'),
                                    recipient=public_key, protected=protected_header_back)
                enc = jwe_token.serialize(compact=True)

                payload = {
                    "cards": [{
                        "cardId": card_id,
                        "accountId": account_id,
                        "cardProductId": card_product_id,
                        "state": kwargs.get('state', 'ACTIVE'),
                        "encryptedData": enc
                    }]
                }
            headers = {
                "x-correlation-id": folio,
                # "Prefer": "",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}"
            }
            # cert = None
            cert = (settings.SSL_CERTIFICATE_THALES_CRT, settings.SSL_CERTIFICATE_THALES_KEY)
            resp_data, resp_status = process_volcan_api_request(data=payload, url=url, headers=headers,
                                                                method='PUT', cert=cert)
            if resp_status == 204:
                if card_bin_config:
                    card_bin_config = CardBinConfig.objects.filter(card_bin=str(card_real[0:8])).first()
                try:
                    if not card_bin_config:
                        card_bin = card_real[0:8]
                        card_type = 'credit'
                        issuer = 'CMF'
                    else:
                        card_bin = card_bin_config.card_bin
                        card_type = card_bin_config.card_type
                        issuer = card_bin_config.emisor
                    card_detail = CardDetail.objects.filter(card_id=card_id).first()
                    if not card_detail:
                        card_detail = CardDetail.objects.create(card_id=card_id, consumer_id=consumer_id,
                                                                account_id=account_id, issuer_id=issuer_id,
                                                                card_bin=card_bin, card_type=card_type, emisor=issuer)
                    if client:
                        card_detail.client = client
                        card_detail.save()
                except Exception as e:
                    logger.error("Error al registrar card_detail")
                    logger.error(e.args.__str__())
                return resp_data, 200
            else:
                return resp_data, resp_status
        return {"error": "Error in authorization"}, 400


class ThalesV2ApiViewPrivate(ThalesApiViewPrivate):
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    serializer_class = GetVerifyCardSerializer

    def post_register_consumer_cards(self, request, *args, **kwargs):
        from common.utils import get_response_data_errors
        request_data = request.data.copy()
        data = {k.upper(): v for k, v in request_data.items()}
        serializer = self.get_serializer(data=data)
        response_data = {}
        response_status = 200
        resp_msg = ''
        if serializer.is_valid():
            validated_data = serializer.validated_data.copy()
            client = validated_data.pop('client', None)
            response_data['RSP_ERROR'] = 'OK'
            response_data['RSP_CODIGO'] = '0000000000'
            response_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
            obj_data = {
                'tarjeta': validated_data['TARJETA'],
                'fecha_exp': validated_data['FECHA_EXP'],
                'folio': validated_data['FOLIO'],
                "card_id": validated_data['TARJETAID'],
                "consumer_id": validated_data['CLIENTEID'],
                "account_id": validated_data['CUENTAID'],
                "issuer_id": validated_data['ISSUER_ID'],
                "card_product_id": validated_data['CARD_PRODUCT_ID'],
                "state": validated_data['STATE'],
                'client': client,
                "find_card_bin_configuration": True
            }
            resp = self.register_consumer_thalesapi(**obj_data)
            if resp[1] == 200:
                response_data = {
                    'rsp_folio': validated_data['FOLIO']
                }
            else:
                response_data = resp[0]
            response_status = resp[1]
        else:
            resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
        return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)
