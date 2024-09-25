import logging
from datetime import datetime

import pytz
import rest_framework.status
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import IsAuthenticated

from django.http import HttpResponse
from common.export_excel import WriteToExcel
from common.export_pdf import WriteToPdf
from common.utils import is_valid_uuid, get_response_data_errors, handler_exception_general, \
    get_datetime_from_querystring
from common.views import CustomViewSetWithPagination
from corresponsalia.models import Corresponsalia, TransaccionCorresponsalia
from corresponsalia.serializers import ConfigCorresponsaliaSerializer, CorresponsaliaSerializer, \
    CorresponsaliaSimpleSerializer, CorresponsaliaResponseSerializer, TransaccionCorresponsaliaSerializer, \
    CreateTransaccionCorresponsaliaSerializer, TransaccionCorresponsaSimpleliaSerializer
from thalesapi.models import CardBinConfig, CardType
from users.permissions import IsVerified, IsOperator, IsAdministrator

logger = logging.getLogger(__name__)


class CorresponsaliaApiView(CustomViewSetWithPagination):
    """
    get:
        Return all coresponsalias
    """
    serializer_class = CorresponsaliaSimpleSerializer
    create_serializer_class = ConfigCorresponsaliaSerializer
    update_serializer_class = ConfigCorresponsaliaSerializer
    one_serializer_class = CorresponsaliaSerializer
    response_serializer_class = CorresponsaliaResponseSerializer
    model_class = Corresponsalia
    permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
    field_pk = 'corresponsalia_id'

    def initial(self, request, *args, **kwargs):
        if self.request.method == "POST":
            self.permission_classes = (IsAuthenticated, IsVerified, IsOperator)
        else:
            self.permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        issuer_id = self.request.query_params.get('iss', '')
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'description')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        filters = dict(is_active=True)
        queryset = self.model_class.objects.all()

        if len(issuer_id) > 0:
            filters['company__volcan_issuer_id'] = issuer_id


        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(description__icontains=q) |
                Q(country__icontains=q) |
                Q(city__icontains=q) |
                Q(branch__icontains=q) |
                Q(user_payload__icontains=q) |
                Q(authorization__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.queryset:
            data = {
                'ID': item.id,
                _('nombre'): item.name,
                _('issuer_id'): item.issuer_id,
                _('thales_issuer_id'): item.thales_issuer_id,
                _('status'): 'Activo' if item.is_active else 'Inactivo',
            }
            response_data.append(data)
        fields = ['ID', _('nombre'), _('issuer_id'), _('thales_issuer_id'), _('estatus'), ]
        title = _(u'Empresas')
        if export == 'excel':
            xlsx_data = WriteToExcel(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = 'attachment; filename=Empresas.xlsx'
            response.write(xlsx_data)
        else:
            pdf_data = WriteToPdf(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachement; filename=Empresas.pdf'
            response['Content-Transfer-Encoding'] = 'binary'
            response.write(pdf_data)
        return response



class TransaccionApiView(CustomViewSetWithPagination):
    serializer_class = TransaccionCorresponsaSimpleliaSerializer
    create_serializer_class = CreateTransaccionCorresponsaliaSerializer
    one_serializer_class = TransaccionCorresponsaliaSerializer
    model_class = TransaccionCorresponsalia
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    field_pk = 'transaccion_id'

    def initial(self, request, *args, **kwargs):
        if self.request.method == "POST":
            self.permission_classes = (IsAuthenticated, IsVerified, IsOperator)
        else:
            self.permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        corresponsalia_id = self.request.query_params.get('coId', '')
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'created_at')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        filters = dict(is_active=True)
        queryset = self.model_class.objects.all()
        request = self.request

        from_date = get_datetime_from_querystring(request=request, date_find='from_date', default_value=None)
        to_date = get_datetime_from_querystring(request=request, date_find='to_date', default_value=None)

        if from_date and to_date:
            filters['created_at__date__range'] = (from_date, to_date)
        elif from_date:
            filters['created_at__date__gte'] = from_date
        elif to_date:
            filters['created_at__date__lte'] = to_date

        if is_valid_uuid(corresponsalia_id):
            filters['corresponsalia_id'] = corresponsalia_id


        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(card_number__icontains=q) |
                Q(reference__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.queryset:
            data = {
                'id_transaccion': str(item.id),
                'id_corresponsalia': str(item.corresponsalia_id),
                'tarjeta': item.card_number,
                'moneda': item.currency.abr_code,
                'codigo_movimiento': item.movement_code,
                'importe': item.amount,
                'referencia_numerica': item.reference,
                'estatus': item.get_status_display(),
                'fecha_creacion': item.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            response_data.append(data)
        fields = ['id_transaccion', 'id_corresponsalia', 'tarjeta', 'moneda', 'codigo_movimiento',
                  'importe', 'referencia_numerica', 'estatus', 'fecha_creacion']
        title = _(u'TransaccionesCorresponsalia')
        if export == 'excel':
            xlsx_data = WriteToExcel(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = 'attachment; filename=TransaccionesCorresponsalia.xlsx'
            response.write(xlsx_data)
        else:
            pdf_data = WriteToPdf(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachement; filename=TransaccionesCorresponsalia.pdf'
            response['Content-Transfer-Encoding'] = 'binary'
            response.write(pdf_data)
        return response

    def create(self, request, *args, **kwargs):
        try:
            request_data = request.data if 'request_data' not in kwargs else kwargs['request_data']
            self.serializer = self.get_create_serializer(data=request_data)
            if self.serializer.is_valid():
                card_bin_config: CardBinConfig = self.serializer.validated_data.get('card_bin_config', None)
                if card_bin_config:
                    # guardamos los datos
                    transaction = self.serializer.save()
                    if card_bin_config.card_type == CardType.CT_PREPAID:
                        self.create_prepaid_transaction(request=request, transaction=transaction)
                    elif card_bin_config.card_type == CardType.CT_CREDIT:
                        self.create_credit_transaction(request=request, transaction=transaction)
                    else:
                        self.make_response_success(status=rest_framework.status.HTTP_404_NOT_FOUND,
                                                   message='Tipo de tarjeta no identificado')
                else:
                    self.make_response_success(status=rest_framework.status.HTTP_404_NOT_FOUND,
                                               message='BIN no registrado')
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


    def create_prepaid_transaction(self, request, *args, **kwargs):
        pass


    def create_credit_transaction(self, request, *args, **kwargs):
        pass

    # def get_card_data_tokenization(self, request, *args, **kwargs):
    #     from django.conf import settings
    #     from control.utils import process_volcan_api_request
    #     from common.utils import get_response_data_errors
    #     request_data = request.data.copy()
    #     request_data['usuario_atz'] = settings.VOLCAN_USUARIO_ATZ
    #     request_data['acceso_atz'] = settings.VOLCAN_ACCESO_ATZ
    #     data = {k.upper(): v for k, v in request_data.items()}
    #     serializer = self.get_serializer(data=data)
    #     response_data = {}
    #     if serializer.is_valid():
    #         url_server = settings.SERVER_VOLCAN_AZ7_URL
    #         api_url = f'{url_server}{settings.URL_THALES_API_VERIFY_CARD}'
    #         validated_data = serializer.validated_data.copy()
    #         client = validated_data.pop('client', None)
    #         resp_msg, resp_data, response_status = process_volcan_api_request(data=validated_data,
    #                                                                           url=api_url, request=request, times=0)
    #         if response_status == 200:
    #             if resp_data['RSP_ERROR'].upper() == 'OK' or len(resp_data['RSP_TARJETAID']) > 0:
    #                 resp_data['RSP_ERROR'] = 'OK'
    #                 resp_data['RSP_CODIGO'] = '0000000000'
    #                 resp_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
    #             if resp_data['RSP_ERROR'] == 'OK':
    #                 obj_data = {
    #                     'tarjeta': validated_data['TARJETA'],
    #                     'fecha_exp': validated_data['FECHA_EXP'],
    #                     'folio': resp_data['RSP_FOLIO'],
    #                     "card_id": resp_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in resp_data else '',
    #                     "consumer_id": resp_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in resp_data else '',
    #                     "account_id": resp_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in resp_data else '',
    #                     "issuer_id": settings.THALES_API_ISSUER_ID,
    #                     "card_product_id": 'D1_VOLCAN_VISA_SANDBOX',
    #                     "client": client,
    #                     "state": "ACTIVE"
    #                 }
    #                 resp = self.register_consumer_thalesapi(**obj_data)
    #                 if resp[1] == 200:
    #                     response_data = {
    #                         'RSP_ERROR': resp_data['RSP_ERROR'],
    #                         'RSP_CODIGO': resp_data['RSP_CODIGO'],
    #                         'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'],
    #                         'rsp_folio': resp_data['RSP_FOLIO'],
    #                         "cardId": resp_data['RSP_TARJETAID'] if 'RSP_TARJETAID' in resp_data else '',
    #                         # "consumerId": resp_data['RSP_CLIENTEID'] if 'RSP_CLIENTEID' in resp_data else '',
    #                         "consumerId": client.consumer_id,
    #                         "accountId": resp_data['RSP_CUENTAID'] if 'RSP_CUENTAID' in resp_data else ''
    #                     }
    #                 else:
    #                     response_data = resp[0]
    #                     response_status = resp[1]
    #                     if 'error' in response_data:
    #                         response_data = {
    #                             'RSP_ERROR': 'RC',
    #                             'RSP_CODIGO': f"{response_status}",
    #                             'RSP_DESCRIPCION': response_data['error']
    #                         }
    #                         response_status = 200
    #             else:
    #                 response_data = {
    #                     'RSP_ERROR': resp_data['RSP_ERROR'] if resp_data['RSP_ERROR'] != '' else 'RC',
    #                     'RSP_CODIGO': resp_data['RSP_CODIGO'] if resp_data['RSP_CODIGO'] != '' else '400',
    #                     'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'] if resp_data[
    #                                                                            'RSP_DESCRIPCION'] != '' else 'Error en datos de origen'
    #                 }
    #     else:
    #         resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
    #         # response_data, response_status = {}, 400
    #     logger.info(f"Response Card Data Tokenizacion: {response_data}")
    #     return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)
    #
    # def get_card_data_tokenization_paycard(self, request, *args, **kwargs):
    #     from django.conf import settings
    #     from control.utils import process_volcan_api_request
    #     from common.utils import get_response_data_errors
    #     request_data = request.data.copy()
    #     access_token_paycard = get_access_token_paycard()
    #     if not access_token_paycard:
    #         return self.get_response(status=400, message='No fue posible hacer login a AZ7')
    #     self.serializer_class = GetDataTokenizationPaycardSerializer
    #     data = {k.upper(): v for k, v in request_data.items()}
    #     serializer = self.get_serializer(data=data)
    #     response_data = {}
    #     if serializer.is_valid():
    #         url_server = settings.SERVER_VOLCAN_PAYCARD_URL
    #         api_url = f'{url_server}{settings.URL_AZ7_CONSULTA_TOKEN_TARJETA}'
    #         validated_data = serializer.validated_data.copy()
    #         client = validated_data.pop('client', None)
    #         card = validated_data.pop('card', request_data['tarjeta'])
    #         fecha_exp = validated_data.pop('FECHA_EXP', request_data['fecha_exp'])
    #         folio = validated_data.pop('FOLIO', '12345')
    #         headers = {
    #             'Credenciales': get_credentials_paycad(),
    #             'Authorization': f"{access_token_paycard}",
    #             'Content-Type': 'application/json',
    #             'Accept': 'application/json'
    #         }
    #         resp_msg, resp_data, response_status = process_volcan_api_request(data=validated_data, headers=headers,
    #                                                                           url=api_url, request=request, times=0)
    #         if response_status == 200:
    #             if resp_data['CodRespuesta'] == '0000' or len(resp_data['CardID']) > 0:
    #                 resp_data['RSP_ERROR'] = 'OK'
    #                 resp_data['RSP_CODIGO'] = '0000000000'
    #                 resp_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
    #             if resp_data['RSP_ERROR'] == 'OK':
    #                 obj_data = {
    #                     'tarjeta': card,
    #                     'fecha_exp': fecha_exp,
    #                     'folio': folio,
    #                     "card_id": resp_data['CardID'] if 'CardID' in resp_data else '',
    #                     "consumer_id": resp_data['ConsumerID'] if 'ConsumerID' in resp_data else '',
    #                     "account_id": resp_data['AccountID'] if 'AccountID' in resp_data else '',
    #                     "issuer_id": settings.THALES_API_ISSUER_ID,
    #                     "card_product_id": 'D1_VOLCAN_VISA_SANDBOX',
    #                     "client": client,
    #                     "state": "ACTIVE"
    #                 }
    #                 resp = self.register_consumer_thalesapi(**obj_data)
    #                 if resp[1] == 200:
    #                     response_data = {
    #                         'RSP_ERROR': 'OK',
    #                         'RSP_CODIGO': '00000000',
    #                         'RSP_DESCRIPCION': 'Transaccion aprobada',
    #                         'rsp_folio': folio,
    #                         "cardId": resp_data['CardID'] if 'CardID' in resp_data else '',
    #                         # "consumerId": resp_data['ConsumerID'] if 'ConsumerID' in resp_data else '',
    #                         "consumerId": client.consumer_id,
    #                         "accountId": resp_data['AccountID'] if 'AccountID' in resp_data else ''
    #                     }
    #                 else:
    #                     response_data = resp[0]
    #                     response_status = resp[1]
    #                     if 'error' in response_data:
    #                         response_data = {
    #                             'RSP_ERROR': 'RC',
    #                             'RSP_CODIGO': f"{response_status}",
    #                             'RSP_DESCRIPCION': response_data['error']
    #                         }
    #                         response_status = 200
    #             else:
    #                 response_data = {
    #                     'RSP_ERROR': resp_data['RSP_ERROR'] if resp_data['RSP_ERROR'] != '' else 'RC',
    #                     'RSP_CODIGO': resp_data['RSP_CODIGO'] if resp_data['RSP_CODIGO'] != '' else '400',
    #                     'RSP_DESCRIPCION': resp_data['RSP_DESCRIPCION'] if resp_data[
    #                                                                            'RSP_DESCRIPCION'] != '' else 'Error en datos de origen'
    #                 }
    #     else:
    #         resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
    #         # response_data, response_status = {}, 400
    #     logger.info(f"Response Card Data Tokenizacion: {response_data}")
    #     return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)
    #
    # def get_authorization_token(self, folio=None, issuer_id=None):
    #     from .utils import process_volcan_api_request
    #     from django.conf import settings
    #     from datetime import datetime, timedelta
    #     import jwt
    #     if not issuer_id:
    #         issuer_id = settings.THALES_API_ISSUER_ID
    #     jwt_token = None
    #     url = settings.URL_THALES_AUTHORIZATION_TOKEN
    #
    #     auth_data = {
    #         "iss": issuer_id,
    #         "sub": issuer_id,
    #         "exp": int((datetime.utcnow() + timedelta(minutes=15)).timestamp()),
    #         "aud": f"https://{settings.THALES_API_AUD}"
    #     }
    #     if settings.DEBUG:
    #         logger.debug(f'Data to Auth: {auth_data}')
    #     else:
    #         logger.info(f"AUD https://{settings.THALES_API_AUD}")
    #
    #     with open(settings.PRIV_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pem_file:
    #         private_key = pem_file.read()
    #     with open(settings.PUB_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pem_file:
    #         public_key = pem_file.read()
    #     if private_key:
    #         headers = {
    #             "alg": "ES256",
    #             "typ": "JWT",
    #             "kid": settings.THALES_API_ENCRYPTED_K06_AUTH_KID
    #         }
    #         jwt_token = jwt.encode(payload=auth_data, key=private_key, algorithm="ES256", headers=headers)
    #
    #     if public_key and jwt_token:
    #         decoded = jwt.decode(jwt=jwt_token, key=public_key, algorithms=["ES256"],
    #                              audience=f"https://{settings.THALES_API_AUD}", issuer=issuer_id)
    #         if settings.DEBUG:
    #             logger.debug(f"Descifrar: {decoded}")
    #         else:
    #             logger.info(f"Descifrar: Ok")
    #
    #     if jwt_token:
    #         payload = {
    #             "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    #             "assertion": jwt_token
    #         }
    #         headers = {
    #             "x-correlation-id": folio if folio else '12345',
    #             # "Prefer": "code=200",
    #             "Content-Type": "application/json",
    #             "Accept": "application/json"
    #         }
    #         # cert = None
    #         cert = (settings.SSL_CERTIFICATE_THALES_CRT, settings.SSL_CERTIFICATE_THALES_KEY)
    #         resp_data, resp_status = process_volcan_api_request(data=payload, url=url, headers=headers, cert=cert)
    #         if resp_status == 200:
    #             return resp_data['access_token'] if 'access_token' in resp_data else None
    #     return None
    #
    # def register_consumer_thalesapi(self, *args, **kwargs):
    #     from .utils import process_volcan_api_request
    #     from jwcrypto import jwk, jwe
    #     from thalesapi.utils import get_card_triple_des_process
    #     import json
    #     from django.conf import settings
    #     card_bin_config = None
    #     resp_status = 400
    #     tarjeta = kwargs.get('tarjeta', '')
    #     fecha_exp = kwargs.get('fecha_exp', '0000')
    #     folio = kwargs.get('folio', '123456789')
    #     issuer_id = kwargs.get('issuer_id', settings.THALES_API_ISSUER_ID)
    #     card_product_id = kwargs.get('card_product_id', 'D1_VOLCAN_VISA_SANDBOX')
    #     card_id = kwargs.get('card_id', '')
    #     account_id = kwargs.get('account_id', '')
    #     consumer_id = kwargs.get('consumer_id', '')
    #     client = kwargs.get('client', None)
    #     identification = kwargs.get('identification', '')
    #     find_card_bin_configuration = kwargs.get('find_card_bin_configuration', True)
    #
    #     if not client:
    #         client = get_card_client(identification=identification)
    #
    #     if settings.DEBUG:
    #         logger.debug(f"Register Consumer Data: {kwargs}")
    #     else:
    #         logger.info(f'Register Consumer Data: {{"tarjeta": "{tarjeta}", "folio": "{folio}"}}')
    #
    #     card_real = get_card_triple_des_process(tarjeta, is_descript=True)
    #     if not card_real:
    #         logger.warning(f'Tarjeta: {kwargs.get("tarjeta", "")} no pudo ser desincriptada')
    #         return None
    #     if find_card_bin_configuration:
    #         card_bin_config = CardBinConfig.objects.filter(card_bin=str(card_real[0:8])).first()
    #         if card_bin_config:
    #             if settings.DEBUG:
    #                 logger.debug(f"CardBinConfig --> {card_bin_config}")
    #             else:
    #                 logger.info(
    #                     f"CardBinConfig --> {str(card_bin_config.id)} {card_bin_config.card_type} {card_bin_config.emisor}")
    #             issuer_id = card_bin_config.issuer_id
    #             card_product_id = card_bin_config.card_product_id
    #     card_exp = fecha_exp[2:4] + fecha_exp[0:2]
    #
    #     encrypted_data = {
    #         "pan": card_real,
    #         "exp": card_exp
    #     }
    #     encrypted_data = json.dumps(encrypted_data)
    #     if settings.DEBUG:
    #         logger.debug(f'EncryptedData: {encrypted_data}')
    #     else:
    #         logger.info(f'EncryptedData: {{"pan": "{mask_card(card_real)}", "exp": "{card_exp}"}}')
    #
    #     access_token = self.get_authorization_token(folio=folio, issuer_id=issuer_id)
    #     # return {'access_token': access_token}, 200
    #
    #     if access_token:
    #         url = get_url_thales_register_customer_with_cards(issuer_id=issuer_id, consumer_id=client.consumer_id)
    #
    #         public_key = None
    #         payload = {}
    #         with open(settings.PUB_KEY_ISSUER_SERVER_TO_D1_SERVER_PEM, "rb") as pem_file:
    #             public_key = jwk.JWK.from_pem(pem_file.read())
    #         if public_key:
    #             protected_header_back = {
    #                 "alg": "ECDH-ES",
    #                 "enc": "A256GCM",
    #                 "kid": settings.THALES_API_ENCRYPTED_K01_KID
    #             }
    #             jwe_token = jwe.JWE(encrypted_data.encode('utf-8'),
    #                                 recipient=public_key, protected=protected_header_back)
    #             enc = jwe_token.serialize(compact=True)
    #
    #             payload = {
    #                 "cards": [{
    #                     "cardId": card_id,
    #                     "accountId": account_id,
    #                     "cardProductId": card_product_id,
    #                     "state": kwargs.get('state', 'ACTIVE'),
    #                     "encryptedData": enc
    #                 }]
    #             }
    #         headers = {
    #             "x-correlation-id": folio,
    #             # "Prefer": "",
    #             "Content-Type": "application/json",
    #             "Accept": "application/json",
    #             "Authorization": f"Bearer {access_token}"
    #         }
    #         # cert = None
    #         cert = (settings.SSL_CERTIFICATE_THALES_CRT, settings.SSL_CERTIFICATE_THALES_KEY)
    #         resp_data, resp_status = process_volcan_api_request(data=payload, url=url, headers=headers,
    #                                                             method='PUT', cert=cert)
    #         if resp_status == 204:
    #             if card_bin_config:
    #                 card_bin_config = CardBinConfig.objects.filter(card_bin=str(card_real[0:8])).first()
    #             try:
    #                 if not card_bin_config:
    #                     card_bin = card_real[0:8]
    #                     card_type = 'credit'
    #                     issuer = 'CMF'
    #                 else:
    #                     card_bin = card_bin_config.card_bin
    #                     card_type = card_bin_config.card_type
    #                     issuer = card_bin_config.emisor
    #                 card_detail = CardDetail.objects.filter(card_id=card_id).first()
    #                 if not card_detail:
    #                     card_detail = CardDetail.objects.create(card_id=card_id, consumer_id=consumer_id,
    #                                                             account_id=account_id, issuer_id=issuer_id,
    #                                                             card_bin=card_bin, card_type=card_type, emisor=issuer)
    #                 if client:
    #                     card_detail.client = client
    #                     card_detail.save()
    #             except Exception as e:
    #                 logger.error("Error al registrar card_detail")
    #                 logger.error(e.args.__str__())
    #             return resp_data, 200
    #         else:
    #             return resp_data, resp_status
    #     return {"error": "Error in authorization"}, 400

#
# class ThalesV2ApiViewPrivate(ThalesApiViewPrivate):
#     permission_classes = (IsAuthenticated, IsVerified, IsOperator)
#     serializer_class = GetVerifyCardSerializer
#
#     def post_register_consumer_cards(self, request, *args, **kwargs):
#         from common.utils import get_response_data_errors
#         request_data = request.data.copy()
#         data = {k.upper(): v for k, v in request_data.items()}
#         serializer = self.get_serializer(data=data)
#         response_data = {}
#         response_status = 200
#         resp_msg = ''
#         if serializer.is_valid():
#             validated_data = serializer.validated_data.copy()
#             client = validated_data.pop('client', None)
#             response_data['RSP_ERROR'] = 'OK'
#             response_data['RSP_CODIGO'] = '0000000000'
#             response_data['RSP_DESCRIPCION'] = u'Transacción aprobada'
#             obj_data = {
#                 'tarjeta': validated_data['TARJETA'],
#                 'fecha_exp': validated_data['FECHA_EXP'],
#                 'folio': validated_data['FOLIO'],
#                 "card_id": validated_data['TARJETAID'],
#                 "consumer_id": validated_data['CLIENTEID'],
#                 "account_id": validated_data['CUENTAID'],
#                 "issuer_id": validated_data['ISSUER_ID'],
#                 "card_product_id": validated_data['CARD_PRODUCT_ID'],
#                 "state": validated_data['STATE'],
#                 'client': client,
#                 "find_card_bin_configuration": True
#             }
#             resp = self.register_consumer_thalesapi(**obj_data)
#             if resp[1] == 200:
#                 response_data = {
#                     'rsp_folio': validated_data['FOLIO']
#                 }
#             else:
#                 response_data = resp[0]
#             response_status = resp[1]
#         else:
#             resp_msg, response_data, response_status = get_response_data_errors(serializer.errors)
#         return self.get_response(message=resp_msg, data=response_data, status=response_status, lower_response=False)
