from rest_framework.exceptions import ParseError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from common.views import CustomViewSet
from thalesapi.models import CardType, CardDetail
from thalesapi.serializers import GetDataTokenizationSerializer
from thalesapi.utils import is_card_bin_valid
from users.permissions import IsVerified, IsOperator


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

    def get_card_data_tokenization(self, request, *args, **kwargs):
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
                if response_data['RSP_ERROR'].upper() == 'OK':
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
