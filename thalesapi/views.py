from rest_framework.exceptions import ParseError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from common.views import CustomViewSet
from thalesapi.models import CardType, CardDetail
from thalesapi.utils import is_card_bin_valid


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
        if 'cardBin' in request_data and is_card_bin_valid(request_data['cardBin']):
            # aqui revisamos si es credito o prepago
            card_bin = request_data['cardBin']
            card_type = CardType.CT_PREPAID if card_bin == '53876436' else CardType.CT_CREDIT
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
        card_id = request.query_params.get('cardId', '')
        issuer_id = kwargs.get('issuer_id', '')
        card_detail = CardDetail.objects.filter(consumer_id=consumer_id, card_id=card_id, issuer_id=issuer_id).first()
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

    def get_card_credentials_testing(self, request, *args, **kwargs):
        from thalesapi.utils import get_card_credentials_credit_testing
        response_data, response_status = self.control_action(request=request,
                                                             control_function=get_card_credentials_credit_testing,
                                                             *args, **kwargs)
        return Response(data=response_data, status=response_status)