import logging

from django.conf import settings

from common.utils import get_response_data_errors
from control.utils import process_volcan_api_request
from corresponsalia.serializers import CorresponsaliaSerializer

logger = logging.getLogger(__name__)

def conf_corresponsalia(request, **kwargs):
    times = kwargs.get('times', 0)
    if 'request_data' not in kwargs:
        request_data = request.data.copy()
    else:
        request_data = kwargs['request_data'].copy()
    url_server = settings.SERVER_VOLCAN_AZ7_URL
    api_url = f'{url_server}{settings.URL_AZ7_CORRESPONSALIA}'
    serializer = CorresponsaliaSerializer(data=request_data)
    if serializer.is_valid():
        resp = process_volcan_api_request(data=serializer.validated_data, url=api_url, request=request, times=times)
    else:
        resp = get_response_data_errors(serializer.errors)
    return resp
