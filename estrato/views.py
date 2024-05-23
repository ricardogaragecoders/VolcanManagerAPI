import json

from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from common.utils import get_response_data_errors, handler_exception_general
from common.views import CustomViewSet
from estrato.serializers import EstadosCuentaSerializer
from estrato.utils import call_volcan_manager_api
from users.permissions import IsVerified, IsOperator
from volcanmanagerapi import settings


class MixinEstratoVolcanApi:
    issuer_slug: str = ''
    api_key: str = ''

    def get_api_key_from_slug(self, issuer_slug: str = 'CMF'):
        if not self.issuer_slug:
            self.issuer_slug = issuer_slug
        key_cache = f"api_key_{self.issuer_slug}"
        if key_cache not in cache:
            api_key = settings.API_KEY_FID
            cache.set(key_cache, api_key, 60 * 24)
        return cache.get(key_cache)

    def get_server_estrato_volcan_url(self):
        key_cache = f"server_estrato_volcan_url"
        if key_cache not in cache:
            base_url = settings.SERVER_ESTRATO_VOLCAN_URL
            cache.set(key_cache, base_url, 60 * 24)
        return cache.get(key_cache)

    def call_volcan_manager_api(self, request_data, issuer_slug: str = 'CMF', url: str = '', method='POST'):
        if not self.api_key:
            self.api_key = self.get_api_key_from_slug(issuer_slug=issuer_slug)

        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": f"{self.api_key}"
        }

        if method != 'GET':
            request_data = json.dumps(request_data, indent=4)
        
        response_data, status_code = call_volcan_manager_api(
            f"{self.get_server_estrato_volcan_url()}{url}",
            headers=headers, method=method, data=request_data
        )

        return response_data, status_code


class EstratoEstadosCuentaApiView(CustomViewSet, MixinEstratoVolcanApi):
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    serializer_class = EstadosCuentaSerializer
    http_method_names = ['post', 'options', 'head']

    def perform_create(self, request, *args, **kwargs):
        """
            Create users clients
        """
        response_data = dict()
        profile = request.user.profile

        if settings.APIKEY_ESTRATO_VOLCAN_API_ENABLED:
            validated_data = self.serializer.validated_data.copy()
            response_data, status_code = self.call_volcan_manager_api(
                request_data=validated_data, issuer_slug='FID',
                url='/api/statements/account/statements/', method='GET'
            )
            if status_code in [200, 201]:
                self.make_response_success(data=response_data['data'], 
                                           message=response_data['message'], 
                                           status=status_code)
            else:
                self.make_response_success(data=response_data['data'], 
                                           message=response_data['message'], 
                                           status=status_code)
        else:
            self.make_response_success(data=response_data, message='Servicio Estrato no disponible', status=200)
