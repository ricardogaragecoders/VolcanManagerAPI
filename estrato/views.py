import json
import time

from django.core.cache import cache
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from common.views import CustomViewSet
from estrato.models import EstratoApiKey
from estrato.serializers import EstadosCuentaSerializer, EstratoApiKeySerializer, EstratoApiKeyListSerializer
from estrato.utils import call_volcan_manager_api, get_estrato_api_key_credentials
from users.permissions import IsVerified, IsOperator
from volcanmanagerapi import settings


class MixinEstratoVolcanApi:
    issuer_slug: str = ''
    api_key: EstratoApiKey = None

    def get_api_key_from_issuer_id(self, issuer_id: str = 'CMF') -> EstratoApiKey:
        return get_estrato_api_key_credentials(issuer_id=issuer_id)

    def call_volcan_manager_api(self, request_data, issuer_id: str = 'CMF', url: str = '', method='POST'):
        self.api_key = self.get_api_key_from_issuer_id(issuer_id=issuer_id)
        response_data = {'data': {}, 'message': 'Sin datos'}
        status_code = 400
        if self.api_key:
            headers = {
                "Content-Type": "application/json; charset=UTF-8",
                f"{self.api_key.header_request}": f"{self.api_key.api_key}"
            }

            if method != 'GET':
                request_data = json.dumps(request_data, indent=4)

            response_data, status_code = call_volcan_manager_api(
                f"{self.api_key.url_estrato}{url}",
                headers=headers, method=method, data=request_data
            )

        return response_data, status_code


class EstratoEstadosCuentaApiView(CustomViewSet, MixinEstratoVolcanApi):
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    serializer_class = EstadosCuentaSerializer
    http_method_names = ['post', 'options', 'head']

    def make_response_success_from_data(self, response_data, response_time=None):
        print(f"Response time: {response_time}")
        results = response_data['data']['results']
        server_host = self.request.get_host()
        server_host = f"http{'s' if self.request.is_secure() else ''}://{server_host}"
        for index, item in enumerate(results):
            if 'PDF' in item and item['PDF']:
                item['PDF'] = item['PDF'].replace(settings.SERVER_ESTRATO_VOLCAN_URL, server_host)
                results[index] = item
        response_data['data']['results'] = results
        return response_data['data']

    def perform_create(self, request, *args, **kwargs):
        """
            Create users clients
        """
        response_data = dict()
        # profile = request.user.profile
        start_time = time.time()
        if settings.APIKEY_ESTRATO_VOLCAN_API_ENABLED:
            validated_data = self.serializer.validated_data.copy()
            response_data, status_code = self.call_volcan_manager_api(
                request_data=validated_data, issuer_id=validated_data['iss'],
                url='/api/statements/account/statements/', method='GET'
            )
            if status_code in [200, 201]:
                self.make_response_success(data=self.make_response_success_from_data(
                    response_data,
                    response_time=time.time() - start_time),
                    status=status_code)
                self.make_response_success(data=response_data['data'],
                                           message=response_data['message'],
                                           status=status_code)
            elif 'error' in response_data:
                self.make_response_success(data={}, message=response_data['error'], status=status_code)
        else:
            self.make_response_success(data=response_data, message='Servicio Estrato no disponible',  status=200)


class EstratoApiKeyApiView(CustomViewSet):
    """
    get:
        Return all EstratoApiKey's
    """
    serializer_class = EstratoApiKeySerializer
    list_serializer_class = EstratoApiKeyListSerializer
    response_serializer_class = EstratoApiKeyListSerializer
    one_serializer_class = EstratoApiKeyListSerializer
    model_class = EstratoApiKey
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    field_pk = 'api_key_id'

    def get_queryset_filters(self, *args, **kwargs):
        active = self.request.query_params.get('active', 'all')
        profile = self.request.user.profile
        if profile.is_admin(equal=False):
            volcan_issuer_id = self.request.query_params.get('issuer_id', '')
        elif profile.is_operator():
            volcan_issuer_id = profile.operator.company.volcan_issuer_id
        else:
            volcan_issuer_id = 'sin_emision'
        filters = {'deleted_at__isnull': True}

        if len(volcan_issuer_id) > 0:
            filters['volcan_issuer_id'] = volcan_issuer_id

        if active != 'all':
            filters['is_active'] = active == 'true'
        return filters

    def get_queryset(self, *args, **kwargs):
        filters = self.get_queryset_filters(*args, **kwargs)
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'id')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        queryset = self.model_class.objects.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(account_issuer__icontains=q) |
                Q(url_webhook__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def perform_list(self, request, *args, **kwargs):
        response_data = dict()
        response_data['rsp_codigo'] = '200'
        response_data['rsp_descripcion'] = u'ok'
        response_data['rsp_data'] = self.serializer.data
        self.make_response_success(data=response_data)

    def perform_retrieve(self, request, *args, **kwargs):
        register = self.get_object(pk=self.pk)
        self.serializer = self.get_one_serializer(register)
        response_data = self.serializer.data
        response_data['rsp_codigo'] = '200'
        response_data['rsp_descripcion'] = u'Detalle de Estrato Api Key'
        self.make_response_success(data=response_data)

    def delete_from_cache(self, issuer_id):
        from django.core.cache import cache
        key_cache = f"estrato-api-key-{issuer_id}"
        if key_cache in cache:
            cache.delete(key_cache)
        return True

    def perform_create(self, request, *args, **kwargs):
        register = self.serializer.save()
        self.delete_from_cache(issuer_id=register.volcan_issuer_id)
        if not self.response_serializer_class:
            response_data = self.serializer.data
        else:
            response_data = self.response_serializer_class(register).data
        response_data['rsp_codigo'] = '201'
        response_data['rsp_descripcion'] = u'Creación de apikey realizada'
        self.make_response_success(data=response_data, status=201)

    def perform_update(self, request, *args, **kwargs):
        register = self.serializer.save()
        self.delete_from_cache(issuer_id=register.volcan_issuer_id)
        if not self.response_serializer_class:
            response_data = self.serializer.data
        else:
            response_data = self.response_serializer_class(register).data
        response_data['rsp_codigo'] = '200'
        response_data['rsp_descripcion'] = u'Actualización de apike realizada'
        self.make_response_success(data=response_data, status=200)

    def perform_destroy(self, request, *args, **kwargs):
        register = kwargs['register']
        if hasattr(register, 'is_active'):
            register.is_active = False
            if hasattr(register, 'deleted_at'):
                register.deleted_at = timezone.now()
            if hasattr(register, 'is_deleted'):
                register.is_deleted = True
            register.save()
        self.delete_from_cache(issuer_id=register.volcan_issuer_id)
        response_data = {'rsp_codigo': '204', 'rsp_descripcion': u'Estrato Api Key borrado'}
        self.make_response_success(data=response_data, status=204)