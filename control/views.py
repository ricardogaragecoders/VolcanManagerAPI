from django.shortcuts import render

from common.views import CustomViewSet, CustomViewSetWithPagination
from rest_framework.permissions import IsAuthenticated

from control.models import Webhook
from control.serializers import WebhookSerializer, WebhookListSerializer
from users.permissions import IsVerified, IsOperator, IsAdministrator
from django.db.models import Q, F, Value, Avg


# Create your views here.

class ControlApiView(CustomViewSet):
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    http_method_names = ['post', 'options', 'head']

    def control_action(self, request, control_function, name_control_function):
        response_message = ''
        response_data = dict()
        response_status = 200
        try:
            response_message, response_data, response_status = control_function(request)
            if 'RSP_CODIGO' in response_data:
                if (response_data['RSP_CODIGO'].isnumeric() and int(response_data['RSP_CODIGO']) == 0) \
                        or response_data['RSP_CODIGO'] == '':
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.info(request.user.profile.get_full_name())
                    logger.info(response_data)
            else:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(request.user.profile.get_full_name())
                logger.error(response_data)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)
            response_message = u"Error en applicación"
            response_status = 500
        finally:
            return self.get_response(response_message, response_data, response_status)

    def creation_ente(self, request, *args, **kwargs):
        from control.utils import creation_ente
        return self.control_action(request=request, control_function=creation_ente,
                                   name_control_function="creation_ente")

    def creation_cta_tar(self, request, *args, **kwargs):
        from control.utils import creation_cta_tar
        return self.control_action(request=request, control_function=creation_cta_tar,
                                   name_control_function="creation_cta_tar")

    def consulta_cuenta(self, request, *args, **kwargs):
        from control.utils import consulta_cuenta
        return self.control_action(request=request, control_function=consulta_cuenta,
                                   name_control_function="consulta_cuenta")

    def extrafinanciamientos(self, request, *args, **kwargs):
        from control.utils import extrafinanciamientos
        return self.control_action(request=request, control_function=extrafinanciamientos,
                                   name_control_function="extrafinanciamientos")

    def intrafinanciamientos(self, request, *args, **kwargs):
        from control.utils import intrafinanciamientos
        return self.control_action(request=request, control_function=intrafinanciamientos,
                                   name_control_function="intrafinanciamientos")

    def consulta_tarjetas(self, request, *args, **kwargs):
        from control.utils import consulta_tarjetas
        return self.control_action(request=request, control_function=consulta_tarjetas,
                                   name_control_function="consulta_tarjetas")

    def cambio_pin(self, request, *args, **kwargs):
        from control.utils import cambio_pin
        return self.control_action(request=request, control_function=cambio_pin,
                                   name_control_function="cambio_pin")


class WebHookApiView(CustomViewSet):
    """
    get:
        Return all webhooks
    """
    serializer_class = WebhookSerializer
    list_serializer_class = WebhookListSerializer
    response_serializer_class = WebhookListSerializer
    one_serializer_class = WebhookListSerializer
    model_class = Webhook
    permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
    field_pk = 'webhook_id'

    def get_queryset_filters(self, *args, **kwargs):
        active = self.request.query_params.get('active', 'all')
        account_issuer = self.request.query_params.get('ai', '')
        filters = {'deleted_at__isnull': True}

        if len(account_issuer) > 0:
            filters['account_issuer'] = account_issuer

        if active != 'all':
            filters['active'] = active == 'true'
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
        print(response_data)
        response_data['rsp_codigo'] = '200'
        response_data['rsp_descripcion'] = u'ok'
        response_data['rsp_data'] = self.serializer.data
        self.make_response_success(data=response_data)

    def perform_retrieve(self, request, *args, **kwargs):
        register = self.get_object(pk=self.pk)
        self.serializer = self.get_one_serializer(register)
        response_data = self.serializer.data
        response_data['rsp_codigo'] = '200'
        response_data['rsp_descripcion'] = u'Detalle de webhook'
        self.make_response_success(data=response_data)

    def perform_create(self, request, *args, **kwargs):
        register = self.serializer.save()
        if not self.response_serializer_class:
            response_data = self.serializer.data
        else:
            response_data = self.response_serializer_class(register).data
        response_data['rsp_codigo'] = '201'
        response_data['rsp_descripcion'] = u'Creación de webhook realizada'
        self.make_response_success(data=response_data, status=201)

    def perform_update(self, request, *args, **kwargs):
        register = self.serializer.save()
        if not self.response_serializer_class:
            response_data = self.serializer.data
        else:
            response_data = self.response_serializer_class(register).data
        response_data['rsp_codigo'] = '200'
        response_data['rsp_descripcion'] = u'Actualización de webhook realizada'
        self.make_response_success(data=response_data, status=200)

    def perform_destroy(self, request, *args, **kwargs):
        register = kwargs['register']
        if hasattr(register, 'active'):
            register.active = False
            if hasattr(register, 'deleted_at'):
                from django.utils import timezone
                register.deleted_at = timezone.now()
            register.save()
        response_data = dict()
        response_data['rsp_codigo'] = '204'
        response_data['rsp_descripcion'] = u'Webhook borrado'
        self.make_response_success('Webhook borrado', response_data, 204)
