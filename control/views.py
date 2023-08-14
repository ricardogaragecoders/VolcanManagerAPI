import pymongo
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated

from common.utils import get_date_from_querystring, make_day_start, make_day_end, get_response_data_errors
from common.views import CustomViewSet, CustomViewSetWithPagination
from control.models import Webhook, TransactionCollection, TransactionErrorCollection
from control.permissions import HasPermissionByMethod, HasUserAndPasswordInData
from control.serializers import WebhookSerializer, WebhookListSerializer, TransactionSerializer
from users.permissions import IsVerified, IsOperator, IsAdministrator


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
        except ParseError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)
            response_data = {'RSP_CODIGO': '-1', 'RSP_DESCRIPCION': "%s" % e}
            response_message = "%s" % e
            response_status = 400
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

    def cambio_limites(self, request, *args, **kwargs):
        from control.utils import cambio_limites
        return self.control_action(request=request, control_function=cambio_limites,
                                   name_control_function="cambio_limites")

    def cambio_estatus_tdc(self, request, *args, **kwargs):
        from control.utils import cambio_estatus_tdc
        return self.control_action(request=request, control_function=cambio_estatus_tdc,
                                   name_control_function="cambio_estatus_tdc")

    def reposicion_tarjetas(self, request, *args, **kwargs):
        from control.utils import reposicion_tarjetas
        return self.control_action(request=request, control_function=reposicion_tarjetas,
                                   name_control_function="reposicion_tarjetas")


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
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    field_pk = 'webhook_id'

    def get_queryset_filters(self, *args, **kwargs):
        active = self.request.query_params.get('active', 'all')
        profile = self.request.user.profile
        if profile.isAdminProgram():
            account_issuer = self.request.query_params.get('emisor', '')
        elif profile.isOperator(equal=True):
            account_issuer = profile.user.first_name
        else:
            account_issuer = 'sin_emision'
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


class TransactionCollectionApiView(CustomViewSetWithPagination):
    """
    get:
        Return all transactions from mongodb.
    post:
        Create a transaction and save to mongodb.
    retrieve:
        Return a transaction from mongodb.
    update:
        Update a transaction and save to mongodb.
    delete:
        Delete a transaction from mongodb.
    """
    serializer_class = None
    model_class = TransactionCollection
    field_pk = 'notification_id'
    permission_classes = (HasPermissionByMethod,)
    http_method_names = ['get', 'post', 'options', 'head']
    method_permissions = {
        'POST': [HasUserAndPasswordInData,],
        'GET': [IsAuthenticated, IsVerified, IsOperator]
    }
    _limit = 20
    _offset = 0
    _page = 0
    _order_by = 'action'
    _total = 0

    def get_results(self):
        profile = self.request.user.profile
        if profile.isAdminProgram():
            account_issuer = self.request.query_params.get('emisor', '')
        elif profile.isOperator(equal=True):
            account_issuer = profile.user.first_name
        else:
            account_issuer = 'sin_emision'

        self._limit = int(self.request.query_params.get('limit', 20))
        self._offset = int(self.request.query_params.get('offset', 0))
        self._page = int(self._offset / self._limit) if self._offset > 0 else 0
        self._order_by = self.request.query_params.get('orderBy', 'action')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        q = self.request.query_params.get('q', None)
        # export = self.request.query_params.get('export', None)

        filters = dict()
        sort = self._order_by
        direction = pymongo.ASCENDING if order_by_desc == 'false' else pymongo.DESCENDING

        s_from_date = self.request.query_params.get('from_date', None)
        s_to_date = self.request.query_params.get('to_date', None)
        from_date = get_date_from_querystring(self.request, 'from_date', timezone.localtime(timezone.now()))
        to_date = get_date_from_querystring(self.request, 'to_date', timezone.localtime(timezone.now()))
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)
        if s_from_date and s_to_date:
            filters['updated_at'] = {
                "$gte": from_date,
                "$lt": to_date
            }
        elif s_from_date:
            filters['updated_at'] = {
                "$gte": from_date
            }
        elif s_to_date:
            filters['updated_at'] = {
                "$lt": to_date
            }

        if len(account_issuer) > 0:
            filters['emisor'] = account_issuer.upper()

        if q:
            filters['$or'] = [
                {'tarjeta': {'$regex': q, '$options': 'i'}},
                {'referencia': {'$regex': q, '$options': 'i'}},
                {'numero_autorizacion': {'$regex': q, '$options': 'i'}},
                {'codigo_autorizacion': {'$regex': q, '$options': 'i'}},
                {'comercio': {'$regex': q, '$options': 'i'}}
            ]

        db = TransactionCollection()
        self._total = db.find(filters).count()

        return db.find(filters, sort, direction, self._limit, self._page)

    def create(self, request, *args, **kwargs):
        try:
            self.serializer = TransactionSerializer(data=request.data)
            if self.serializer.is_valid():
                db = TransactionCollection()
                data = self.serializer.validated_data
                data['entregado'] = False
                data['fecha_entregado'] = None
                data['codigo_error'] = ''
                data['mensaje_error'] = ''
                result = db.insert_one(data=data)
                from control.tasks import send_transaction_emisor
                send_transaction_emisor.delay(transaction_id=str(result.inserted_id))
                self.make_response_success(data={'RSP_CODIGO': '00', 'RSP_DESCRIPCION': 'Aprobado'})
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
                db = TransactionErrorCollection()
                data = {
                    'request_data': request.data,
                    'error': self.resp[0],
                    'created_at': timezone.localtime(timezone.now()),
                }
                db.insert_one(data=data)
        except ParseError as e:
            from common.utils import handler_exception_general
            db = TransactionErrorCollection()
            data = {
                'request_data': request.data,
                'error': "%s" % e,
                'created_at': timezone.localtime(timezone.now()),
            }
            db.insert_one(data=data)
            self.resp = ["%s" % e, {'code': 'error'}, 400]
        except Exception as e:
            from common.utils import handler_exception_general
            db = TransactionErrorCollection()
            data = {
                'request_data': request.data,
                'error': self.resp[0],
                'created_at': timezone.localtime(timezone.now()),
            }
            db.insert_one(data=data)
            self.resp = ["%s" % e, {'code': 'error'}, 500]
        finally:
            return self.get_response()

    def list(self, request, *args, **kwargs):
        try:
            from bson.json_util import dumps
            # import pytz
            query = self.get_results()
            results = []
            # local_tz = pytz.timezone('America/Mexico_City')
            for item in query:
                # updated_at = local_tz.localize(item['updated_at'], is_dst=None)
                results.append({
                    'rsp_id': '{}'.format(item['_id']),
                    'rsp_emisor': item['emisor'],
                    'rsp_monto': item['monto'],
                    'rsp_moneda': item['moneda'],
                    'rsp_fecha_transaccion': item['fecha_transaccion'],
                    'rsp_hora_transaccion': item['hora_transaccion'],
                    'rsp_tarjeta': item['tarjeta'],
                    # 'rsp_estatus': item['estatus'],
                    # 'rsp_tipo_transaccion': item['tipo_transaccion'],
                    # 'rsp_id_movimiento': item['id_movimiento'],
                    # 'rsp_referencia': item['referencia'],
                    # 'rsp_numero_autorizacion': item['numero_autorizacion'],
                    # 'rsp_codigo_autorizacion': item['codigo_autorizacion'],
                    # 'rsp_comercio': item['comercio'],
                    'rsp_entregado': item['entregado'],
                    # 'rsp_fecha_entregado': item['fecha_entregado'],
                    'rsp_codigo_error': item['codigo_error'],
                    # 'rsp_mensaje_error': item['mensaje_error']
                })
            pages = int(self._total / self._limit)
            current_page = self._offset / self._limit
            response_data = {
                'rsp_paginas': pages,
                'rsp_pagina_actual': current_page,
                'rsp_registros_totales': self._total,
                'rsp_registros': results
            }
            self.make_response_success(data=response_data)
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def retrieve(self, request, *args, **kwargs):
        try:
            from control.models import TransactionCollection
            db = TransactionCollection()
            pk = kwargs.pop(self.field_pk)
            if len(pk) > 10:
                from bson.objectid import ObjectId
                query = db.find({'_id': ObjectId(pk)})
            else:
                query = db.find({'_id': int(pk)})

            if query:
                # import pytz
                results = []
                # local_tz = pytz.timezone('America/Mexico_City')
                for item in query:
                    # updated_at = local_tz.localize(item['updated_at'], is_dst=None)
                    results.append({
                        'rsp_id': '{}'.format(item['_id']),
                        'rsp_monto': item['monto'],
                        'rsp_moneda': item['moneda'],
                        'rsp_emisor': item['emisor'],
                        'rsp_estatus': item['estatus'],
                        'rsp_tipo_transaccion': item['tipo_transaccion'],
                        'rsp_tarjeta': item['tarjeta'],
                        'rsp_id_movimiento': item['id_movimiento'],
                        'rsp_fecha_transaccion': item['fecha_transaccion'],
                        'rsp_hora_transaccion': item['hora_transaccion'],
                        'rsp_referencia': item['referencia'],
                        'rsp_numero_autorizacion': item['numero_autorizacion'],
                        'rsp_codigo_autorizacion': item['codigo_autorizacion'],
                        'rsp_comercio': item['comercio'],
                        'rsp_entregado': item['entregado'],
                        'rsp_fecha_entregado': item['fecha_entregado'],
                        'rsp_codigo_error': item['codigo_error'],
                        'rsp_mensaje_error': item['mensaje_error'],
                    })
                response_data = results[0] if len(results) > 0 else []
                self.make_response_success(data=response_data)
            else:
                self.make_response_not_found()
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()
