import time

import pymongo
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated

from common.utils import get_date_from_querystring, make_day_start, make_day_end, get_response_data_errors
from common.views import CustomViewSet, CustomViewSetWithPagination
from webhook.models import Webhook, TransactionCollection, TransactionErrorCollection
from webhook.permissions import HasPermissionByMethod, HasUserAndPasswordInData
from webhook.serializers import WebhookSerializer, WebhookListSerializer, TransactionSerializer
from users.permissions import IsVerified, IsOperator


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
    http_method_names = ['get', 'post', 'patch', 'options', 'head']
    method_permissions = {
        'POST': [HasUserAndPasswordInData, ],
        'GET': [IsAuthenticated, IsVerified, IsOperator],
        'PATCH': [IsAuthenticated, IsVerified, IsOperator]
    }
    _limit = 20
    _offset = 0
    _page = 0
    _order_by = 'action'
    _total = 0

    def get_queryset_filters(self, *args, **kwargs):
        filters = dict()
        profile = self.request.user.profile
        if profile.isAdminProgram():
            account_issuer = self.request.query_params.get('emisor', '')
        elif profile.isOperator(equal=True):
            account_issuer = profile.user.first_name
        else:
            account_issuer = 'sin_emision'

        s_from_date = self.request.query_params.get('from_date', None)
        s_to_date = self.request.query_params.get('to_date', None)
        from_date = get_date_from_querystring(self.request, 'from_date', timezone.localtime(timezone.now()))
        to_date = get_date_from_querystring(self.request, 'to_date', timezone.localtime(timezone.now()))
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)
        if s_from_date and s_to_date:
            filters['updated_at'] = {"$gte": from_date, "$lt": to_date}
        elif s_from_date:
            filters['updated_at'] = {"$gte": from_date}
        elif s_to_date:
            filters['updated_at'] = {"$lt": to_date}

        if len(account_issuer) > 0:
            filters['emisor'] = account_issuer.upper()

        return filters

    def get_queryset(self, *args, **kwargs):
        filters = self.get_queryset_filters(*args, **kwargs)
        self._limit = int(self.request.query_params.get('limit', 20))
        self._offset = int(self.request.query_params.get('offset', 0))
        self._page = int(self._offset / self._limit) if self._offset > 0 else 0
        self._order_by = self.request.query_params.get('orderBy', 'action')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        q = self.request.query_params.get('q', None)
        # export = self.request.query_params.get('export', None)
        sort = self._order_by
        direction = pymongo.ASCENDING if order_by_desc == 'false' else pymongo.DESCENDING

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
            print(request.data)
            self.serializer = TransactionSerializer(data=request.data)
            if self.serializer.is_valid():
                db = TransactionCollection()
                data = self.serializer.validated_data
                data['entregado'] = False
                data['fecha_entregado'] = None
                data['codigo_error'] = ''
                data['mensaje_error'] = ''
                result = db.insert_one(data=data)
                from webhook.tasks import send_transaction_emisor
                send_transaction_emisor(transaction_id=str(result.inserted_id))
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
            query = self.get_queryset(*args, **kwargs)
            results = []
            # local_tz = pytz.timezone('America/Mexico_City')
            for item in query:
                # updated_at = local_tz.localize(item['updated_at'], is_dst=None)
                results.append({
                    'id': '{}'.format(item['_id']),
                    'emisor': item['emisor'],
                    'monto': item['monto'],
                    'moneda': item['moneda'],
                    'fecha_transaccion': item['fecha_transaccion'],
                    'hora_transaccion': item['hora_transaccion'],
                    'tarjeta': item['tarjeta'],
                    # 'estatus': item['estatus'],
                    # 'tipo_transaccion': item['tipo_transaccion'],
                    # 'id_movimiento': item['id_movimiento'],
                    # 'referencia': item['referencia'],
                    # 'numero_autorizacion': item['numero_autorizacion'],
                    # 'codigo_autorizacion': item['codigo_autorizacion'],
                    # 'comercio': item['comercio'],
                    'entregado': item['entregado'],
                    # 'fecha_entregado': item['fecha_entregado'],
                    'codigo_error': item['codigo_error'],
                    # 'mensaje_error': item['mensaje_error']
                })
            pages = int(self._total / self._limit)
            current_page = self._offset / self._limit
            response_data = {
                'paginas': pages,
                'pagina_actual': current_page,
                'registros_totales': self._total,
                'registros': results
            }
            self.make_response_success(data=response_data)
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def retrieve(self, request, *args, **kwargs):
        try:
            from webhook.models import TransactionCollection
            db = TransactionCollection()
            filters = self.get_queryset_filters(*args, **kwargs)
            pk = kwargs.pop(self.field_pk)
            if len(pk) > 10:
                from bson.objectid import ObjectId
                filters['_id'] = ObjectId(pk)

            query = db.find(filters)
            if query:
                # import pytz
                results = []
                # local_tz = pytz.timezone('America/Mexico_City')
                for item in query:
                    # updated_at = local_tz.localize(item['updated_at'], is_dst=None)
                    results.append({
                        'RSP_CODIGO': '00',
                        'RSP_DESCRIPCION': 'Aprobado',
                        'id': '{}'.format(item['_id']),
                        'monto': item['monto'],
                        'moneda': item['moneda'],
                        'emisor': item['emisor'],
                        'estatus': item['estatus'],
                        'tipo_transaccion': item['tipo_transaccion'],
                        'tarjeta': item['tarjeta'],
                        'id_movimiento': item['id_movimiento'],
                        'fecha_transaccion': item['fecha_transaccion'],
                        'hora_transaccion': item['hora_transaccion'],
                        'referencia': item['referencia'],
                        'numero_autorizacion': item['numero_autorizacion'],
                        'codigo_autorizacion': item['codigo_autorizacion'],
                        'comercio': item['comercio'],
                        'entregado': item['entregado'],
                        'fecha_entregado': item['fecha_entregado'],
                        'codigo_error': item['codigo_error'],
                        'mensaje_error': item['mensaje_error'],
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

    def update(self, request, *args, **kwargs):
        try:
            from webhook.models import TransactionCollection
            db = TransactionCollection()
            filters = self.get_queryset_filters(*args, **kwargs)
            pk = kwargs.pop(self.field_pk)
            if len(pk) > 10:
                from bson.objectid import ObjectId
                filters['_id'] = ObjectId(pk)

            query = db.find(filters)
            if query:
                from webhook.tasks import send_transaction_emisor
                results = []
                for item in query:
                    send_transaction_emisor(transaction_id=str(item['_id']))
                    results.append(str(item['_id']))
                response_data = results[0] if len(results) > 0 else []
                self.make_response_success(data=response_data)
            else:
                self.make_response_not_found()
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def resend(self, request, *args, **kwargs):
        try:
            from webhook.models import TransactionCollection
            db = TransactionCollection()
            filters = self.get_queryset_filters(*args, **kwargs)
            filters['entregado'] = False

            query = db.find(filters)
            if query:
                from webhook.tasks import send_transaction_emisor
                results = []
                for item in query:
                    send_transaction_emisor(transaction_id=str(item['_id']))
                    time.sleep(3)
                    results.append(str(item['_id']))
                response_data = results[0] if len(results) > 0 else []
                self.make_response_success(data=response_data)
            else:
                self.make_response_not_found()
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()
