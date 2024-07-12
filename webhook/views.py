import time

import pymongo
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated, AllowAny

from common.utils import get_date_from_querystring, make_day_start, make_day_end, get_response_data_errors
from common.views import CustomViewSet, CustomViewSetWithPagination
from users.permissions import IsVerified, IsOperator
from webhook.models import Webhook, TransactionErrorCollection, NotificationCollection
from webhook.permissions import HasPermissionByMethod, HasUserAndPasswordInData
from webhook.serializers import WebhookSerializer, WebhookListSerializer, TransactionSerializer, \
    PaycardNotificationserializer
from webhook.utils import get_notification_data


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
        if profile.is_admin(equal=False):
            account_issuer = self.request.query_params.get('issuer_id', '')
        elif profile.is_operator():
            account_issuer = profile.user.first_name
        else:
            account_issuer = 'sin_emision'
        filters = {'deleted_at__isnull': True}

        if len(account_issuer) > 0:
            filters['account_issuer'] = account_issuer

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
        if hasattr(register, 'is_active'):
            register.is_active = False
            if hasattr(register, 'deleted_at'):
                register.deleted_at = timezone.now()
            if hasattr(register, 'is_deleted'):
                register.is_deleted = True
            register.save()
        response_data = {'rsp_codigo': '204', 'rsp_descripcion': u'Webhook borrado'}
        self.make_response_success(data=response_data, status=204)


class NotificationTransactionApiView(CustomViewSetWithPagination):
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
    serializer_class = TransactionSerializer
    model_class = NotificationCollection
    field_pk = 'notification_id'
    permission_classes = (HasPermissionByMethod,)
    http_method_names = ['get', 'post', 'patch', 'options', 'head']
    method_permissions = {
        'POST': [AllowAny, ],
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
        if profile.is_superadmin():
            issuer = self.request.query_params.get('emisor', '')
        elif profile.is_operator(equal=True):
            issuer = profile.user.first_name
        else:
            issuer = 'sin_emision'

        s_from_date = self.request.query_params.get('from_date', None)
        s_to_date = self.request.query_params.get('to_date', None)
        from_date = get_date_from_querystring(self.request, 'from_date', timezone.localtime(timezone.now()))
        to_date = get_date_from_querystring(self.request, 'to_date', timezone.localtime(timezone.now()))
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)
        if s_from_date and s_to_date:
            filters['created_at'] = {"$gte": from_date, "$lt": to_date}
        elif s_from_date:
            filters['created_at'] = {"$gte": from_date}
        elif s_to_date:
            filters['created_at'] = {"$lt": to_date}

        if len(issuer) > 0:
            filters['issuer.issuer'] = issuer.upper()

        return filters

    def get_queryset(self, *args, **kwargs):
        filters = self.get_queryset_filters(*args, **kwargs)
        notification_type = self.request.query_params.get('nType', 'transaction')
        filters['notification_type.type'] = notification_type
        self._limit = int(self.request.query_params.get('limit', 20))
        self._offset = int(self.request.query_params.get('offset', 0))
        self._page = int(self._offset / self._limit) if self._offset > 0 else 0
        self._order_by = self.request.query_params.get('orderBy', 'created_at')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        q = self.request.query_params.get('q', None)
        # export = self.request.query_params.get('export', None)
        sort = self._order_by
        direction = pymongo.ASCENDING if order_by_desc == 'false' else pymongo.DESCENDING
        if notification_type == 'transaction':
            if q:
                filters['$or'] = [
                    {'notification.tarjeta': {'$regex': q, '$options': 'i'}},
                    {'notification.referencia': {'$regex': q, '$options': 'i'}},
                    {'notification.numero_autorizacion': {'$regex': q, '$options': 'i'}},
                    {'notification.codigo_autorizacion': {'$regex': q, '$options': 'i'}},
                    {'notification.email': {'$regex': q, '$options': 'i'}},
                    {'notification.tarjetahabiente': {'$regex': q, '$options': 'i'}},
                    {'notification.comercio': {'$regex': q, '$options': 'i'}}
                ]
        else:
            pass

        db = NotificationCollection()
        self._total = db.collection.count_documents(filters)

        return db.find(filters, sort, direction, self._limit, self._page)

    def create(self, request, *args, **kwargs):
        try:
            print(f"Request encoding: {request.encoding}")
            if not request.encoding:
                request.encoding = 'utf-8'
            self.serializer = self.get_serializer(data=request.data)
            if self.serializer.is_valid():
                db = NotificationCollection()
                validated_data = self.serializer.validated_data
                result = db.insert_one(data=validated_data)
                from webhook.tasks import send_notification_webhook_issuer
                send_notification_webhook_issuer.delay(notification_id=str(result.inserted_id))
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
            print(f"Request: {request.body}")
            data = {
                'request_data': request.body,
                'error': "%s" % e,
                'created_at': timezone.localtime(timezone.now()),
            }
            db.insert_one(data=data)
            self.resp = ["%s" % e, {'code': 'error'}, 400]
        except Exception as e:
            from common.utils import handler_exception_general
            db = TransactionErrorCollection()
            print(f"Request: {request.body}")
            data = {
                'request_data': request.data,
                'error': self.resp[0],
                'created_at': timezone.localtime(timezone.now()),
            }
            db.insert_one(data=data)
            self.resp = ["%s" % e, {'code': 'error'}, 500]
        finally:
            return self.get_response()

    def paycard_notification(self, request, *args, **kwargs):
        self.serializer_class = PaycardNotificationserializer
        return self.create(request, *args, **kwargs)


    def list(self, request, *args, **kwargs):
        try:
            query = self.get_queryset(*args, **kwargs)
            results = []
            for item in query:
                # created_at = item['created_at'].strftime("%d/%m/%Y %H:%M:%S")
                results.append({
                    'id': str(item['_id']),
                    'user': item['user'],
                    'notification': get_notification_data(item['notification']),
                    'notification_type': item['notification_type'],
                    'webhook': item['webhook'],
                    'delivery': item['delivery'],
                    'response': item['response'],
                    'issuer': item['issuer'],
                    'created_at': item['created_at']
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
            from bson.objectid import ObjectId
            db = self.model_class()
            filters = self.get_queryset_filters(*args, **kwargs)
            pk = kwargs.pop(self.field_pk)
            if len(pk) > 10:
                filters['_id'] = ObjectId(pk)

            item = db.find_one(filters)
            if item:
                # created_at = item['created_at'].strftime("%d/%m/%Y %H:%M:%S")
                response_data = {
                    'RSP_CODIGO': '00',
                    'RSP_DESCRIPCION': 'Aprobado',
                    'notification': {
                        'id': str(item['_id']),
                        'user': item['user'],
                        'notification': get_notification_data(item['notification']),
                        'notification_type': item['notification_type'],
                        'webhook': item['webhook'],
                        'delivery': item['delivery'],
                        'response': item['response'],
                        'issuer': item['issuer'],
                        'created_at': item['created_at']
                    }
                }
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
            db = self.model_class()
            filters = self.get_queryset_filters(*args, **kwargs)
            pk = kwargs.pop(self.field_pk)
            if len(pk) > 10:
                from bson.objectid import ObjectId
                filters['_id'] = ObjectId(pk)

            query = db.find(filters)
            if query:
                from webhook.tasks import send_notification_webhook_issuer
                results = []
                for item in query:
                    send_notification_webhook_issuer.delay(notification_id=str(item['_id']))
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
            db = NotificationCollection()
            filters = self.get_queryset_filters(*args, **kwargs)
            filters['delivery.delivered'] = False

            query = db.find(filters)
            if query:
                from webhook.tasks import send_notification_webhook_issuer
                results = []
                for item in query:
                    send_notification_webhook_issuer.delay(transaction_id=str(item['_id']))
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


class TransactionErrorApiView(CustomViewSetWithPagination):
    """
    get:
        Return all transactions error from mongodb.
    """
    serializer_class = TransactionSerializer
    model_class = TransactionErrorCollection
    field_pk = 'notification_error_id'
    permission_classes = (HasPermissionByMethod,)
    http_method_names = ['get', 'options', 'head']
    method_permissions = {
        'GET': [IsAuthenticated, IsVerified, IsOperator]
    }
    _limit = 20
    _offset = 0
    _page = 0
    _order_by = 'action'
    _total = 0

    def get_queryset_filters(self, *args, **kwargs):
        filters = dict()
        profile = self.request.user.profile
        if profile.is_superadmin():
            issuer = self.request.query_params.get('emisor', '')
        elif profile.is_operator(equal=True):
            issuer = profile.user.first_name
        else:
            issuer = 'sin_emision'

        s_from_date = self.request.query_params.get('from_date', None)
        s_to_date = self.request.query_params.get('to_date', None)
        from_date = get_date_from_querystring(self.request, 'from_date', timezone.localtime(timezone.now()))
        to_date = get_date_from_querystring(self.request, 'to_date', timezone.localtime(timezone.now()))
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)
        if s_from_date and s_to_date:
            filters['created_at'] = {"$gte": from_date, "$lt": to_date}
        elif s_from_date:
            filters['created_at'] = {"$gte": from_date}
        elif s_to_date:
            filters['created_at'] = {"$lt": to_date}

        if len(issuer) > 0:
            filters['request_data.emisor'] = issuer.upper()

        return filters

    def get_queryset(self, *args, **kwargs):
        filters = self.get_queryset_filters(*args, **kwargs)
        self._limit = int(self.request.query_params.get('limit', 20))
        self._offset = int(self.request.query_params.get('offset', 0))
        self._page = int(self._offset / self._limit) if self._offset > 0 else 0
        self._order_by = self.request.query_params.get('orderBy', 'created_at')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        q = self.request.query_params.get('q', None)
        # export = self.request.query_params.get('export', None)
        sort = self._order_by
        direction = pymongo.ASCENDING if order_by_desc == 'false' else pymongo.DESCENDING
        if q:
            filters['$or'] = [
                {'request_data.tarjeta': {'$regex': q, '$options': 'i'}},
                {'request_data.referencia': {'$regex': q, '$options': 'i'}},
                {'request_data.numero_autorizacion': {'$regex': q, '$options': 'i'}},
                {'request_data.codigo_autorizacion': {'$regex': q, '$options': 'i'}},
                {'request_data.email': {'$regex': q, '$options': 'i'}},
                {'request_data.tarjetahabiente': {'$regex': q, '$options': 'i'}},
                {'request_data.comercio': {'$regex': q, '$options': 'i'}}
            ]

        db = self.model_class()
        self._total = db.collection.count_documents(filters)

        return db.find(filters, sort, direction, self._limit, self._page)

    def list(self, request, *args, **kwargs):
        try:
            query = self.get_queryset(*args, **kwargs)
            results = []
            for item in query:
                # created_at = item['created_at'].strftime("%d/%m/%Y %H:%M:%S")
                results.append({
                    'id': str(item['_id']),
                    'data': item['request_data'],
                    'error': item['error'],
                    'created_at': item['created_at']
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
            from bson.objectid import ObjectId
            db = self.model_class()
            filters = self.get_queryset_filters(*args, **kwargs)
            pk = kwargs.pop(self.field_pk)
            if len(pk) > 10:
                filters['_id'] = ObjectId(pk)

            item = db.find_one(filters)
            if item:
                # created_at = item['created_at'].strftime("%d/%m/%Y %H:%M:%S")
                response_data = {
                    'RSP_CODIGO': '00',
                    'RSP_DESCRIPCION': 'Aprobado',
                    'transaction_error': {
                        'id': str(item['_id']),
                        'data': item['request_data'],
                        'error': item['error'],
                        'created_at': item['created_at']
                    }
                }
                self.make_response_success(data=response_data)
            else:
                self.make_response_not_found()
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()
