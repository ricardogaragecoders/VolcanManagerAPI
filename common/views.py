import json
from collections import OrderedDict
from datetime import datetime
from typing import Union

import newrelic.agent
import pymongo
from django.core import exceptions
from django.http import HttpResponse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from common.export_excel import WriteToExcel
from common.export_pdf import WriteToPdf
from common.middleware import get_request
from common.models import Status, MonitorCollection
from common.serializers import StatusSerializer
from common.utils import get_response_data_errors, handler_exception_general, handler_exception_404, \
    get_date_from_querystring, make_day_start, make_day_end
from users.permissions import IsVerified, IsChangePassword, IsAdministrator


class LimitOffsetSetPagination(LimitOffsetPagination):
    default_limit = 20
    max_limit = 100


class CustomViewSet(viewsets.GenericViewSet):
    model_class = None
    one_serializer_class = None
    list_serializer_class = None
    create_serializer_class = None
    update_serializer_class = None
    response_serializer_class = None
    serializer = None
    resp = []
    permission_classes = (IsAuthenticated, IsChangePassword)
    authentication_classes = (SessionAuthentication, BasicAuthentication, JWTAuthentication)
    field_pk = 'id'
    lookup_field = 'id'
    pk = None

    @newrelic.agent.background_task()
    def get_response(self, message: str = '', data: Union[dict, list] = {}, status: int = 200, lower_response=True):
        request = get_request()
        if len(self.resp) > 0:
            message = self.resp[0]
            data = self.resp[1]
            status = self.resp[2]
        response_data = dict()

        success = True if status == 200 or status == 201 else False
        message = data.pop('message') if 'message' in data else message
        code = data.pop('code') if 'code' in data else ''

        if request and request.session:
            if 'code' in request.session:
                code = request.session['code']
                del request.session['code']

        if not success and len(code) == 0:
            if status == 404:
                code = '404'
            elif status == 422:
                code = '422'
            else:
                code = '400'

        if isinstance(data, dict) and len(data) > 0:
            if 'RSP_CODIGO' in data:
                if data['RSP_CODIGO'].isnumeric():
                    if int(data['RSP_CODIGO']) > 0:
                        success = False
                        code = str(int(data['RSP_CODIGO'])).zfill(2)
                    else:
                        success = True
                        code = '00'
                    del data['RSP_CODIGO']
                elif data['RSP_CODIGO'] == '':
                    success = True
                    code = '00'
                    del data['RSP_CODIGO']
                else:
                    success = False
                    code = data['RSP_CODIGO']
                    del data['RSP_CODIGO']
            if 'RSP_DESCRIPCION' in data:
                message = data['RSP_DESCRIPCION']
                del data['RSP_DESCRIPCION']
            if 'RSP_ERROR' in data:
                del data['RSP_ERROR']

        response_data['RSP_SUCCESS'] = success
        response_data['RSP_CODIGO'] = code
        if isinstance(message, str):
            response_data['RSP_DESCRIPCION'] = message.strip() if message else ('ok' if success else 'error')
        else:
            response_data['RSP_DESCRIPCION'] = message

        if code == 'no_permissions':
            status = 403
            code = '403'
        if len(data) > 0:
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        internal_data = {}
                        for ki, vi in v.items():
                            internal_data[ki] = vi
                        response_data[k] = internal_data
                    else:
                        response_data[k] = v
            else:
                response_data['RSP_DATA'] = data
        response_data_2 = {}
        if lower_response:
            for k, v in response_data.items():
                response_data_2[k.lower()] = v
        else:
            for k, v in response_data.items():
                if k in ['RSP_SUCCESS', 'RSP_CODIGO', 'RSP_DESCRIPCION']:
                    response_data_2[k.lower()] = v
                else:
                    response_data_2[k] = v
        if status == 422 or status == 400 or status == 403:
            status = 200

        keys = list(response_data_2.keys())
        len_keys = 3 if len(keys) >= 3 else len(keys)
        response_data_string = {keys[i]: response_data_2[keys[i]] for i in range(len_keys)}
        newrelic.agent.add_custom_attributes(
            [
                ("response.json", json.dumps(response_data_string)),
            ]
        )

        return Response(response_data_2, status=status)

    def get_queryset_filters(self, *args, **kwargs):
        return {}

    def get_queryset_excludes(self, *args, **kwargs):
        return {}

    def get_queryset(self, *args, **kwargs):
        filters = self.get_queryset_filters(*args, **kwargs)
        if len(filters) > 0:
            return self.model_class.objects.filter(**filters)
        else:
            return self.model_class.objects.all()

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset(*args, **kwargs)
            self.serializer = self.get_list_serializer(queryset, many=True)
            self.perform_list(request, *args, **kwargs)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def perform_list(self, request, *args, **kwargs):
        self.make_response_success(data=self.serializer.data)

    def get_select_related_one(self):
        return []

    def get_prefetch_related_one(self):
        return []

    def get_object(self, pk=None, filters: dict = {}, values: list = []):
        if pk:
            filters = {self.lookup_field: pk}
        if len(values) == 0:
            return self.model_class.objects.select_related(
                *self.get_select_related_one()
            ).prefetch_related(
                *self.get_prefetch_related_one()
            ).get(**filters)
        else:
            return self.model_class.objects.values(*values).get(**filters)

    def retrieve(self, request, *args, **kwargs):
        try:
            self.pk = kwargs.pop(self.field_pk)
            self.perform_retrieve(request, *args, **kwargs)
        except self.model_class.DoesNotExist:
            self.make_response_not_found()
        except exceptions.ValidationError as e:
            self.resp = handler_exception_404(__name__, self.lookup_field, self.pk, e)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def perform_retrieve(self, request, *args, **kwargs):
        simple = request.query_params.get('simple', 'false')
        register = self.get_object(pk=self.pk)
        if simple == 'false':
            self.serializer = self.get_one_serializer(register)
        else:
            self.serializer = self.get_serializer(register)
        self.make_response_success(data=self.serializer.data)

    def create(self, request, *args, **kwargs):
        try:
            request_data = request.data if 'request_data' not in kwargs else kwargs['request_data']
            self.serializer = self.get_create_serializer(data=request_data)
            if self.serializer.is_valid():
                self.perform_create(request, *args, **kwargs)
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def perform_create(self, request, *args, **kwargs):
        response_simple = False if 'simple' not in kwargs else kwargs['simple']
        register = self.serializer.save()
        if response_simple:
            response_data = {'status': 'ok'}
        else:
            if not self.response_serializer_class:
                response_data = self.serializer.data
            else:
                response_data = self.response_serializer_class(register).data
        self.make_response_success(data=response_data, status=201)

    def make_response_success(self, message: str = '', data: Union[dict, list] = None, status: int = 200):
        self.resp = [message, data, status]

    def make_response_not_found(self):
        self.resp = ['Registro no encontrado', {}, 404]

    def update(self, request, *args, **kwargs):
        try:
            request_data = request.data if 'request_data' not in kwargs else kwargs['request_data']
            self.pk = kwargs.pop(self.field_pk)
            register = self.get_object(pk=self.pk)
            self.serializer = self.get_update_serializer(register, data=request_data, partial=True)
            if self.serializer.is_valid():
                self.perform_update(request, *args, **kwargs)
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except self.model_class.DoesNotExist:
            self.make_response_not_found()
        except exceptions.ValidationError as e:
            self.resp = handler_exception_404(__name__, self.lookup_field, self.pk, e)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def perform_update(self, request, *args, **kwargs):
        response_simple = False if 'simple' not in kwargs else kwargs['simple']
        register = self.serializer.save()
        if response_simple:
            response_data = {'status': 'ok'}
        else:
            if not self.response_serializer_class:
                response_data = self.serializer.data
            else:
                response_data = self.response_serializer_class(register).data
        self.make_response_success(data=response_data)

    def destroy(self, request, *args, **kwargs):
        try:
            self.pk = kwargs.pop(self.field_pk)
            register = self.get_object(pk=self.pk)
            if hasattr(register, 'status') or hasattr(register, 'active'):
                self.perform_destroy(request, register=register, *args, **kwargs)
            else:
                self.resp = ['Este modelo no tiene alguno de los siguientes campos: status o active.', {}, 400]
        except self.model_class.DoesNotExist:
            self.make_response_not_found()
        except exceptions.ValidationError as e:
            self.resp = handler_exception_404(__name__, self.lookup_field, self.pk, e)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def perform_destroy(self, request, *args, **kwargs):
        register = kwargs['register']
        if hasattr(register, 'status'):
            register.status = Status.objects.get(slug='deleted')
            if hasattr(register, 'deleted_at'):
                register.deleted_at = timezone.now()
            if hasattr(register, 'is_deleted'):
                register.is_deleted = True
            register.save()
        elif hasattr(register, 'is_active'):
            register.is_active = False
            if hasattr(register, 'deleted_at'):
                register.deleted_at = timezone.now()
            if hasattr(register, 'is_deleted'):
                register.is_deleted = True
            register.save()
        self.make_response_success('Registro borrado', {}, 204)

    def get_list_serializer(self, *args, **kwargs):
        serializer_class = self.get_list_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def get_list_serializer_class(self):
        if self.list_serializer_class:
            return self.list_serializer_class
        else:
            return self.get_serializer_class()

    def get_one_serializer(self, *args, **kwargs):
        serializer_class = self.get_one_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def get_one_serializer_class(self):
        if self.one_serializer_class:
            return self.one_serializer_class
        else:
            return self.get_serializer_class()

    def get_create_serializer(self, *args, **kwargs):
        serializer_class = self.get_create_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def get_create_serializer_class(self):
        if self.create_serializer_class:
            return self.create_serializer_class
        else:
            return self.get_serializer_class()

    def get_update_serializer(self, *args, **kwargs):
        serializer_class = self.get_update_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def get_update_serializer_class(self):
        if self.update_serializer_class:
            return self.update_serializer_class
        else:
            return self.get_serializer_class()

    def get_serializer(self, *args, **kwargs):
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def get_serializer_class(self):
        assert self.serializer_class is not None, (
                "'%s' should either include a `serializer_class` attribute, "
                "or override the `get_serializer_class()` method."
                % self.__class__.__name__
        )

        return self.serializer_class

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }


class CustomViewSetWithPagination(CustomViewSet):
    pagination_class = LimitOffsetSetPagination

    @property
    def paginator(self):
        """
        The paginator instance associated with the view, or `None`.
        """
        if not hasattr(self, '_paginator'):
            if self.pagination_class is None:
                self._paginator = None
            else:
                self._paginator = self.pagination_class()
        return self._paginator

    def paginate_queryset(self, queryset):
        """
        Return a single page of results, or `None` if pagination is disabled.
        """
        if self.paginator is None:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)

    def get_paginated_response(self, data):
        """
        Return a paginated style `Response` object for the given output data.
        """
        assert self.paginator is not None

        pages = int(self.paginator.count / self.paginator.limit)
        current_page = self.paginator.offset / self.paginator.limit

        return OrderedDict([
            ('pages', pages),
            ('current_page', current_page),
            ('limit', self.paginator.limit),
            ('offset', self.paginator.offset),
            ('count', self.paginator.count),
            ('next', self.paginator.get_next_link()),
            ('previous', self.paginator.get_previous_link()),
            ('results', data)
        ])

    def get_response_from_export(self, export):
        return export

    def list(self, request, *args, **kwargs):
        response = None
        try:
            self.queryset = self.get_queryset(*args, **kwargs)
            export = request.query_params.get('export', None)
            if not export:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_list_serializer(page, many=True)
                    response_data = self.get_paginated_response(serializer.data)
                    self.make_response_success(data=response_data)
            elif export:
                response = self.get_response_from_export(export=export)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            if not response:
                return self.get_response()
            return response


class StatusApiView(CustomViewSet):
    """
    get:
        Return all status
    """
    serializer_class = StatusSerializer
    model_class = Status
    permission_classes = (IsAuthenticated, IsVerified)
    http_method_names = ['get', 'options', 'head']


class MonitorCollectionApiView(CustomViewSetWithPagination):
    """
    get:
        Return all monitor systems from mongodb.
    retrieve:
        Return one monitor system from mongodb.
    """
    serializer_class = None
    model_class = None
    field_pk = 'monitor_system_id'
    permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
    http_method_names = ['get', 'options', 'head']

    def get_results(self, *args, **kwargs):
        username = self.request.query_params.get('username', '')
        issuer = self.request.query_params.get('issuer', '')
        status_code = int(self.request.query_params.get('status_code', '0'))
        rsp_success = self.request.query_params.get('rsp_success', 'all')
        self._limit = int(self.request.query_params.get('limit', 20))
        self._offset = int(self.request.query_params.get('offset', 0))
        self._page = int(self._offset / self._limit) if self._offset > 0 else 0
        self._order_by = self.request.query_params.get('orderBy', 'action')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        q = self.request.query_params.get('q', None)
        export = self.request.query_params.get('export', None)

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
            filters['created_at'] = {
                "$gte": from_date,
                "$lt": to_date
            }
        elif s_from_date:
            filters['created_at'] = {
                "$gte": from_date
            }
        elif s_to_date:
            filters['created_at'] = {
                "$lt": to_date
            }

        if status_code > 0:
            filters['status_code'] = status_code

        if rsp_success != "all":
            filters['response_data.rsp_success'] = rsp_success == "true"

        if len(username) > 0:
            filters['user.username'] = username

        if len(issuer) > 0:
            filters['user.emisor'] = issuer

        if q:
            filters['$or'] = [
                {'url': {'$regex': q, '$options': 'i'}},
                {'method': {'$regex': q, '$options': 'i'}},
                {'user.username': {'$regex': q, '$options': 'i'}},
                {'user.emisor': {'$regex': q, '$options': 'i'}},
                {'headers.X-Correlation-Id': {'$regex': q, '$options': 'i'}}
            ]

        db = MonitorCollection()
        self._total = db.count_all(filters)

        if not export:
            return db.find(filters, sort, direction, self._limit, self._page)
        else:
            return db.find(filters, sort, direction, self._total, self._page)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.results:
            rsp_success = True
            rsp_codigo = 200
            rsp_descripcion = 'ok'
            x_correlation_id = ''
            if 'response_data' in item:
                if 'rsp_success' in item['response_data']:
                    rsp_success = item['response_data']['rsp_success']
                if 'rsp_codigo' in item['response_data']:
                    rsp_codigo = item['response_data']['rsp_codigo']
                if 'rsp_descripcion' in item['response_data']:
                    rsp_descripcion = item['response_data']['rsp_descripcion']

            if 'headers' in item:
                if 'X-Correlation-Id' in item['headers']:
                    x_correlation_id = item['headers']['X-Correlation-Id']

            data = {
                'ID': item['id'],
                _('fecha'): timezone.localtime(item['created_at']).strftime("%d/%m/%Y %H:%M"),
                _('username'): item['user.username'],
                _('emisor'): item['user.emisor'],
                _('status_code'): item['status_code'],
                _('method'): item['method'],
                _('url'): item['url'],
                _('X-Correlaction-Id'): x_correlation_id,
                _('success'): rsp_success,
                _('code'): rsp_codigo,
                _('descripiton'): rsp_descripcion,
            }
            response_data.append(data)
        fields = ['ID', _('fecha'), _('username'), _('emisor'), _('status_code'), _('method'), _('url'),
                  _('X-Correlaction-Id'), _('success'), _('code'), _('descripiton')]
        title = _(u'Bitacora')
        if export == 'excel':
            xlsx_data = WriteToExcel(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = 'attachment; filename=Bitacora.xlsx'
            response.write(xlsx_data)
        else:
            pdf_data = WriteToPdf(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachement; filename=Bitacora.pdf'
            response['Content-Transfer-Encoding'] = 'binary'
            response.write(pdf_data)
        return response

    def get(self, request, *args, **kwargs):
        response = None
        try:
            from bson.json_util import dumps
            # import pytz
            query = self.get_results()
            results = []
            # local_tz = pytz.timezone('America/Mexico_City')
            for item in query:
                if isinstance(item['created_at'], datetime):
                    created_at = timezone.localtime(item['created_at']).isoformat()
                else:
                    created_at = item['created_at']
                results.append({
                    'id': '{}'.format(str(item['_id'])),
                    'user': item['user'],
                    'endpoint': f"{item['method']}: {item['url']}",
                    'request_data': item['request_data'] if 'request_data' in item else '',
                    'response_data': item['response_data'] if 'response_data' in item else '',
                    'status_code': item['status_code'] if 'status_code' in item else '',
                    'created_at': created_at
                })
            export = request.query_params.get('export', None)
            if not export:
                pages = int(self._total / self._limit)
                current_page = self._offset / self._limit
                response_data = {
                    'pages': pages,
                    'current_page': current_page,
                    'limit': self._limit,
                    'offset': self._offset,
                    'count': self._total,
                    'results': results
                }
                self.make_response_success(data=response_data)
            else:
                self.results = results
                response = self.get_response_from_export(export=export)
        except Exception as e:
            from common.utils import handler_exception_general
            self.resp = handler_exception_general(__name__, e)
        finally:
            if not response:
                return self.get_response()
            return response

    def retrieve(self, request, *args, **kwargs):
        try:
            from common.models import MonitorCollection
            db = MonitorCollection()
            pk = kwargs.pop(self.field_pk)
            query = None
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
                    if isinstance(item['created_at'], datetime):
                        created_at = timezone.localtime(item['created_at']).isoformat()
                    else:
                        created_at = item['created_at']

                    results.append({
                        'id': '{}'.format(str(item['_id'])),
                        'user': item['user'],
                        'method': item['method'],
                        'url':  item['url'],
                        'headers': item['headers'],
                        'request_data': item['request_data'] if 'request_data' in item else '',
                        'response_data': item['response_data'] if 'response_data' in item else '',
                        'status_code': item['status_code'] if 'status_code' in item else '',
                        'time_seconds': item['time_seconds'],
                        'created_at': created_at
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
