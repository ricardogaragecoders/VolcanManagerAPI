from collections import OrderedDict
from typing import Union

from django.core import exceptions
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from common.middleware import get_request
from common.models import Status
from common.serializers import StatusSerializer
from common.utils import get_response_data_errors, handler_exception_general, handler_exception_404
from users.permissions import IsVerified, IsChangePassword


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


