from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponse
from common.export_excel import WriteToExcel
from common.export_pdf import WriteToPdf
from common.utils import is_valid_uuid
from common.views import CustomViewSet, CustomViewSetWithPagination
from control.models import Company, Operator
from control.serializers import CompanySerializer, OperatorSerializer
from users.permissions import IsVerified, IsOperator, IsAdministrator

import logging

logger = logging.getLogger(__name__)


class CompanyApiView(CustomViewSetWithPagination):
    """
    get:
        Return all companies
    """
    serializer_class = CompanySerializer
    model_class = Company
    permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
    field_pk = 'issuer_id'

    def initial(self, request, *args, **kwargs):
        if self.request.method == "GET":
            self.permission_classes = (IsAuthenticated, IsVerified, IsOperator)
        else:
            self.permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        status = self.request.query_params.get('st', 'all')
        company_id = int(self.request.query_params.get('cId', 0))
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'name')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        filters = dict()
        queryset = self.model_class.objects.all()

        if company_id > 0:
            filters['id__in'] = [company_id, ]

        if status != 'all':
            filters['is_active'] = status == 'true'

        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(name__icontains=q) |
                Q(issuer_id__icontains=q) |
                Q(thales_issuer_id__icontains=q) |
                Q(slug__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.queryset:
            data = {
                'ID': item.id,
                _('nombre'): item.name,
                _('issuer_id'): item.issuer_id,
                _('thales_issuer_id'): item.thales_issuer_id,
                _('status'): 'Activo' if item.is_active else 'Inactivo',
            }
            response_data.append(data)
        fields = ['ID', _('nombre'), _('issuer_id'), _('thales_issuer_id'), _('estatus'), ]
        title = _(u'Empresas')
        if export == 'excel':
            xlsx_data = WriteToExcel(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = 'attachment; filename=Empresas.xlsx'
            response.write(xlsx_data)
        else:
            pdf_data = WriteToPdf(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachement; filename=Empresas.pdf'
            response['Content-Transfer-Encoding'] = 'binary'
            response.write(pdf_data)
        return response


class OperatorApiView(CustomViewSetWithPagination):
    """
    get:
        Return all operators
    """
    serializer_class = OperatorSerializer
    create_serializer_class = OperatorSerializer
    model_class = Operator
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    field_pk = 'operator_id'

    def initial(self, request, *args, **kwargs):
        if self.request.method == "GET":
            self.permission_classes = (IsAuthenticated, IsVerified, IsOperator)
        else:
            self.permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        status = self.request.query_params.get('st', 'all')
        company_id = self.request.query_params.get('cId', '')
        operator_id = self.request.query_params.get('oId', '')
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'id')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        filters = dict()
        queryset = self.model_class.objects.all()

        if is_valid_uuid(operator_id):
            filters['id'] = operator_id

        if is_valid_uuid(company_id):
            filters['company_id'] = company_id

        if status != 'all':
            filters['active'] = status == 'true'

        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(operator_name__icontains=q) |
                Q(profile__email__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.queryset:
            data = {
                'ID': item.id,
                _('nombre'): item.profile.get_full_name() if item.profile and item.profile.user else 'Sin profile',
                _('email'): item.profile.email if item.profile and item.profile.user else '',
                _('empresa'): item.company.name if item.company else 'Sin empresa',
                _('estatus'): 'Activo' if item.active else 'Inactivo',
                _('role'): ' '.join(item.profile.role),
            }
            response_data.append(data)
        fields = ['ID', _('nombre'), _('email'), _('empresa'), _('estatus'), _('roles'), ]
        title = _(u'Operadores')
        if export == 'excel':
            xlsx_data = WriteToExcel(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = 'attachment; filename=Operadores.xlsx'
            response.write(xlsx_data)
        else:
            pdf_data = WriteToPdf(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachement; filename=Operadores.pdf'
            response['Content-Transfer-Encoding'] = 'binary'
            response.write(pdf_data)
        return response


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
                    pass
            else:
                logger.error(request.user.profile.get_full_name())
                logger.error(response_data)
        except ParseError as e:
            logger.exception(e)
            response_data = {'RSP_CODIGO': '-1', 'RSP_DESCRIPCION': "%s" % e}
            response_message = "%s" % e
            response_status = 400
        except Exception as e:
            logger.exception(e)
            response_message = u"Error en applicación"
            response_status = 500
        finally:
            return self.get_response(response_message, response_data, response_status)

    def creation_ente(self, request, *args, **kwargs):
        from control.utils import creation_ente
        return self.control_action(request=request, control_function=creation_ente,
                                   name_control_function="creation_ente")

    def creation_ente_sectorizacion(self, request, *args, **kwargs):
        from control.utils import creation_ente_sectorizacion
        return self.control_action(request=request, control_function=creation_ente_sectorizacion,
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

    def gestion_transacciones(self, request, *args, **kwargs):
        from control.utils import gestion_transacciones
        return self.control_action(request=request, control_function=gestion_transacciones,
                                   name_control_function="gestion_transacciones")

    def consulta_ente(self, request, *args, **kwargs):
        from control.utils import consulta_ente
        return self.control_action(request=request, control_function=consulta_ente,
                                   name_control_function="consulta_ente")

    def consulta_movimientos(self, request, *args, **kwargs):
        from control.utils import consulta_movimientos
        return self.control_action(request=request, control_function=consulta_movimientos,
                                   name_control_function="consulta_movimientos")

    def consulta_puntos(self, request, *args, **kwargs):
        from control.utils import consulta_puntos
        return self.control_action(request=request, control_function=consulta_puntos,
                                   name_control_function="consulta_puntos")

    def intra_extras(self, request, *args, **kwargs):
        from control.utils import intra_extras_mock
        return self.control_action(request=request, control_function=intra_extras_mock,
                                   name_control_function="intra_extras_mock")

    def consulta_intra_extra_f1(self, request, *args, **kwargs):
        from control.utils import consulta_intra_extra_f1
        return self.control_action(request=request, control_function=consulta_intra_extra_f1,
                                   name_control_function="consulta_intra_extra_f1")

    def consulta_transaciones_x_fecha(self, request, *args, **kwargs):
        from control.utils import consulta_transaciones_x_fecha
        return self.control_action(request=request, control_function=consulta_transaciones_x_fecha,
                                   name_control_function="consulta_txn_x_fecha_1")

    def consulta_cvv2(self, request, *args, **kwargs):
        from control.utils import consulta_cvv2
        return self.control_action(request=request, control_function=consulta_cvv2,
                                   name_control_function="consulta_cvv2")

    def consulta_estado_cuenta(self, request, *args, **kwargs):
        from control.utils import consulta_estado_cuenta
        return self.control_action(request=request, control_function=consulta_estado_cuenta,
                                   name_control_function="consulta_estado_cuenta")

    def consulta_cobranza(self, request, *args, **kwargs):
        from control.utils import consulta_cobranza
        return self.control_action(request=request, control_function=consulta_cobranza,
                                   name_control_function="consulta_cobranza")

    def alta_poliza(self, request, *args, **kwargs):
        from control.utils import alta_poliza
        return self.control_action(request=request, control_function=alta_poliza,
                                   name_control_function="alta_poliza")

    def consulta_poliza(self, request, *args, **kwargs):
        from control.utils import consulta_poliza
        return self.control_action(request=request, control_function=consulta_poliza,
                                   name_control_function="consulta_poliza")

    def intra_extra_especial(self, request, *args, **kwargs):
        from control.utils import intra_extra_especial
        return self.control_action(request=request, control_function=intra_extra_especial,
                                   name_control_function="intra_extra_especial")

    def consulta_intra_extra_esquema(self, request, *args, **kwargs):
        from control.utils import consulta_intra_extra_esquema
        return self.control_action(request=request, control_function=consulta_intra_extra_esquema,
                                   name_control_function="consulta_intra_extra_esquema")

    def consulta_esquemas_financiamiento(self, request, *args, **kwargs):
        from control.utils import consulta_esquemas_financiamiento
        return self.control_action(request=request, control_function=consulta_esquemas_financiamiento,
                                   name_control_function="consulta_esquemas_financiamiento")

    def refinanciamiento(self, request, *args, **kwargs):
        from control.utils import refinanciamiento
        return self.control_action(request=request, control_function=refinanciamiento,
                                   name_control_function="refinanciamiento")
