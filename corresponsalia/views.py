import logging
from datetime import datetime
from gettext import translation
from typing import Optional
from django.core.cache import cache

import pytz
import rest_framework.status
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import IsAuthenticated

from django.http import HttpResponse
from common.export_excel import WriteToExcel
from common.export_pdf import WriteToPdf
from common.utils import is_valid_uuid, get_response_data_errors, handler_exception_general, \
    get_datetime_from_querystring, model_code_generator
from common.views import CustomViewSetWithPagination
from control.utils import process_volcan_api_request
from corresponsalia.models import Corresponsalia, TransaccionCorresponsalia, TransaccionCorresponsaliaCollection
from corresponsalia.serializers import CorresponsaliaSerializer, \
    CorresponsaliaSimpleSerializer, TransaccionCorresponsaliaSerializer, \
    CreateTransaccionCorresponsaliaSerializer, TransaccionCorresponsaSimpleliaSerializer
from thalesapi.models import CardBinConfig, CardType
from thalesapi.utils import get_card_triple_des_process
from users.permissions import IsVerified, IsOperator, IsAdministrator
from volcanmanagerapi import settings

logger = logging.getLogger(__name__)


class CorresponsaliaApiView(CustomViewSetWithPagination):
    """
    get:
        Return all coresponsalias
    """
    serializer_class = CorresponsaliaSimpleSerializer
    create_serializer_class = CorresponsaliaSerializer
    update_serializer_class = CorresponsaliaSerializer
    one_serializer_class = CorresponsaliaSerializer
    response_serializer_class = CorresponsaliaSimpleSerializer
    model_class = Corresponsalia
    permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
    field_pk = 'corresponsalia_id'

    def initial(self, request, *args, **kwargs):
        if self.request.method == "POST":
            self.permission_classes = (IsAuthenticated, IsVerified, IsOperator)
        else:
            self.permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        issuer_id = self.request.query_params.get('iss', '')
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'description')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        filters = dict(is_active=True)
        queryset = self.model_class.objects.all()

        if len(issuer_id) > 0:
            filters['company__volcan_issuer_id'] = issuer_id


        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(description__icontains=q) |
                Q(country__icontains=q) |
                Q(city__icontains=q) |
                Q(branch__icontains=q) |
                Q(user_payload__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.queryset:
            data = {
                'id_corresponalia': str(item.id),
                _('descripcion'): item.description,
                _('pais'): item.country,
                _('ciudad'): item.city,
                _('sucursal'): item.branch,
                _('usuario_paycard'): item.user_paycard,
                _('password_paycard'): item.pass_paycard,
                _('emisor'): item.company.volcan_issuer_id,
                _('estatus'): 'Activo' if item.is_active else 'Inactivo',
            }
            response_data.append(data)
        fields = ['id_corresponalia', _('descripcion'), _('pais'), _('ciudad'), _('sucursal'), _('usuario_paycard'),
                  _('password_paycard'), _('password_paycard'), _('estatus')]
        title = _(u'Corresponsalia')
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



class TransaccionApiView(CustomViewSetWithPagination):
    serializer_class = TransaccionCorresponsaSimpleliaSerializer
    create_serializer_class = CreateTransaccionCorresponsaliaSerializer
    one_serializer_class = TransaccionCorresponsaliaSerializer
    model_class = TransaccionCorresponsalia
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    field_pk = 'transaccion_id'

    def initial(self, request, *args, **kwargs):
        if self.request.method == "POST":
            self.permission_classes = (IsAuthenticated, IsVerified, IsOperator)
        else:
            self.permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        corresponsalia_id = self.request.query_params.get('coId', '')
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'created_at')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        filters = dict(is_active=True)
        queryset = self.model_class.objects.all()
        request = self.request

        from_date = get_datetime_from_querystring(request=request, date_find='from_date', default_value=None)
        to_date = get_datetime_from_querystring(request=request, date_find='to_date', default_value=None)

        if from_date and to_date:
            filters['created_at__date__range'] = (from_date, to_date)
        elif from_date:
            filters['created_at__date__gte'] = from_date
        elif to_date:
            filters['created_at__date__lte'] = to_date

        if is_valid_uuid(corresponsalia_id):
            filters['corresponsalia_id'] = corresponsalia_id


        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(card_number__icontains=q) |
                Q(reference__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_response_from_export(self, export):
        response_data = []
        for item in self.queryset:
            data = {
                'id_transaccion': str(item.id),
                'id_corresponsalia': str(item.corresponsalia_id),
                'tarjeta': item.card_number,
                'moneda': item.currency.abr_code,
                'codigo_movimiento': item.movement_code,
                'importe': item.amount,
                'referencia_numerica': item.reference,
                'estatus': item.get_status_display(),
                'fecha_creacion': item.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            response_data.append(data)
        fields = ['id_transaccion', 'id_corresponsalia', 'tarjeta', 'moneda', 'codigo_movimiento',
                  'importe', 'referencia_numerica', 'estatus', 'fecha_creacion']
        title = _(u'TransaccionesCorresponsalia')
        if export == 'excel':
            xlsx_data = WriteToExcel(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = 'attachment; filename=TransaccionesCorresponsalia.xlsx'
            response.write(xlsx_data)
        else:
            pdf_data = WriteToPdf(response_data, title=title, fields=fields)
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachement; filename=TransaccionesCorresponsalia.pdf'
            response['Content-Transfer-Encoding'] = 'binary'
            response.write(pdf_data)
        return response

    def create(self, request, *args, **kwargs):
        try:
            request_data = request.data if 'request_data' not in kwargs else kwargs['request_data']
            self.serializer = self.get_create_serializer(data=request_data)
            if self.serializer.is_valid():
                card_bin_config: CardBinConfig = self.serializer.validated_data.get('card_bin_config', None)
                if card_bin_config:
                    transaction_corresponsalia = self.serializer.save()
                    if card_bin_config.card_type == CardType.CT_PREPAID:
                        self.create_prepaid_transaction(request=request, transaction=transaction_corresponsalia)
                    elif card_bin_config.card_type == CardType.CT_CREDIT:
                        self.create_credit_transaction(request=request, transaction=transaction_corresponsalia)
                    else:
                        self.make_response_success(status=rest_framework.status.HTTP_404_NOT_FOUND,
                                                   message='Tipo de tarjeta no identificado')
                else:
                    self.make_response_success(status=rest_framework.status.HTTP_404_NOT_FOUND,
                                               message='BIN no registrado')
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()

    def get_credentials_paycad(self, corresponsalia: Corresponsalia):
        key_cache = f'credentials-{str(corresponsalia.id)}'
        if key_cache not in cache:
            import base64
            userpass = f'{corresponsalia.user_paycard}:{corresponsalia.pass_paycard}'
            cache.set(key_cache, base64.b64encode(userpass.encode()).decode(), 60 * 60 * 2)
        return cache.get(key_cache)

    def get_access_token_paycard(self, corresponsalia: Corresponsalia):
        key_cache = f'access_token-{str(corresponsalia.id)}'
        if key_cache not in cache:
            url_server = settings.SERVER_VOLCAN_PARABILIA_URL
            api_url = f'{url_server}{settings.URL_PARABILIA_LOGIN}'
            data_json = {
                'NombreUsuario': corresponsalia.user_paycard,
                'Password': corresponsalia.pass_paycard
            }
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                "Credenciales": self.get_credentials_paycad(corresponsalia)
            }
            resp = process_volcan_api_request(data=data_json, url=api_url, headers=headers)
            if resp[1] == 200:
                cache.set(key_cache, resp[0]['Token'], 30)
                corresponsalia.access_token_paycard = resp[0]['Token']
                corresponsalia.save()
        return cache.get(key_cache) if key_cache in cache else None

    def create_prepaid_transaction(self, request, *args, **kwargs):
        transaction_corresponsalia: Optional[TransaccionCorresponsalia] = kwargs.get('transaction', None)
        assert transaction_corresponsalia, "La transaccion no fue proporcionada"
        access_token_paycard = self.get_access_token_paycard(corresponsalia=transaction_corresponsalia.corresponsalia)
        if not access_token_paycard:
            return self.get_response(status=400, message='No fue posible hacer login a PAYCARD')

        headers = {
            'Credenciales': self.get_credentials_paycad(corresponsalia=transaction_corresponsalia.corresponsalia),
            'Authorization': f"{access_token_paycard}",
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        request_data = {
            "IDSolicitud": "1",
            "Tarjeta": get_card_triple_des_process(transaction_corresponsalia.card_number, is_descript=False),
            "MedioAcceso": "",
            "TipoMedioAcceso": "",
            "Importe": transaction_corresponsalia.amount,
            "ClaveMovimiento": transaction_corresponsalia.movement_code,
            "RefNumerica": transaction_corresponsalia.reference,
            "Observaciones": "",
            "ConceptoPago": ""
        }
        url_server = settings.SERVER_VOLCAN_PARABILIA_URL
        api_url = f'{url_server}{settings.URL_PARABILIA_MOVIMIENTO_MANUAL}'

        resp_msg, resp_data, response_status = process_volcan_api_request(data=request_data, headers=headers,
                                                                          url=api_url, request=request, times=0)
        if response_status == 200:
            if resp_data['CodRespuesta'] == '0000' or len(resp_data['Tarjeta']) > 0:
                transaction_corresponsalia.authorization = model_code_generator(TransaccionCorresponsalia, 32,
                                                                                code='authorization')
                transaction_corresponsalia.save()
                db = TransaccionCorresponsaliaCollection()
                db.insert_one(data={
                    "transaction_id": str(transaction_corresponsalia.id),
                    "request_data": request_data,
                    "response_data": {k.lower(): v.lower() for k, v, in resp_data.items()}
                })
                self.make_response_success(status=response_status, message="Transacción aprobada", data={
                    "RSP_ERROR": "OK",
                    "RSP_CODIGO": "0000000000",
                    'RSP_DESCRIPCION': "Transacción aprobada",
                    'id_corresponsalia': str(transaction_corresponsalia.corresponsalia.id),
                    'autorizacion': transaction_corresponsalia.authorization,
                    'importe': transaction_corresponsalia.amount,
                    'moneda': transaction_corresponsalia.currency.number_code
                })
                return True
        self.make_response_success(status=response_status, message=resp_msg, data=resp_data)


    def create_credit_transaction(self, request, *args, **kwargs):
        transaction_corresponsalia: Optional[TransaccionCorresponsalia] = kwargs.get('transaction', None)
        assert transaction_corresponsalia, "La transaccion no fue proporcionada"
        from control.utils import gestion_transacciones

        request_data = {
                "tarjeta": transaction_corresponsalia.card_number,
                "transaccion": transaction_corresponsalia.movement_code,
                "importe": transaction_corresponsalia.amount,
                "moneda": transaction_corresponsalia.currency.number_code,
                "fecha_trx": transaction_corresponsalia.created_at.strftime("%Y%m%d"),
                "hora_trx": transaction_corresponsalia.created_at.strftime("%H%M%S"),
                "origen_mov": "",
                "referencia": "",
                "doc_oper": "",
                "autorizacion": "",
                "comercio": transaction_corresponsalia.corresponsalia.description,
                "ciudad": transaction_corresponsalia.corresponsalia.city,
                "pais": transaction_corresponsalia.corresponsalia.country,
                "sucursal": transaction_corresponsalia.corresponsalia.branch,
                "emisor": transaction_corresponsalia.corresponsalia.company.volcan_issuer_id
        }
        response_message, response_data, response_status = gestion_transacciones(request=request,
                                                                                 request_data=request_data)
        if 'RSP_CODIGO' in response_data and (
                response_data['RSP_CODIGO'].isnumeric() and int(response_data['RSP_CODIGO']) == 0
        ) or response_data['RSP_CODIGO'] == '':
            transaction_corresponsalia.authorization = model_code_generator(TransaccionCorresponsalia, 32, code='authorization')
            transaction_corresponsalia.save()
            db = TransaccionCorresponsaliaCollection()
            db.insert_one(data={
                "transaction_id": str(transaction_corresponsalia.id),
                "request_data": request_data,
                "response_data": {k.lower(): v.lower() for k, v, in response_data.items()}
            })
            self.make_response_success(status=response_status, message="Transacción aprobada", data={
                "RSP_ERROR": "OK",
                "RSP_CODIGO": "0000000000",
                'RSP_DESCRIPCION': "Transacción aprobada",
                'id_corresponsalia': str(transaction_corresponsalia.corresponsalia.id),
                'autorizacion': transaction_corresponsalia.authorization,
                'importe': transaction_corresponsalia.amount,
                'moneda': transaction_corresponsalia.currency.number_code
            })
        else:
            self.make_response_success(status=response_status, message=response_message, data=response_data)
