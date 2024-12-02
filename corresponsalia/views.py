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
    get_datetime_from_querystring, model_code_generator, code_generator
from common.views import CustomViewSetWithPagination
from corresponsalia.models import Corresponsalia, TransaccionCorresponsalia, TransaccionCorresponsaliaCollection, \
    TransaccionCorresponsaliaStatus
from corresponsalia.serializers import CreateCorresponsaliaSerializer, \
    CorresponsaliaSimpleSerializer, TransaccionCorresponsaliaSerializer, \
    CreateTransaccionCorresponsaliaSerializer, TransaccionCorresponsaSimpleliaSerializer, \
    CorresponsaliaCompleteSerializer, CreateTransaccionReversoCorresponsaliaSerializer
from corresponsalia.utils import process_parabilia_api_request
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
    create_serializer_class = CreateCorresponsaliaSerializer
    update_serializer_class = CreateCorresponsaliaSerializer
    one_serializer_class = CorresponsaliaCompleteSerializer
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
        status_transaccion = self.request.query_params.get('st', 'all')
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

        if status_transaccion != 'all':
            filters['status'] = status_transaccion

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
            response_data, response_status = process_parabilia_api_request(data=data_json, url=api_url, request=self.request, headers=headers)
            if response_status in [200, 201, 203, 204]:
                cache.set(key_cache, response_data['Token'], 30)
                corresponsalia.access_token_paycard = response_data['Token']
                corresponsalia.save()
        return cache.get(key_cache) if key_cache in cache else None

    def create_prepaid_transaction(self, request, *args, **kwargs):
        transaction_corresponsalia: Optional[TransaccionCorresponsalia] = kwargs.get('transaction', None)
        status_transaction: Optional[TransaccionCorresponsaliaStatus] = kwargs.get(
            'status_transaction', TransaccionCorresponsaliaStatus.TCS_PROCESSED)
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
        if status_transaction == TransaccionCorresponsaliaStatus.TCS_PROCESSED:
            movement_code = transaction_corresponsalia.movement_code
            reference = transaction_corresponsalia.reference
        else:
            movement_code = transaction_corresponsalia.params['movement_code_reverse']['code']
            reference = code_generator(10, option='num')

        request_data = {
            "IDSolicitud": str(code_generator(characters=8, option='num')),
            "Tarjeta": get_card_triple_des_process(transaction_corresponsalia.card_number, is_descript=True),
            "MedioAcceso": "",
            "TipoMedioAcceso": "",
            "Importe": transaction_corresponsalia.amount,
            "ClaveMovimiento": movement_code,
            "RefNumerica": reference,
            "Observaciones": "",
            "ConceptoPago": ""
        }
        url_server = settings.SERVER_VOLCAN_PARABILIA_URL
        api_url = f'{url_server}{settings.URL_PARABILIA_MOVIMIENTO_MANUAL}'

        response_data, response_status = process_parabilia_api_request(data=request_data, headers=headers,
                                                                          url=api_url, request=request, times=0)
        if response_status == 200:
            if 'CodRespuesta' in response_data and int(response_data['CodRespuesta']) == 0:
                if not transaction_corresponsalia.authorization:
                    transaction_corresponsalia.authorization = model_code_generator(TransaccionCorresponsalia, 32,
                                                                                    code='authorization').upper()
                transaction_corresponsalia.status = status_transaction
                transaction_corresponsalia.save()
                db = TransaccionCorresponsaliaCollection()
                db.insert_one(data={
                    "transaction_id": str(transaction_corresponsalia.id),
                    "request_data": request_data,
                    "response_data": response_data,
                    "status": status_transaction,
                    "created_at": datetime.now(pytz.utc)
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
        # error, si llegua aqui puede ser que no haya sido efectiva la peticion
        db = TransaccionCorresponsaliaCollection()
        db.insert_one(data={
            "transaction_id": str(transaction_corresponsalia.id),
            "request_data": request_data,
            "response_data": response_data,
            "status": 'error' if status_transaction == TransaccionCorresponsaliaStatus.TCS_PROCESSED else 'error_returned',
            "created_at": datetime.now(pytz.utc)
        })
        self.make_response_success(status=response_status, data=response_data)
        return False


    def create_credit_transaction(self, request, *args, **kwargs):
        transaction_corresponsalia: Optional[TransaccionCorresponsalia] = kwargs.get('transaction', None)
        status_transaction: Optional[TransaccionCorresponsaliaStatus] = kwargs.get(
            'status_transaction', TransaccionCorresponsaliaStatus.TCS_PROCESSED)
        assert transaction_corresponsalia, "La transaccion no fue proporcionada"
        from control.utils import gestion_transacciones

        if status_transaction == TransaccionCorresponsaliaStatus.TCS_PROCESSED:
            movement_code = transaction_corresponsalia.movement_code
            reference = transaction_corresponsalia.reference
            authorization = ""
        else:
            movement_code = transaction_corresponsalia.params['movement_code_reverse']['code']
            reference = code_generator(10, option='num')
            authorization = transaction_corresponsalia.params['authorization_origin']

        request_data = {
                "tarjeta": transaction_corresponsalia.card_number,
                "transaccion": movement_code,
                "importe": transaction_corresponsalia.amount,
                "moneda": transaction_corresponsalia.currency.number_code,
                "fecha_trx": transaction_corresponsalia.updated_at.strftime("%Y%m%d"),
                "hora_trx": transaction_corresponsalia.updated_at.strftime("%H%M%S"),
                "origen_mov": "",
                "referencia": f"{reference}",
                "doc_oper": "",
                "autorizacion": f"{authorization}",
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

            if status_transaction == TransaccionCorresponsaliaStatus.TCS_PROCESSED:
                transaction_corresponsalia.authorization = model_code_generator(TransaccionCorresponsalia, 32,
                                                                                code='authorization').upper()
                if 'RSP_AUTORIZ' in response_data and len(response_data['RSP_AUTORIZ']) > 0:
                    transaction_corresponsalia.params['authorization_origin'] = response_data['RSP_AUTORIZ']

            transaction_corresponsalia.status = status_transaction
            transaction_corresponsalia.save()
            db = TransaccionCorresponsaliaCollection()
            db.insert_one(data={
                "transaction_id": str(transaction_corresponsalia.id),
                "request_data": request_data,
                "response_data": response_data,
                "status": status_transaction,
                "created_at": datetime.now(pytz.utc)
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
            # error
            db = TransaccionCorresponsaliaCollection()
            db.insert_one(data={
                "transaction_id": str(transaction_corresponsalia.id),
                "request_data": request_data,
                "response_data": response_data,
                "status": 'error' if status_transaction == TransaccionCorresponsaliaStatus.TCS_PROCESSED else 'error_returned',
                "created_at": datetime.now(pytz.utc)
            })
            self.make_response_success(status=response_status, message=response_message, data=response_data)


class TransaccionReversoApiView(TransaccionApiView):
    serializer_class = TransaccionCorresponsaSimpleliaSerializer
    create_serializer_class = CreateTransaccionReversoCorresponsaliaSerializer
    one_serializer_class = TransaccionCorresponsaliaSerializer
    model_class = TransaccionCorresponsalia
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)

    def create(self, request, *args, **kwargs):
        try:
            request_data = request.data if 'request_data' not in kwargs else kwargs['request_data']
            self.serializer = self.get_create_serializer(data=request_data)
            if self.serializer.is_valid():
                transaction_corresponsalia: TransaccionCorresponsalia = self.serializer.validated_data.pop(
                    'transaction_corresponsalia', None)
                if transaction_corresponsalia:
                    if transaction_corresponsalia.card_bin_config.card_type == CardType.CT_PREPAID:
                        self.create_prepaid_transaction(request=request, transaction=transaction_corresponsalia,
                                                       status_transaction=TransaccionCorresponsaliaStatus.TCS_RETURNED)
                    elif transaction_corresponsalia.card_bin_config.card_type == CardType.CT_CREDIT:
                        self.create_credit_transaction(request=request, transaction=transaction_corresponsalia,
                                                       status_transaction=TransaccionCorresponsaliaStatus.TCS_RETURNED)
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

