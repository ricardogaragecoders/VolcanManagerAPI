import hashlib
import hmac
import json

import pymongo
import requests
from bson.objectid import ObjectId
from celery import shared_task
from django.conf import settings
from django.utils import timezone

from control.models import TransactionCollection
from control.models import Webhook


class BodyDigestSignature(object):
    def __init__(self, secret, header='Sign', algorithm=hashlib.sha512):
        self.secret = secret
        self.header = header
        self.algorithm = algorithm

    def __call__(self, request):
        body = request.body
        if not isinstance(body, bytes):  # Python 3
            body = body.encode('latin1')  # standard encoding for HTTP
        signature = hmac.new(self.secret.encode('latin1'), body, digestmod=self.algorithm)
        request.headers[self.header] = signature.hexdigest()
        return request


def get_volcan_headers():
    return {
        'Content-Type': 'application/json'
    }


def send_transaction_url_webhook(data, webhook: Webhook):
    headers = get_volcan_headers()
    data_json = json.dumps(data)
    if settings.DEBUG:
        print(f"Request webhook: {webhook.url_webhook}")
        print(f"Data json webhook: {data_json}")
    try:
        res = requests.post(
            webhook.url_webhook,
            data=data_json, headers=headers, auth=BodyDigestSignature(webhook.key_webhook))
        # r = requests.post(url=webhook.url_webhook, data=data_json, headers=headers)
        response_status = res.status_code
        if 200 <= response_status <= 204:
            response_data = res.json()
            if len(response_data) == 0:
                print(f"Response: empty")
                response_data = {'RSP_CODIGO': '400', 'RSP_DESCRIPCION': 'Error en datos de origen'}
            else:
                print(f"Response webhook: {response_data}")
        elif response_status == 404:
            response_data = {'RSP_CODIGO': '404', 'RSP_DESCRIPCION': 'Recurso no disponible'}
            print(f"Response: 404 Recurso no disponible")
        else:
            response_data = {'RSP_CODIGO': str(response_status), 'RSP_DESCRIPCION': 'Error desconocido'}
            print(f"Response: {str(response_status)} Error desconocido")
            print(f"Data server: {str(res.text)}")
        response_message = ''
    except requests.exceptions.Timeout:
        response_data = {'RSP_CODIGO': "408",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (Timeout)'}
        response_status = 408
        response_message = 'Error de conexion con servidor VOLCAN (Timeout)'
        print(response_message)
    except requests.exceptions.TooManyRedirects:
        response_data = {'RSP_CODIGO': "429",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (TooManyRedirects)'}
        response_status = 429
        response_message = 'Error de conexion con servidor VOLCAN (TooManyRedirects)'
        print(response_message)
    except requests.exceptions.RequestException as e:
        response_data = {'RSP_CODIGO': "400",
                         'RSP_DESCRIPCION': 'Error de conexion con servidor VOLCAN (RequestException)'}
        response_status = 400
        response_message = 'Error de conexion con servidor VOLCAN (RequestException)'
        print(response_message)
    except Exception as e:
        print("Error peticion")
        print(e.args.__str__())
        response_status = 500
        response_message = 'error'
        response_data = {'RSP_CODIGO': '500', 'RSP_DESCRIPCION': e.args.__str__()}

    if response_status in [200, 201, 202, 203, 204]:
        return True, response_status, 'ok'
    else:
        return False, response_status, response_data['RSP_DESCRIPCION']


@shared_task
def send_transaction_emisor(transaction_id=None, emisor=''):
    db = TransactionCollection()
    webhook = None
    if len(emisor) == 0 and transaction_id:
        if len(transaction_id) > 10:
            queryset = db.find({'_id': ObjectId(transaction_id)})
        else:
            queryset = db.find({'_id': int(transaction_id)})
    else:
        webhook = Webhook.objects.filter(account_issuer=emisor, deleted_at__isnull=True).first()
        sort = 'fecha_entregado'
        direction = pymongo.ASCENDING
        filters = {'emisor': emisor, 'entregado': False}
        queryset = db.find_all(filters, sort, direction)

    results = []
    for item in queryset:
        results.append({
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
            'comercio': item['comercio']
        })
    if len(results) > 0 and not webhook:
        webhook = Webhook.objects.filter(account_issuer=results[0]['emisor'], deleted_at__isnull=True).first()

    if webhook:
        for item in results:
            resp = send_transaction_url_webhook(data=item, webhook=webhook)
            filters = {'_id': ObjectId(item['id'])}
            data_update = {'$set': {
                'entregado': resp[0],
                'fecha_entregado': timezone.localtime(timezone.now()),
                'codigo_error': str(resp[1]),
                'mensaje_error': resp[2]
            }}
            db.update_one(filters=filters, data=data_update)
    return len(results)
