import hashlib
import hmac
import json

import pymongo
import requests
from bson.json_util import dumps, loads
from bson.objectid import ObjectId
from celery import shared_task
from django.utils import timezone

from webhook.models import TransactionCollection, NotificationCollection
from webhook.models import Webhook


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


def get_volcan_headers(webhook: Webhook):
    return {
        'Content-Type': 'application/json',
        f'{webhook.header_webhook}': f'{webhook.key_webhook}'
    }


def send_transaction_url_webhook(data, webhook: Webhook):
    headers = get_volcan_headers(webhook)
    data_json = json.dumps(data)
    print(f"Request webhook: {webhook.url_webhook}")
    print(f"Request headers: {headers}")
    print(f"Request json webhook: {data_json}")
    response_status = 0
    response_data = {}
    try:
        res = requests.post(
            webhook.url_webhook,
            data=data_json, headers=headers, auth=BodyDigestSignature(webhook.key_webhook))
        # r = requests.post(url=webhook.url_webhook, data=data_json, headers=headers)
        response_status = res.status_code
        print(res.text)
        print(res.headers)
        if 'Content-Type' in res.headers:
            if 'application/json' in res.headers['Content-Type']:
                response_data = res.json() if response_status != 204 else {}
            else:
                response_data = res.content
        print(f"Response webhook {response_status}: {response_data}")
        if response_status == 200:
            response_message = response_data
        elif response_status == 204:
            response_message = ''
        elif response_status == 404:
            response_message = 'Recurso no disponible'
        elif 400 <= response_status < 500:
            response_message = response_data
        else:
            print(f"Response: {str(response_status)}")
            print(f"Data server: {str(res.content)}")
            response_message = res.content
    except requests.exceptions.Timeout:
        response_status = 408
        response_message = 'Error de conexion con servidor VOLCAN (Timeout)'
        print(response_message)
    except requests.exceptions.TooManyRedirects:
        response_status = 429
        response_message = 'Error de conexion con servidor VOLCAN (TooManyRedirects)'
        print(response_message)
    except requests.exceptions.RequestException as e:
        response_status = 400
        response_message = '%s' % e
    except Exception as e:
        response_status = 500
        response_message = e.args.__str__()

    if response_status in [200, 201, 204]:
        return True, response_status, response_message
    else:
        return False, response_status, response_message


@shared_task
def send_notification_webhook_issuer(notification_id=None, emisor=''):
    db = NotificationCollection()
    webhook = None
    if len(emisor) == 0 and notification_id:
        if len(notification_id) > 10:
            queryset = db.find({'_id': ObjectId(notification_id)})
        else:
            queryset = db.find({'_id': int(notification_id)})
    else:
        webhook = Webhook.objects.filter(account_issuer=emisor, delesend_notification_webhook_issuerted_at__isnull=True).first()
        sort = 'delivery.delivery_date'
        direction = pymongo.ASCENDING
        filters = {'issuer.issuer': emisor, 'delivery.delivered': False}
        queryset = db.find_all(filters, sort, direction)

    results = []
    for item in queryset:
        # created_at = item['created_at'].strftime("%d/%m/%Y %H:%M:%S")
        results.append({
            'id': str(item['_id']),
            'user': item['user'],
            'notification': item['notification'],
            'notification_type': item['notification_type'],
            'webhook': item['webhook'],
            'delivery': item['delivery'],
            'response': item['response'],
            'issuer': item['issuer'],
            'created_at': item['created_at']
        })
    if len(results) > 0 and not webhook:
        webhook = Webhook.objects.filter(account_issuer=results[0]['issuer']['issuer'], deleted_at__isnull=True).first()

    if webhook:
        for result_item in results:
            resp = send_transaction_url_webhook(data=result_item['notification'], webhook=webhook)
            filters = {'_id': ObjectId(result_item['id'])}
            data_update = {'$set': {
                'delivery': {
                    'delivered': resp[0],
                    'delivery_date': timezone.localtime(timezone.now()) if resp[0] else None,
                    'attempts': result_item['delivery']['attempts'] + 1
                },
                'response': {
                    'code': str(resp[1]),
                    'body': resp[2]
                },
                'webhook': {
                    'id': str(webhook.id),
                    'url': webhook.url_webhook,
                    'headers': {
                        'header': webhook.header_webhook,
                        'value': f"...{webhook.key_webhook[-4:]}"
                    }
                }
            }}
            db.update_one(filters=filters, data=data_update)

    return len(results)
