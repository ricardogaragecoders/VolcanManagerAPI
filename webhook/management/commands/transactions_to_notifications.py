from __future__ import unicode_literals

from django.core.management.base import BaseCommand

from common.models import Status


class Command(BaseCommand):
    """
        Rename fields from TransactionCollection
    """
    help = "Convertir transacciones en notificaciones."

    def handle(self, *args, **options):
        from webhook.models import TransactionCollection, NotificationCollection, Webhook
        from django.utils import timezone
        self.stdout.write(self.style.SUCCESS(u'Iniciando actualizacion'))
        """
            Structure of a transaction

            {
                _id: ObjectId('65495c05f133f00c88f72a17'),
                ....,
                entregado: true,
                fecha_entregado: ISODate('2023-11-06T21:35:01.683Z'),
                codigo_error: '200',
                mensaje_error: {
                  success: true,
                  apikey: 'bb58nSz6/DvCav7MqVxuphEtKR/wa0656lFE+2688JXnETNqK2g3K8iXPUneKRgV4Qdhc8XEt0T9fneochcHaZ5AFD6ovEg4wQ+yRoQ4RLfr3+gxpHDr8zkwLH7E0yi90x3XlibY3ZUxfKR87YNTZYGmzZB0V6EO5Zq+A95nk6Bpww/JRcqRrIHp2COLT1NVcOdQpVeShfpfW7AOTIAdBOSmSRydBquc6r9xypUSaQ4Xz7MQci1Bfv+VUKhC3pNuH0QcMr3Q1MrayikdLF47Ylr/XeHf1S9pV2OrjTYKtGb7Cdixtu97jgBr+gGMb8cUekt14LTLFdXnO46evpG9LQ=='
                }
            }
            
            rename to:
            
            {
                _id: ObjectId('65495c05f133f00c88f72a17'),
                ....,
                delivered: true,
                delivery_date: ISODate('2023-11-06T21:35:01.683Z'),
                response_code: '200',
                response_body: {
                  success: true,
                  apikey: 'bb58nSz6/DvCav7MqVxuphEtKR/wa0656lFE+2688JXnETNqK2g3K8iXPUneKRgV4Qdhc8XEt0T9fneochcHaZ5AFD6ovEg4wQ+yRoQ4RLfr3+gxpHDr8zkwLH7E0yi90x3XlibY3ZUxfKR87YNTZYGmzZB0V6EO5Zq+A95nk6Bpww/JRcqRrIHp2COLT1NVcOdQpVeShfpfW7AOTIAdBOSmSRydBquc6r9xypUSaQ4Xz7MQci1Bfv+VUKhC3pNuH0QcMr3Q1MrayikdLF47Ylr/XeHf1S9pV2OrjTYKtGb7Cdixtu97jgBr+gGMb8cUekt14LTLFdXnO46evpG9LQ=='
                }
            }
        """
        transactions = TransactionCollection()
        transactions.collection.update_many({}, {'$rename': {
            "entregado": "delivered",
            "fecha_entregado": "delivery_date",
            "codigo_error": "response_code",
            "mensaje_error": "response_body"
        }})

        notifications = NotificationCollection()
        for item in transactions.find({}):
            webhook = Webhook.objects.filter(account_issuer=item['emisor']).first()
            webhook_data = None
            issuer_data = None
            if webhook:
                webhook_data = {
                    'id': str(webhook.id),
                    'url': webhook.url_webhook,
                    'headers': {
                        'header': webhook.header_webhook,
                        'value': f"...{webhook.key_webhook[-4:]}"
                    }
                }
                issuer_data = {'issuer': webhook.account_issuer }

            notifications.insert_one({
                'user': {'name': 'webhook'},
                'notification': {
                    'monto': item['monto'],
                    'moneda': item['moneda'],
                    'emisor': item['emisor'],
                    'estatus': item['estatus'],
                    'tipo_transaccion': item['tipo_transaccion'],
                    'tarjeta': item['tarjeta'],
                    'id_movimiento': str(item['id_movimiento']),
                    'fecha_transaccion': item['fecha_transaccion'],
                    'hora_transaccion': item['hora_transaccion'],
                    'referencia': item['referencia'],
                    'numero_autorizacion': item['numero_autorizacion'],
                    'codigo_autorizacion': item['codigo_autorizacion'],
                    'comercio': item['comercio'],
                    'pais': item['pais'] if 'pais' in item else '',
                    'email': item['email'] if 'email' in item else '',
                    'tarjetahabiente': item['tarjetahabiente'] if 'tarjetahabiente' in item else ''
                },
                'notification_type': {'type': 'transaction', 'mode': 'normal', 'version': 1},
                'delivery': {
                    'delivered': item['delivered'],
                    'delivery_date': item['delivery_date'],
                    'attempts': 1
                },
                'webhook': webhook_data,
                'issuer': issuer_data,
                'response': {
                    'code': item['response_code'],
                    'body': item['response_body']
                },
                'created_at': timezone.localtime(timezone.now())
            })

        self.stdout.write(self.style.SUCCESS(u'Finalizando la actualizacion'))
