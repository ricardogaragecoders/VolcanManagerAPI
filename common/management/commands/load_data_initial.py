from __future__ import unicode_literals

from django.core.management.base import BaseCommand

from common.models import Status


class Command(BaseCommand):
    """
        Load data initial common
    """
    help = "Load data initial common."

    def handle(self, *args, **options):
        from django.contrib.auth.models import Group

        self.stdout.write(self.style.SUCCESS('Iniciando carga de datos common'))

        states = [
            {'name': 'ACTIVO', 'slug': 'active'},
            {'name': 'INACTIVO', 'slug': 'inactive'},
            {'name': 'BORRADO', 'slug': 'deleted'}
        ]

        for item in Status.objects.all():
            item.name = item.name.upper()
            item.save()

        for item in states:
            Status.objects.get_or_create(name=item['name'], slug=item['slug'])

        self.stdout.write(self.style.SUCCESS('Carga de status'))

        groups = [
            {'name': 'CLIENT'},
            {'name': 'OPERATOR'},
            {'name': 'SUPERVISOR'},
            {'name': 'ADMINISTRATOR'},
        ]

        for item in Group.objects.all():
            item.name = item.name.upper()
            item.save()

        for item in groups:
            Group.objects.get_or_create(name=item['name'])
        self.stdout.write(self.style.SUCCESS('Carga de groups'))

        from django.apps import apps

        # if apps.is_installed('statements'):
        #     from statements.models import Company
        #     from statements.models import ProductType
        #     from statements.models import Currency
        #
        #     Company.objects.get_or_create(name='We Are Garage')
        #     self.stdout.write(self.style.SUCCESS('Carga Empresas'))
        #
        #     product_types = [
        #         {'name': 'PREPAGO', 'slug': 'prepaid'},
        #         {'name': 'CREDITO', 'slug': 'credit'}
        #     ]
        #
        #     for item in ProductType.objects.all():
        #         item.name = item.name.upper()
        #         item.save()
        #
        #     for item in product_types:
        #         product_type, created = ProductType.objects.get_or_create(slug=item['slug'])
        #         product_type.name = item['name']
        #         product_type.save()
        #
        #     self.stdout.write(self.style.SUCCESS(u'Carga de tipos de producto'))
        #
        #     currencies = [
        #         {'name': 'DOLARES', 'abr': 'USD', 'slug': 'dollar'},
        #         {'name': 'LEMPIRAS', 'abr': 'HNL', 'slug': 'lempiras'}
        #     ]
        #
        #     for item in Currency.objects.all():
        #         item.name = item.name.upper()
        #         item.abr = item.abr.upper()
        #         item.save()
        #
        #     for item in currencies:
        #         currency, created = Currency.objects.get_or_create(abr=item['abr'], slug=item['slug'])
        #         currency.name = item['name']
        #         currency.save()
        #
        #     self.stdout.write(self.style.SUCCESS(u'Carga de monedas'))
        #
        # if apps.is_installed('etl'):
        #     from etl.models import ETLProcessType
        #     etl_process_types = [
        #         {'name': 'Account Statement', 'slug': 'account-statement'},
        #         {'name': 'Account Statement V2', 'slug': 'account-statement-v2'},
        #         {'name': 'MCI Load Files', 'slug': 'mci-load-files'}
        #     ]
        #
        #     for item in etl_process_types:
        #         etl_process_type, created = ETLProcessType.objects.get_or_create(slug=item['slug'])
        #         etl_process_type.name = item['name']
        #         etl_process_type.save()
        #
        #     self.stdout.write(self.style.SUCCESS('Carga ETLProcessType'))

        self.stdout.write(self.style.SUCCESS('Finalizando carga'))
