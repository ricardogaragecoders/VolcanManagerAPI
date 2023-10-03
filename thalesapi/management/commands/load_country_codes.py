from __future__ import unicode_literals

from django.core.management.base import BaseCommand

from common.models import Status
from thalesapi.models import ISOCountry


class Command(BaseCommand):
    """
        Load country codes
    """
    help = "Load country codes ISO."

    def handle(self, *args, **options):
        from django.contrib.auth.models import Group

        self.stdout.write(self.style.SUCCESS('Iniciando carga country codes ISO'))
        from django.conf import settings
        import pandas as pd
        col_names = [
            'Code',
            'Country',
            'Alfa3',
            'Alfa2'
        ]
        # Use Pandas to parse the CSV file
        csv_data = pd.read_csv(settings.PATH_ISO_COUNTRIES_CSV, names=col_names, header=0, encoding='utf8')

        for i, row in csv_data.iterrows():
            if not ISOCountry.objects.filter(country_name__unaccent__icontains=row['Country']).exists():
                try:
                    iso_country = ISOCountry.objects.create(code=row['Code'], country_name=row['Country'], alfa2=row['Alfa2'], alfa3=row['Alfa3'])
                    self.stdout.write(self.style.SUCCESS(iso_country))
                except Exception as e:
                    print(row)
                    self.stdout.write(self.style.ERROR(e.args.__str__()))

        self.stdout.write(self.style.SUCCESS('Finalizando carga'))
