# Generated by Django 4.2.11 on 2024-10-04 19:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('corresponsalia', '0003_rename_authorization_corresponsalia_description_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='transaccioncorresponsalia',
            name='params',
            field=models.JSONField(default=dict),
        ),
    ]
