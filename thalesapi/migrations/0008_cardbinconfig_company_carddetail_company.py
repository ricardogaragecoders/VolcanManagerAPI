# Generated by Django 4.2.3 on 2024-05-29 22:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('control', '0001_initial'),
        ('thalesapi', '0007_client_carddetail_client'),
    ]

    operations = [
        migrations.AddField(
            model_name='cardbinconfig',
            name='company',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='card_bin_configs', to='control.company'),
        ),
        migrations.AddField(
            model_name='carddetail',
            name='company',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='cards', to='control.company'),
        ),
    ]
