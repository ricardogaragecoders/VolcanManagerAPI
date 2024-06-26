# Generated by Django 4.2.3 on 2024-03-20 17:26

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('thalesapi', '0006_alter_cardbinconfig_card_product_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('card_name', models.CharField(blank=True, max_length=50, null=True)),
                ('consumer_id', models.CharField(blank=True, max_length=45, null=True)),
                ('type_identification', models.CharField(blank=True, max_length=2, null=True)),
                ('document_identification', models.CharField(blank=True, max_length=20, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='carddetail',
            name='client',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='cards', to='thalesapi.client'),
        ),
    ]
