# Generated by Django 4.2.3 on 2023-09-02 18:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('thalesapi', '0002_carddetail_card_bin_alter_carddetail_card_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='carddetail',
            name='account_id',
            field=models.CharField(blank=True, help_text='Generated by AZ7', max_length=64, null=True, verbose_name='Account ID'),
        ),
    ]
