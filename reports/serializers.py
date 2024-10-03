import os
from datetime import datetime

import pytz
from rest_framework import serializers

from common.exceptions import CustomValidationError
from common.utils import make_day_start, make_day_end
from control.models import Company
from reports.models import Report, ReportType
from django.utils.translation import gettext_lazy as _
from django.db import transaction
from django.db.models import F, Q, Sum


class ReportSerializer(serializers.ModelSerializer):
    issuer = serializers.SerializerMethodField(read_only=True)
    issuer_id = serializers.CharField(max_length=3, required=True, write_only=True)
    report_type = serializers.CharField(max_length=50, required=False, allow_blank=True, allow_null=True)
    initial_date = serializers.DateTimeField(format="%Y-%m-%d", input_formats=['%Y-%m-%d', 'iso-8601'],
                                             required=False, allow_null=True)
    final_date = serializers.DateTimeField(format="%Y-%m-%d", input_formats=['%Y-%m-%d', 'iso-8601'],
                                           required=False, allow_null=True)
    time_zone = serializers.CharField(max_length=50, default='America/Mexico_City', required=False)
    params = serializers.JSONField(default={}, required=False)

    class Meta:
        model = Report
        fields = ('id', 'issuer', 'issuer_id', 'report_type', 'report',
                  'initial_date', 'final_date', 'time_zone', 'params',
                  'is_processed', 'is_active', 'created_at', 'updated_at')
        read_only_fields = ('id', 'is_processed', 'report', 'created_at', 'updated_at')

    def validate(self, data):
        data = super(ReportSerializer, self).validate(data)
        company = self.instance.company if self.instance else None
        issuer_id = data.pop('issuer_id', None)
        report_type = data.get('report_type', self.instance.report_type if self.instance else ReportType.RT_LOGS)
        initial_date = data.get('initial_date', self.instance.initial_date if self.instance else None)
        final_date = data.get('final_date', self.instance.final_date if self.instance else None)
        time_zone = data.get('time_zone', self.instance.time_zone if self.instance else 'America/Mexico_City')
        now = datetime.now()
        request = self.context['request']
        profile = request.user.profile

        if not self.instance:
            if not issuer_id:
                raise CustomValidationError(detail='Issuer ID es requerido', code='400')

        if issuer_id:
            company = Company.objects.filter(volcan_issuer_id=issuer_id).first()

        if not company:
            raise CustomValidationError(detail='Issuer ID es requerido', code='400')

        if not initial_date:
            initial_date = make_day_start(now.astimezone(pytz.timezone(time_zone)))
        else:
            initial_date = make_day_start(initial_date).astimezone(pytz.timezone(time_zone))

        if not final_date:
            final_date = make_day_end(now).astimezone(pytz.timezone(time_zone))
        else:
            final_date = make_day_end(final_date).astimezone(pytz.timezone(time_zone))

        if initial_date > final_date:
            raise CustomValidationError(detail=_(u'Fecha inicial invalida'),
                                        code='initial_date_invalid')

        if report_type not in [item[0] for item in ReportType.choices]:
            raise CustomValidationError(detail=_(u'Tipo de reporte invalida'),
                                        code='report_type_invalid')
        data['company'] = company
        data['report_type'] = report_type
        data['initial_date'] = initial_date
        data['final_date'] = final_date
        data['created_by'] = profile
        data['is_processed'] = False
        data['time_zone'] = time_zone

        return data

    def create(self, validated_data):
        with transaction.atomic():
            instance = super(ReportSerializer, self).create(validated_data)
            from reports.tasks import control_create_report
            control_create_report.delay(report_id=instance.id)
        return instance

    def update(self, instance, validated_data):
        if instance.report and os.path.exists(instance.report.path):
            os.remove(instance.report.path)
            validated_data['report'] = None
        with transaction.atomic():
            instance = super(ReportSerializer, self).update(instance, validated_data)
            from reports.tasks import control_create_report
            control_create_report.delay(report_id=instance.id)
        return instance

    def get_issuer(self, instance):
        company = instance.company
        if company:
            return {'id': company.id, 'name': company.name, 'issuer_id': company.volcan_issuer_id}
        return None