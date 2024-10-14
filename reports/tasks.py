from io import BytesIO
import re
import os
import pytz

import pymongo
import xlsxwriter
from celery import shared_task
from django.core.files.base import ContentFile
from django.utils import timezone

from common.models import MonitorCollection
from common.utils import get_letter_from_number, make_day_start, make_day_end
from reports.models import Report, ReportType


def camel_to_snake(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


@shared_task()
def control_create_report(report_id: int, report_type = None):
    report = None
    if not report_type:
        try:
            report = Report.objects.get(id=report_id)
            report_type = report.report_type
        except Report.DoesNotExist:
            report_type = ''

    if report_type == ReportType.RT_LOGS:
        return CreateReportExcelLogs(report_id=report_id, report=report)
    return None


@shared_task()
def CreateReportExcelLogs(report_id: int, report: Report = None):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    fields = ['ID', 'Webservice', 'StatusCode', 'RspSuccess',
              'Fecha', 'Hora', 'Usuario',
              'Emisor', 'Origin']
    title = 'Logs'
    with_title = 4 if title else 0
    filters = dict()
    if not report:
        try:
            report = Report.objects.get(id=report_id)
        except Report.DoesNotExist:
            report = None
    if report and not report.is_processed:
        # define styles to use
        title_format = workbook.add_format({
            'bold': True,
            'font_size': 14,
            'align': 'center',
            'valign': 'vcenter'
        })
        header_format = workbook.add_format({
            'bg_color': '#cfe7f5',
            'color': 'black',
            'align': 'center',
            'valign': 'top',
            'border': 1
        })
        cell_center = workbook.add_format({'align': 'center'})

        # add a worksheet to work with
        worksheet_s = workbook.add_worksheet("report")

        if title:
            range_title_text = 'A2:{0}2'.format(get_letter_from_number(len(fields)-2))
            worksheet_s.merge_range(range_title_text, title.title(), title_format)

        # Add headers for data
        cont = 0
        for field in fields:
            # field_title = field.title()
            worksheet_s.write(with_title, cont, field, header_format)
            cont += 1

        from_date, to_date = report.initial_date, report.final_date
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)
        if from_date and to_date:
            filters['created_at'] = {
                "$gte": from_date,
                "$lt": to_date
            }

        sort = 'created_at'
        direction = pymongo.ASCENDING

        filters['user.emisor'] = report.company.volcan_issuer_id

        db = MonitorCollection()
        # total = db.count_all(filters)
        queryset = db.find_all(filters, sort, direction)
        query_data = []

        report_timezone = pytz.timezone(report.time_zone)

        for item in queryset:
            created_at = timezone.localtime(item['created_at'], timezone=report_timezone)
            rsp_success = 'Exitoso' if 'rsp_success' in item['response_data'] and item['response_data'][
                'rsp_success'] else 'No exitoso'
            if 'Origin' in item['headers']:
                origin = item['headers']['Origin']
            elif 'Client-IP' in item['headers']:
                origin = item['headers']['Client-IP']
            else:
                origin = ''
            data = {
                'ID': str(item['_id']),
                'Webservice': item['url'],
                'StatusCode': item['status_code'],
                'RspSuccess': rsp_success,
                'Fecha': created_at.strftime("%d/%m/%Y"),
                'Hora': created_at.strftime("%H:%M"),
                'Usuario': item['user']['username'],
                'Emisor': item['user']['emisor'],
                'Origin': origin
            }
            query_data.append(data)

        # write data to cells
        for idx, data in enumerate(query_data):
            row_index = (with_title + 1) + idx
            i = 0
            for field in fields:
                worksheet_s.write(row_index, i, data[field], cell_center)
                i += 1

        workbook.close()
        xlsx_data = output.getvalue()
        if report.report and os.path.isfile(report.report.path):
            os.remove(report.report.path)
        report.report = ContentFile(xlsx_data, name='{0}.{1}'.format(report.report_type, 'xlsx'))
        report.is_processed = True
        report.save()
    return True
