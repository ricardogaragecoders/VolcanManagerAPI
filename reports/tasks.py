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
    elif report_type == ReportType.RT_TOTAL_LOGS:
        return CreateReportExcelLogsSummary(report_id=report_id, report=report)
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
        from_date, to_date = report.initial_date, report.final_date
        tz_report = report.time_zone  # = "America/Mexico_City"
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)

        # Formateamos las fechas a DD-MM-YYYY
        from_date_str = from_date.strftime("%d-%m-%Y")
        to_date_str = to_date.strftime("%d-%m-%Y")

        subtitle = f"{from_date_str} a {to_date_str}"

        # Define estilos
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

        # Crear worksheet
        worksheet_s = workbook.add_worksheet("report")

        # Título
        if title:
            range_title_text = 'A2:{0}2'.format(get_letter_from_number(len(fields) - 2))
            worksheet_s.merge_range(range_title_text, title.title(), title_format)

        # Subtítulo
        if subtitle:
            range_subtitle_text = 'A3:{0}3'.format(get_letter_from_number(len(fields) - 1))
            worksheet_s.merge_range(range_subtitle_text, subtitle, title_format)

        # Encabezados
        for idx, field in enumerate(fields):
            worksheet_s.write(with_title, idx, field, header_format)

        if from_date and to_date:
            filters['created_at'] = {
                "$gte": from_date,
                "$lt": to_date
            }

        sort = 'created_at'
        direction = pymongo.ASCENDING

        filters['user.emisor'] = report.company.volcan_issuer_id

        db = MonitorCollection()
        queryset = db.find_all(filters, sort, direction)
        query_data = []
        cont_register = 0

        # Procesar los datos
        report_timezone = pytz.timezone(report.time_zone)
        for item in queryset:
            created_at = timezone.localtime(item['created_at'], timezone=report_timezone)
            rsp_success = 'Exitoso' if 'rsp_success' in item['response_data'] and item['response_data'][
                'rsp_success'] else 'No exitoso'
            origin = item['headers'].get('Origin', item['headers'].get('Client-IP', ''))
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
            cont_register += 1

        # Fila de totales
        total = {
            'ID': 'Total de filas',
            'Webservice': '',
            'StatusCode': '',
            'RspSuccess': '',
            'Fecha': '',
            'Hora': '',
            'Usuario': '',
            'Emisor': '',
            'Origin': f'{cont_register}'
        }
        query_data.append(total)

        # Escribir datos
        for idx, data in enumerate(query_data):
            row_index = (with_title + 1) + idx
            for col_idx, field in enumerate(fields):
                # Para la fila total, aplicamos el formato del encabezado
                if idx == len(query_data) - 1:
                    worksheet_s.write(row_index, col_idx, data[field], header_format)
                else:
                    worksheet_s.write(row_index, col_idx, data[field], cell_center)

        # Cerrar y guardar el reporte
        workbook.close()
        xlsx_data = output.getvalue()
        if report.report and os.path.isfile(report.report.path):
            os.remove(report.report.path)
        report.report = ContentFile(xlsx_data, name='{0}.{1}'.format(report.report_type, 'xlsx'))
        report.is_processed = True
        report.save()
    return True


@shared_task()
def CreateReportExcelLogsSummary(report_id: int, report: Report = None):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    fields = ['Webservice', 'Exitoso', 'No exitoso', 'Total']
    title = 'Resumen de logs'
    subtitle = ''
    with_title = 4 if title else 0
    filters = dict()

    if not report:
        try:
            report = Report.objects.get(id=report_id)
        except Report.DoesNotExist:
            report = None

    if report and not report.is_processed:
        from_date, to_date = report.initial_date, report.final_date
        tz_report = report.time_zone  # = "America/Mexico_City"
        from_date = make_day_start(from_date)
        to_date = make_day_end(to_date)

        # Formateamos las fechas a DD-MM-YYYY
        from_date_str = from_date.strftime("%d-%m-%Y")
        to_date_str = to_date.strftime("%d-%m-%Y")

        subtitle = f"{from_date_str} a {to_date_str}"

        # define styles
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

        # add a worksheet
        worksheet_s = workbook.add_worksheet("Summary")

        if title:
            title = f"{title}: {report.company.volcan_issuer_id.upper()}"
            range_title_text = 'A2:{0}2'.format(get_letter_from_number(len(fields) - 1))
            worksheet_s.merge_range(range_title_text, title, title_format)

        if subtitle:
            range_subtitle_text = 'A3:{0}3'.format(get_letter_from_number(len(fields) - 1))
            worksheet_s.merge_range(range_subtitle_text, subtitle, title_format)

        # Add headers
        for idx, field in enumerate(fields):
            worksheet_s.write(with_title, idx, field, header_format)

        # Filtro de fechas
        if from_date and to_date:
            filters['created_at'] = {
                "$gte": from_date,
                "$lt": to_date
            }

        filters['user.emisor'] = report.company.volcan_issuer_id

        # Agrupamos por URL y contamos las peticiones exitosas y fallidas
        db = MonitorCollection()
        pipeline = [
            {'$match': filters},
            {'$group': {
                '_id': '$url',
                'total_requests': {'$sum': 1},
                'successful_requests': {
                    '$sum': {
                        '$cond': [{'$eq': ['$response_data.rsp_success', True]}, 1, 0]
                    }
                },
                'failed_requests': {
                    '$sum': {
                        '$cond': [{'$eq': ['$response_data.rsp_success', False]}, 1, 0]
                    }
                }
            }}
        ]

        report_data = db.collection.aggregate(pipeline)

        # Inicializamos variables para las sumas
        total_successful = 0
        total_failed = 0
        total_requests = 0

        # Escribimos los datos resumidos en el Excel
        for idx, item in enumerate(report_data):
            row_index = (with_title + 1) + idx
            worksheet_s.write(row_index, 0, item['_id'], cell_center)
            worksheet_s.write(row_index, 1, item['successful_requests'], cell_center)
            worksheet_s.write(row_index, 2, item['failed_requests'], cell_center)
            worksheet_s.write(row_index, 3, item['total_requests'], cell_center)

            # Actualizamos las sumas
            total_successful += item['successful_requests']
            total_failed += item['failed_requests']
            total_requests += item['total_requests']

        # Añadimos la fila total
        total_row_index = (with_title + 1) + idx + 1
        worksheet_s.write(total_row_index, 0, 'Total', header_format)
        worksheet_s.write(total_row_index, 1, total_successful, header_format)
        worksheet_s.write(total_row_index, 2, total_failed, header_format)
        worksheet_s.write(total_row_index, 3, total_requests, header_format)

        # Cerrar y guardar el reporte
        workbook.close()
        xlsx_data = output.getvalue()
        if report.report and os.path.isfile(report.report.path):
            os.remove(report.report.path)
        report.report = ContentFile(xlsx_data, name='{0}.{1}'.format(report.report_type, 'xlsx'))
        report.is_processed = True
        report.save()

    return True
