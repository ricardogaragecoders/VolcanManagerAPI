from io import BytesIO
import xlsxwriter
from django.utils.translation import gettext

from common.utils import get_letter_from_number


def WriteToExcel(query_data, **kwargs):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    fields = kwargs['fields'] if 'fields' in kwargs else []
    title = kwargs['title'] if 'title' in kwargs else None
    with_title = 4 if title else 0
    capitalize_fields = kwargs['capitalize_fields'] if 'capitalize_fields' in kwargs else True

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
        # create title
        title_text = gettext(title)
        # add title to sheet, use merge_range to let title span over multiple columns

        range_title_text = 'A2:{0}2'.format(get_letter_from_number(len(fields)-2))

        worksheet_s.merge_range(range_title_text, title_text.title(), title_format)

    # Add headers for data
    cont = 0
    for field in fields:
        field_title = field
        if capitalize_fields:
            field_title = field.title()
        worksheet_s.write(with_title, cont, gettext(field_title), header_format)

        cont += 1

    # write data to cells
    for idx, data in enumerate(query_data):
        row_index = (with_title + 1) + idx
        i = 0
        for field in fields:
            worksheet_s.write(row_index, i, data[field], cell_center)
            i += 1

    workbook.close()
    xlsx_data = output.getvalue()
    return xlsx_data
