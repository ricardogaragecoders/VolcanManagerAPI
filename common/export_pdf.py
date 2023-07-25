from io import BytesIO

from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def WriteToPdf(querydata, title=None, fields=[]):
    buffer = BytesIO()
    report = PdfPrint(buffer)
    pdf = report.report(querydata, title, fields)
    return pdf


class PdfPrint:
    def __init__(self, buffer):
        self.buffer = buffer
        self.pageSize = landscape(A4)
        self.width, self.height = self.pageSize

    def report(self, querydata, title, fields):
        doc = SimpleDocTemplate(
            self.buffer, rightMargin=10, leftMargin=10,
            topMargin=30, bottomMargin=72,
            pagesize=self.pageSize
        )
        # register fonts
        freesans = settings.BASE_DIR + settings.STATIC_URL + "FreeSans.ttf"
        freesansbold = settings.BASE_DIR + settings.STATIC_URL + "FreeSansBold.ttf"
        pdfmetrics.registerFont(TTFont('FreeSans', freesans))
        pdfmetrics.registerFont(TTFont('FreeSansBold', freesansbold))
        # set up styles
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="TableHeader", fontSize=11, alignment=TA_CENTER, fontName="FreeSansBold"))
        styles.add(ParagraphStyle(name="ParagraphTitle", fontSize=11, alignment=TA_JUSTIFY, fontName="FreeSansBold"))
        styles.add(ParagraphStyle(name="Justify", alignment=TA_JUSTIFY, fontName="FreeSans"))

        data = list()
        data.append(Paragraph(title, styles["Title"]))
        data.append(Spacer(1, 12))
        table_data = []
        headers_data = []
        # table header
        for field in fields:
            headers_data.append(Paragraph(field.title(), styles['TableHeader']))
        table_data.append(headers_data)

        # add a row to table
        for item in querydata:
            item_data = []
            for field in fields:
                item_data.append(item[field])
            table_data.append(item_data)

        # create table
        wh_table = Table(table_data)
        wh_table.hAlign = 'LEFT'
        wh_table.setStyle(TableStyle(
            [('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
             ('BOX', (0, 0), (-1, -1), 0.5, colors.black),
             ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
             ('BACKGROUND', (0, 0), (-1, 0), colors.gray)]))
        data.append(wh_table)
        data.append(Spacer(1, 48))

        doc.build(data)
        pdf = self.buffer.getvalue()
        self.buffer.close()
        return pdf

