from django.urls import path

from reports.views import ReportApiView

urlpatterns = [
    # Reportes
    path('reports/',
         ReportApiView.as_view({'get': 'list', 'post': 'create'})),
    path('reports/<str:report_id>/',
         ReportApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),
]