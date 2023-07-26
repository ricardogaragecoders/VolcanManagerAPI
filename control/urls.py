from django.urls import path
from control.views import *

urlpatterns = [
    # General
    path('CreacionEnte/', ControlApiView.as_view({'post': 'creation_ente'})),
    path('CreacionCtaTar/', ControlApiView.as_view({'post': 'creation_cta_tar'})),
]
