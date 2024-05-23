from django.urls import path
from estrato.views import *

urlpatterns = [
    # General
    path('EstadosCuenta/',
         EstratoEstadosCuentaApiView.as_view({'post': 'create'})),
]
