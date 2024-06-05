from django.urls import path
from estrato.views import *

urlpatterns = [
    # General
    path('EstadosCuenta/',
         EstratoEstadosCuentaApiView.as_view({'post': 'create'})),

    path('ApiKeys/',
         EstratoApiKeyApiView.as_view({'get': 'list', 'post': 'create'})),
    path('ApiKeys/<str:api_key_id>/',
         EstratoApiKeyApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),
]
