from django.urls import path
from corresponsalia.views import *

urlpatterns = [
    # General
    path('Corresponsalias/Configuracion/',
         CorresponsaliaApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Corresponsalias/Configuracion/<str:corresponsalia_id>/',
         CorresponsaliaApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),

    path('Corresponsalias/Transacciones/',
         TransaccionApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Corresponsalias/Transacciones/<str:transaccion_id>/',
         TransaccionApiView.as_view({'get': 'retrieve'})),

]
