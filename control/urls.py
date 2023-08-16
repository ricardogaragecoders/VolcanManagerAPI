from django.urls import path
from control.views import *

urlpatterns = [
    # General
    path('CreacionEnte/', ControlApiView.as_view({'post': 'creation_ente'})),
    path('CreacionCtaTar/', ControlApiView.as_view({'post': 'creation_cta_tar'})),
    path('Cuentas/', ControlApiView.as_view({'post': 'consulta_cuenta'})),
    path('Extrafinanciamientos/', ControlApiView.as_view({'post': 'extrafinanciamientos'})),
    path('Intrafinanciamientos/', ControlApiView.as_view({'post': 'intrafinanciamientos'})),
    path('ConsultaTarjetas/', ControlApiView.as_view({'post': 'consulta_tarjetas'})),
    path('CambioPIN/', ControlApiView.as_view({'post': 'cambio_pin'})),
    path('CambioLimites/', ControlApiView.as_view({'post': 'cambio_limites'})),
    path('CambioEstatusTDC/', ControlApiView.as_view({'post': 'cambio_estatus_tdc'})),
    path('ReposicionTarjetas/', ControlApiView.as_view({'post': 'reposicion_tarjetas'})),


    path('Webhooks/',
         WebHookApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Webhooks/<str:webhook_id>/',
         WebHookApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),

    path('Notificaciones/',
         TransactionCollectionApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Notificaciones/<str:notification_id>/',
         TransactionCollectionApiView.as_view({'get': 'retrieve'})),

    path('Notificaciones/<str:notification_id>/reenviar/',
         TransactionCollectionApiView.as_view({'patch': 'update'})),

    path('Notificaciones/reenviar/emisor/',
         TransactionCollectionApiView.as_view({'patch': 'resend'})),

]
