from django.urls import path
from webhook.views import *

urlpatterns = [
    path('Webhooks/',
         WebHookApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Webhooks/<str:webhook_id>/',
         WebHookApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),

    path('Notificaciones/',
         NotificationTransactionApiView.as_view({'get': 'list', 'post': 'create'})),

    path('Notificaciones/Prepago/',
         NotificationTransactionApiView.as_view({'post': 'paycard_notification'})),

    path('Notificaciones/<str:notification_id>/Detalle/',
         NotificationTransactionApiView.as_view({'get': 'retrieve'})),

    path('Notificaciones/<str:notification_id>/Reenviar/',
         NotificationTransactionApiView.as_view({'patch': 'update'})),

    path('Notificaciones/Reenviar/Emisor/',
         NotificationTransactionApiView.as_view({'patch': 'resend'})),

    path('Transacciones/Error/',
         TransactionErrorApiView.as_view({'get': 'list'})),
    path('Transacciones/Error/<str:transaction_error_id>/Detalle/',
         TransactionErrorApiView.as_view({'get': 'retrieve'})),
]
