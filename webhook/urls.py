from django.urls import path
from webhook.views import *

urlpatterns = [
    path('Webhooks/',
         WebHookApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Webhooks/<str:webhook_id>/',
         WebHookApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),

    path('Notificaciones/',
         NotificationTransactionApiView.as_view({'get': 'list', 'post': 'create'})),

    path('Prepago/Notificaciones/',
         NotificationTransactionApiView.as_view({'post': 'paycard_notification'})),

    path('Notificaciones/<str:notification_id>/',
         NotificationTransactionApiView.as_view({'get': 'retrieve'})),

    path('Notificaciones/<str:notification_id>/reenviar/',
         NotificationTransactionApiView.as_view({'patch': 'update'})),
    path('Notificaciones/reenviar/emisor/',
         NotificationTransactionApiView.as_view({'patch': 'resend'})),

]
