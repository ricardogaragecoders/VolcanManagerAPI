from django.urls import path
from webhook.views import *

urlpatterns = [
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
