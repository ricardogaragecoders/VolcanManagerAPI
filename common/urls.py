from django.urls import path

from .views import *

urlpatterns = [
    # General
    path('status/', StatusApiView.as_view({'get': 'get'})),

    path('monitor/systems/',
         MonitorCollectionApiView.as_view({'get': 'get'})),
    path('monitor/systems/<str:monitor_system_id>/',
         MonitorCollectionApiView.as_view({'get': 'retrieve'})),

]
