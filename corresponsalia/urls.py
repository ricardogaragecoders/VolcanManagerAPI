from django.urls import path
from corresponsalia.views import *

urlpatterns = [
    # General
    path('Corresponsalias/',
         CorresponsaliaApiView.as_view({'get': 'list', 'post': 'create'})),
    path('Corresponsalias/<str:corresponsalia_id>/',
         CorresponsaliaApiView.as_view({'get': 'retrieve', 'patch': 'update', 'delete': 'destroy'})),


]
