from django.urls import path

from .views import *

urlpatterns = [
    # General
    path('status/', StatusApiView.as_view({'get': 'get'})),

]
