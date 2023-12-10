from django.urls import path
from thalesapi.views import *

urlpatterns = [

    path('thales/api/bin/configurations/',
         CardBinConfigApiView.as_view({'get': 'list', 'post': 'create'})),
    path('thales/api/bin/configurations/<str:card_bin_config_id>/',
         CardBinConfigApiView.as_view({'get': 'retrieve', 'patch': 'update'})),

    # General
    path('cms/api/v1/issuers/<str:issuer_id>/cards/credentials',
         ThalesApiView.as_view({'post': 'post_verify_card'})),

    path('cms/api/v1/issuers/<str:issuer_id>/cards/<str:card_id>/credentials',
         ThalesApiView.as_view({'get': 'get_card_credentials'})),

    path('banking/d1/v1/issuers/<str:issuer_id>/consumers/<str:consumer_id>',
         ThalesApiView.as_view({'get': 'get_consumer_information'})),

    path('notifications/d1/v1/issuers/<str:issuer_id>/cards/<str:card_id>/notifications',
         ThalesApiView.as_view({'post': 'post_notify_card_operation'})),

    path('testing/cms/api/v1/issuers/<str:issuer_id>/cards/<str:card_id>/credentials',
         ThalesApiView.as_view({'post': 'get_card_credentials_testing'})),

    path('volcan/api/obtenerDatosTokenizacion/',
         ThalesApiViewPrivate.as_view({'post': 'get_card_data_tokenization'})),

    path('thales/api/registerConsumerCards/',
         ThalesApiViewPrivate.as_view({'post': 'post_register_consumer_cards'})),
]
