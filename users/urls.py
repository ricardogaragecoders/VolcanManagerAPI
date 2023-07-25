from django.urls import path

from .views import *

urlpatterns = [
    # admin tools
    path('empty/', EmptyApiView.as_view({'post': 'post'})),
    path('reset/password/', ResetPasswordApiView.as_view({'post': 'post'})),
    path('whitelists/', WhiteListedTokenApiView.as_view({'get': 'list'})),
    # path('login/log/', LoginLogApiView.as_view({'get': 'get'})),

    # profile
    path('profile/', ProfileApiView.as_view({'get': 'retrieve'})),

    # users
    path('logout/', LogoutApiView.as_view({'post': 'post'})),
    path('register/admin/', RegisterAdminAPIView.as_view({'post': 'post'})),
    path('verification/code/', VerificationCodeAPIView.as_view({'post': 'post'})),
    path('resend/code/', ResendCodeAPIView.as_view({'post': 'post'})),
    path('change/password/', ChangePasswordApiView.as_view({'post': 'post'})),
    path('recover/password/', RecoverPasswordApiView.as_view({'post': 'post'})),

    # groups
    path('groups/', GroupApiView.as_view({'get': 'list', })),

]
