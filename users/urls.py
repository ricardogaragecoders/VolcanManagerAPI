from django.urls import path

from .views import *

urlpatterns = [
    # admin tools
    path('empty/', EmptyApiView.as_view({'post': 'create'})),
    path('reset/password/', ResetPasswordApiView.as_view({'post': 'create'})),
    path('whitelists/', WhiteListedTokenApiView.as_view({'get': 'list'})),
    # path('login/log/', LoginLogApiView.as_view({'get': 'list'})),

    # profile
    path('profile/', ProfileApiView.as_view({'get': 'retrieve'})),

    # users
    path('logout/', LogoutApiView.as_view({'post': 'create'})),
    path('register/admin/', RegisterAdminAPIView.as_view({'post': 'create'})),
    path('verification/code/', VerificationCodeAPIView.as_view({'post': 'create'})),
    path('resend/code/', ResendCodeAPIView.as_view({'post': 'create'})),
    path('change/password/', ChangePasswordApiView.as_view({'post': 'create'})),
    path('recover/password/', RecoverPasswordApiView.as_view({'post': 'create'})),

    # groups
    path('groups/', GroupApiView.as_view({'get': 'list', })),

]
