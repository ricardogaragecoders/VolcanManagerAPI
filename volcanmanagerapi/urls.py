"""volcanmanagerapi URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from django.contrib.staticfiles.urls import static

from users.views import CustomTokenObtainPairView, CustomTokenRefreshView, CustomTokenVerifyView

urlpatterns = [
    path('volcan/api/auth/token/',
         CustomTokenObtainPairView.as_view({'post': 'post'}), name='token_obtain_pair'),

    path('volcan/api/auth/token/refresh/',
         CustomTokenRefreshView.as_view(), name='token_refresh'),

    path('volcan/api/auth/token/verify/',
         CustomTokenVerifyView.as_view(), name='token_verify'),

    path('volcan/api/commons/', include('common.urls')),
    path('volcan/api/users/', include('users.urls')),

    path('volcan/api/', include('control.urls')),
    path('volcan/api/', include('webhook.urls')),

    path('volcan/api/', include('estrato.urls')),

    path('volcan/api/', include('reports.urls')),

    path('', include('thalesapi.urls')),

]


if settings.DEBUG:
    import debug_toolbar
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns = [
        path('admin/', admin.site.urls),
        path('', include('swagger_ui.urls')),
        path('__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns
else:
    urlpatterns = [
        path('', include('swagger_ui.urls')),
    ] + urlpatterns
