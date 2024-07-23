"""
Django settings for volcanmanagerapi project.

Generated by 'django-admin startproject' using Django 3.2.12.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

import os
from datetime import timedelta
from pathlib import Path

import environ

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

env = environ.Env(
    # set casting, default value
    DEBUG=(bool, False)
)

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env('DEBUG')

ALLOWED_HOSTS = env('ALLOWED_HOSTS').split(',')

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.humanize',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.postgres',
    # third parties
    'rest_framework',
    'corsheaders',
    # modules
    'users',
    'common',
    'control',
    'thalesapi',
    'webhook',
    'estrato'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'common.middleware.RequestMiddleware',
    'common.middleware.RequestLoggingMiddleware',
]

APPEND_SLASH = False

ROOT_URLCONF = 'volcanmanagerapi.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'volcanmanagerapi.wsgi.application'

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': env.db()
}

# mongodb
MONGO_DB = {
    'volcanmanagerapidb': {
        'URL': env.str('MONGODB_URL')
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": env.str('REDIS_URL'),
    }
}

# Backend login
AUTH_AUTHENTICATION_TYPE = 'both'
AUTHENTICATION_BACKENDS = (
    'users.backends.EmailOrUsernameModelBackend',
)

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Rest Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication'
    ),
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
        'rest_framework.parsers.JSONParser',
    ],
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'EXCEPTION_HANDLER': 'common.utils.custom_exception_handler'
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),  # timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=30),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(days=1),  # timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=30),
}

# Email configurations
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env.str('MAIL_SERVER')
EMAIL_PORT = env.int('MAIL_SERVER_PORT')
EMAIL_HOST_USER = env.str('MAIL_SERVER_USER')
EMAIL_HOST_PASSWORD = env.str('MAIL_SERVER_PASSWORD')
EMAIL_USE_TLS = env.bool('MAIL_USE_TLS')

# security
X_FRAME_OPTIONS = env.str('X_FRAME_OPTIONS', "DENY")
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

# SSL configuration
# SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# HSTS configuration
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_SECONDS = 3600

# only Debug mode
if DEBUG:
    SWAGGER_YAML_FILE = os.path.join(BASE_DIR, "swagger.yaml")

    REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] = (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication'
    )

    REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES'] = [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ]

    INSTALLED_APPS = ['debug_toolbar', 'swagger_ui', 'sslserver', ] + INSTALLED_APPS

    MIDDLEWARE = ['debug_toolbar.middleware.DebugToolbarMiddleware', ] + MIDDLEWARE

    INTERNAL_IPS = ('127.0.0.1',)

    DEBUG_TOOLBAR_PANELS = [
        'debug_toolbar.panels.versions.VersionsPanel',
        'debug_toolbar.panels.timer.TimerPanel',
        'debug_toolbar.panels.settings.SettingsPanel',
        'debug_toolbar.panels.headers.HeadersPanel',
        'debug_toolbar.panels.request.RequestPanel',
        'debug_toolbar.panels.sql.SQLPanel',
        'debug_toolbar.panels.staticfiles.StaticFilesPanel',
        'debug_toolbar.panels.templates.TemplatesPanel',
        'debug_toolbar.panels.cache.CachePanel',
        'debug_toolbar.panels.signals.SignalsPanel',
        'debug_toolbar.panels.logging.LoggingPanel',
        'debug_toolbar.panels.redirects.RedirectsPanel',
        'debug_toolbar.panels.profiling.ProfilingPanel',
    ]

    DEBUG_TOOLBAR_CONFIG = {
        # Toolbar options
        'RESULTS_CACHE_SIZE': 3,
        'SHOW_COLLAPSED': True,
        # Panel options
        'SQL_WARNING_THRESHOLD': 100,  # milliseconds
    }
else:
    SWAGGER_YAML_FILE = os.path.join(BASE_DIR, "swagger_prod.yaml")
    INSTALLED_APPS = ['swagger_ui', ] + INSTALLED_APPS

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'complete': {
            'format': '[%(asctime)s][%(threadName)s:%(thread)d][task_id:%(name)s][%(filename)s:%(lineno)d]'
                      '[%(levelname)s][%(message)s]'
        },
        'standard': {
            'format': '[%(levelname)s][%(asctime)s][%(filename)s:%(lineno)d]%(message)s'
        },
        'collect': {
            'format': '%(message)s'
        }
    },
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },
    'handlers': {
        'console_debug': {
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'collect'
        },
        'console_error': {
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
        'logfile': {
            'level': 'ERROR',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': os.path.join(BASE_DIR, "logfile.log"),
            'when': 'midnight',  # rotar a medianoche
            'interval': 1,
            'backupCount': 30,  # mantener 30 días de backups
            'formatter': 'complete',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console_debug', 'console_error', 'logfile'],
            'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
            'propagate': True,
        },
        'django': {
            'handlers': ['console_debug', 'console_error', 'logfile'],
            'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console_debug', 'console_error', 'logfile'],
            'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console_debug', 'console_error', 'logfile'],
            'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['console_debug', 'console_error', 'logfile'],
            'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
            'propagate': False,
        },
        'django.template': {
            'handlers': ['console_debug', 'console_error', 'logfile'],
            'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
            'propagate': False,
        },
        # 'common.middleware.RequestLoggingMiddleware': {
        #     'handlers': ['console_debug', 'console_error', 'logfile'],
        #     'level': env.str('DJANGO_LOG_LEVEL', 'DEBUG'),
        #     'propagate': False,
        # },
    },
}

# URLs
URL_BACKEND = env.str('URL_BACKEND', 'http://localhost:8000')
EMAIL_CONTACT = env.str('EMAIL_CONTACT', 'info@volcangroup.io')
DEFAULT_PASSWORD = env.str('DEFAULT_PASSWORD', '')

SERVER_VOLCAN_AZ7_URL = env.str('SERVER_VOLCAN_AZ7_URL', 'http://10.23.102.10:21005')
SERVER_VOLCAN_PAYCARD_URL = env.str('SERVER_VOLCAN_PAYCARD_URL', 'http://10.23.106.33/wsParabiliumVolcan')

PUB_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM = env.str('PUB_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM', '')
PRIV_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM = env.str('PRIV_KEY_D1_SERVER_TO_ISSUER_SERVER_PEM', '')

PUB_KEY_ISSUER_SERVER_TO_D1_SERVER_PEM = env.str('PUB_KEY_ISSUER_SERVER_TO_D1_SERVER_PEM', '')

PRIV_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM = env.str('PRIV_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM', '')
PUB_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM = env.str('PUB_KEY_AUTH_ISSUER_SERVER_TO_D1_SERVER_PEM', '')

# certificates Thales
SSL_CERTIFICATE_THALES_CRT = env.str('SSL_CERTIFICATE_THALES_CRT', '')
SSL_CERTIFICATE_THALES_KEY = env.str('SSL_CERTIFICATE_THALES_KEY', '')

VOLCAN_USUARIO_ATZ = env.str('USUARIO_ATZ', 'KLEWIS')
VOLCAN_ACCESO_ATZ = env.str('ACCESO_ATZ', 'KLEWIS')
AZ7_SECRET_KEY = env.str('AZ7_SECRET_KEY', '')

THALES_API_ENCRYPTED_K01_KID = env.str('THALES_API_ENCRYPTED_K01_KID', '')
THALES_API_ENCRYPTED_K03_KID = env.str('THALES_API_ENCRYPTED_K03_KID', '')
THALES_API_ENCRYPTED_K06_AUTH_KID = env.str('THALES_API_ENCRYPTED_K06_AUTH_KID', '')
THALES_API_EMISOR_DEFAULT = env.str('THALES_API_EMISOR_DEFAULT', 'CMF')

THALES_API_AUD = env.str('THALES_API_AUD', '')
THALES_API_ISSUER_ID = env.str('THALES_API_ISSUER_ID', '')
URL_THALES_AUTHORIZATION_TOKEN = env.str('URL_THALES_AUTHORIZATION_TOKEN', '')
URL_THALES_REGISTER_CONSUMER = env.str('URL_THALES_REGISTER_CONSUMER', '')
URL_THALES_REGISTER_CONSUMER_CARDS = env.str('URL_THALES_REGISTER_CONSUMER_CARDS', '')

# THALESAPI_AUTORIZACION_DEFAULT = env.str('THALESAPI_AUTORIZACION_DEFAULT', '')

VOLCAN_USER_TRANSACTION = env.str('VOLCAN_USER_TRANSACTION', '')
VOLCAN_PASSWORD_TRANSACTION = env.str('VOLCAN_PASSWORD_TRANSACTION', '')

# config
ENABLE_SEND_EMAIL = env.bool('ENABLE_SEND_EMAIL', True)
ENABLE_2FACTOR_AUTHENTICATION = env.bool('ENABLE_2FACTOR_AUTHENTICATION', False)
PASSWORD_DEFAULT = env.str('PASSWORD_DEFAULT', '')
VERIFICATION_ADMINISTRATOR_DEFAULT = env.bool('VERIFICATION_ADMINISTRATOR_DEFAULT', True)
PATH_IMAGE_LOGO = env.str('PATH_IMAGE_LOGO')
PATH_ISO_COUNTRIES_CSV = env.str('PATH_ISO_COUNTRIES_CSV', '')

# API KEY
APIKEY_ESTRATO_VOLCAN_API_ENABLED = env.bool('APIKEY_ESTRATO_VOLCAN_API_ENABLED', False)
API_KEY_FID = env.str('API_KEY_FID', '')
SERVER_ESTRATO_VOLCAN_URL = env.str('SERVER_ESTRATO_VOLCAN_URL', '')
ESTRATO_LIMIT_QUERY = env.int('ESTRATO_LIMIT_QUERY', 5)


from corsheaders.defaults import default_headers, default_methods

CORS_ORIGIN_ALLOW_ALL = False
CORS_ORIGIN_WHITELIST = env('CORS_ALLOWED_ORIGINS').split(',')
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS').split(',')
CORS_ALLOW_HEADERS = list(default_headers)
CORS_ALLOW_METHODS = list(default_methods)
CORS_EXPOSE_HEADERS = list(default_headers) + ['content-disposition', ]

CELERY_BROKER_URL = env.str('RABBITMQ_URL')
CELERY_RESULT_BACKEND = env.str('CELERY_RESULT_BACKEND')
MAX_RETRIES_CELERY_TASK = env.int('MAX_RETRIES_CELERY_TASK', 5)
MIN_WAIT_FOR_RETRY_CELERY_TASK = env.int('MIN_WAIT_FOR_RETRY_CELERY_TASK', 5 * 60)

URL_CMF_DELIVER_OTP = env.str('URL_CMF_DELIVER_OTP', '')

URL_THALES_API_VERIFY_CARD = env.str('URL_THALES_API_VERIFY_CARD', '/web/services/VerifyCard_1')
URL_THALES_API_GET_CONSUMER = env.str('URL_THALES_API_GET_CONSUMER', '/web/services/Volcan_GetConsumer_1')
URL_THALES_API_GET_CARD_CREDENTIALS = env.str('URL_THALES_API_GET_CARD_CREDENTIALS',
                                              '/web/services/GetCardCredentials_1')
URL_AZ7_ALTA_ENTE = env.str('URL_AZ7_ALTA_ENTE', '/web/services/Volcan_Alta_Ente_1')
URL_AZ7_ALTA_ENTE_SECTORIZACION = env.str('URL_AZ7_ALTA_ENTE_SECTORIZACION', '/web/services/Volcan_Alta_Ente_1')
URL_AZ7_ALTA_CUENTA = env.str('URL_AZ7_ALTA_CUENTA', '/web/services/Volcan_Alta_Cuenta_1')
URL_AZ7_CONSULTA_CUENTA = env.str('URL_AZ7_CONSULTA_CUENTA', '/web/services/Volcan_Consulta_Cuenta_1')
URL_AZ7_EXTRA_FINANCIAMIENTO = env.str('URL_AZ7_EXTRA_FINANCIAMIENTO', '/web/services/Volcan_ExtraFinanciamiento_1')
URL_AZ7_INTRA_FINANCIAMIENTO = env.str('URL_AZ7_INTRA_FINANCIAMIENTO', '/web/services/Volcan_Intrafinanciamiento_1')
URL_AZ7_CONSULTA_TARJETAS = env.str('URL_AZ7_CONSULTA_TARJETAS', '/web/services/Consulta_Tarjetas_1')
URL_AZ7_CAMBIO_PIN = env.str('URL_AZ7_CAMBIO_PIN', '/web/services/Cambio_PIN_1')
URL_AZ7_CAMBIO_LIMITES = env.str('URL_AZ7_CAMBIO_LIMITES', '/web/services/Cambio_limites_1')
URL_AZ7_CAMBIO_ESTATUS_TDC = env.str('URL_AZ7_CAMBIO_ESTATUS_TDC', '/web/services/Cambio_estatus_TDC_1')
URL_AZ7_REPOSICION_TARJETAS = env.str('URL_AZ7_REPOSICION_TARJETAS', '/web/services/Reposicion_Tarjetas_1')
URL_AZ7_GESTION_TRANSACCIONES = env.str('URL_AZ7_GESTION_TRANSACCIONES', '/web/services/Volcan_GestionTrx_1')
URL_AZ7_CONSULTAR_ENTE = env.str('URL_AZ7_CONSULTAR_ENTE', '/web/services/Volcan_Consulta_Ente_1')
URL_AZ7_CONSULTAR_MOVIMIENTOS = env.str('URL_AZ7_CONSULTAR_MOVIMIENTOS', '/web/services/Volcan_ConsultaMov_1')
URL_AZ7_CONSULTAR_PUNTOS = env.str('URL_AZ7_CONSULTAR_PUNTOS', '/web/services/Volcan_ConsultaPuntos_1')
URL_AZ7_INTRAS_EXTRAS = env.str('URL_AZ7_INTRAS_EXTRAS', '/web/services/Volcan_Intra_Extras')
URL_AZ7_CONSULTA_INTRA_EXTRA = env.str('URL_AZ7_CONSULTA_INTRA_EXTRA', '/web/services/Volcan_ConsultaIntraExtraF1')
URL_AZ7_CONSULTA_TRANSACCION_X_FECHA = env.str('URL_AZ7_CONSULTA_TRANSACCION_X_FECHA',
                                               '/web/services/Volcan_ConsultaTxnXFecha1')
URL_AZ7_CONSULTA_CVV2 = env.str('URL_AZ7_CONSULTA_CVV2', '/web/services/Volcan_CVV2_1')
URL_AZ7_CONSULTA_ESTADO_CUENTA = env.str('URL_AZ7_CONSULTA_ESTADO_CUENTA',
                                         '/web/services/Volcan_ConsultaEstadoCta_1')
URL_AZ7_CONSULTA_COBRANZA = env.str('URL_AZ7_CONSULTA_COBRANZA',
                                    '/web/services/Volcan_Consulta_cobranza_1')

# obtenerDatosTokenizacionPrepago
URL_AZ7_LOGIN = env.str('URL_AZ7_LOGIN', '/wsParabiliumVolcan/api/Login')
URL_AZ7_CONSULTA_TOKEN_TARJETA = env.str('URL_AZ7_CONSULTA_TOKEN_TARJETA',
                                         '/wsParabiliumVolcan/api/ConsultarTokenTarjeta')
PARAM_AZ7_PAYCARD_USUARIO = env.str('PARAM_AZ7_PAYCARD_USUARIO', '')
PARAM_AZ7_PAYCARD_PASSWORD = env.str('PARAM_AZ7_PAYCARD_PASSWORD', '')
