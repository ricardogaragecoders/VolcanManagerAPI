"""
WSGI config for volcanmanagerapi project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/howto/deployment/wsgi/
"""
try:
    import newrelic.agent
    newrelic.agent.initialize('/opt/apps/config/newrelic.ini')
    newrelic_exists = True
except ImportError:
    newrelic_exists = False


import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'volcanmanagerapi.settings')

# prevenimos UnicodeEncodeError
# os.environ.setdefault("LANG", "es_ES.UTF-8")
# os.environ.setdefault("LC_ALL", "es_ES.UTF-8")

application = get_wsgi_application()

if newrelic_exists:
    application = newrelic.agent.WSGIApplicationWrapper(application)
