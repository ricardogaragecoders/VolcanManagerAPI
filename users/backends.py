from django.conf import settings
from django.contrib.auth import get_user_model, login, user_logged_in
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q


class EmailOrUsernameModelBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        auth_type = settings.AUTH_AUTHENTICATION_TYPE
        user_model = get_user_model()
        try:
            if auth_type == 'both':
                user = user_model.objects.get(
                    Q(username__iexact=username) | Q(email__iexact=username)
                )
            else:
                user = user_model.objects.get(email__iexact=username)
            if password and len(password) > 0 and user.check_password(password):
                # user_logged_in.send(sender=user.__class__, request=request, user=user)
                return user
            else:
                # from django.apps import apps
                # if apps.is_installed('safety'):
                #     from safety.utils import safety_ip
                #     safety_ip(request=request)
                return None
        except user_model.DoesNotExist:
            # from safety.utils import safety_ip
            # safety_ip(request=request)
            return None
