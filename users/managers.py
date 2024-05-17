from django.db import models
from rest_framework_api_key.models import BaseAPIKeyManager


class ProfileManager(models.Manager):
    """
        Implements many shortcuts related to Profile
    """

    def get_queryset(self):
        return super(ProfileManager, self).get_queryset().select_related(
            'user',
        )

    def get_by_username(self, username: str = ''):
        """
            Obtains Profile by username
        """
        return self.get_queryset().filter(user__username=username).first()


class OrganizationAPIKeyManager(BaseAPIKeyManager):
    def get_usable_keys(self):
        return super().get_usable_keys().filter(organization__active=True)
