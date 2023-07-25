from django.db import models


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
