from django.db import models


class SoftDeletionManager(models.Manager):
    def get_queryset(self):
        """
        Return a queryset that filters out any deleted items.

        :param self: The instance of the class.
        :return: A queryset that filters out any deleted items.
        """
        return super().get_queryset().filter(is_deleted=False)

    def all_objects(self):
        """
        Returns all objects in the queryset.

        :param self: The instance of the class.
        :return: The queryset containing all objects.
        """
        return super().get_queryset()
