from rest_framework import permissions
from rest_framework_api_key.permissions import BaseHasAPIKey
from .models import Profile, OrganizationAPIKey


class IsChangePassword(permissions.BasePermission):
    """
        Is user change password process?.
    """

    message = u'Su cuenta tiene un proceso de cambio de contraseña pendiente'
    code = 'change_password_required'

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return not profile.change_password
        return False


class IsVerified(permissions.BasePermission):
    """
        Is the email verified?.
    """

    message = u'Su cuenta de correo electrónico no ha sido verificada'
    code = 'unverified_email'

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return profile.verification_email and not profile.change_password
        return False


class IsAuthenticatedUser(permissions.BasePermission):
    """
        Is the user authenticated?.
    """

    message = 'Usuario no autenticado'
    code = 'unauthenticated_user'

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


class IsClient(permissions.BasePermission):
    """
        Is the user a client?
    """

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return profile.role >= Profile.CLIENT
        return False


class IsOperator(permissions.BasePermission):
    """
        Is the user a call center?
    """

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return profile.role >= Profile.OPERATOR
        return False


class IsSupervisor(permissions.BasePermission):
    """
        Is the user a program administrator?
    """

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return profile.role >= Profile.SUPERVISOR
        return False


class IsAdministrator(permissions.BasePermission):
    """
        Is the user a general administrator?
    """

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return profile.role >= Profile.ADMINISTRATOR
        return False


class IsSuperadmin(permissions.BasePermission):
    """
        Is the user a super administrator?
    """

    def has_permission(self, request, view):
        if request.user and request.user.profile:
            profile = request.user.profile
            if not profile.deleted_at:
                return profile.role == Profile.SUPERADMIN
        return False


class HasOrganizationAPIKey(BaseHasAPIKey):
    model = OrganizationAPIKey
