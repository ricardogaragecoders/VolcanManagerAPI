from rest_framework import permissions


class HasPermissionByMethod(permissions.BasePermission):
    """
        Ensure user has permission by method.
    """

    def has_permission(self, request, view):
        # Get a mapping of methods -> permissions.
        method_permissions_mapping = getattr(view, "method_permissions", {})

        # Return permissions by method.
        method_permissions = method_permissions_mapping.get(request.method, [])

        # If any permission fails, it is understood that you do not have sufficient permissions..
        resp = False
        for permission_class in method_permissions:
            if permission_class().has_permission(request, view):
                resp = True
            else:
                resp = False
                break
        return resp


class HasUserAndPasswordInData(permissions.BasePermission):
    """
        Has it user and password valid?.
    """

    message = u'El usuario y/o password no son validos'
    code = '401'

    def has_permission(self, request, view):
        if 'user' in request.data and 'password' in request.data:
            from django.conf import settings
            user = request.data.get('user')
            password = request.data.get('password')
            return user == settings.VOLCAN_USER_TRANSACTION and password == settings.VOLCAN_PASSWORD_TRANSACTION
        return False
