from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import Profile, WhiteListedToken, OrganizationAPIKey, Organization
from rest_framework_api_key.admin import APIKeyModelAdmin


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'


class CustomUserAdmin(UserAdmin):
    inlines = (ProfileInline,)

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


@admin.register(WhiteListedToken)
class WhiteListedTokenAdmin(admin.ModelAdmin):
    fields = ('user', 'device_token', 'type_token', 'token')
    list_display = ('user', 'type_token', 'created_at')
    search_fields = ['user__username']


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    fields = ('name', 'active')
    list_display = ('name', 'active')
    search_fields = ['name']


@admin.register(OrganizationAPIKey)
class OrganizationAPIKeyModelAdmin(APIKeyModelAdmin):
    pass

