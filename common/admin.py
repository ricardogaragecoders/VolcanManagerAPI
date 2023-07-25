from django.contrib import admin

# Register your models here.
from common.models import Status


@admin.register(Status)
class StatusAdmin(admin.ModelAdmin):
    fields = ('name', 'slug')
    list_display = ('name', 'slug')
