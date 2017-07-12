from django.contrib import admin

from .models import PasswordResetAuth


class PasswordResetAuthAdmin(admin.ModelAdmin):
    list_display = ['email', 'token', 'is_expired']

admin.site.register(PasswordResetAuth, PasswordResetAuthAdmin)
