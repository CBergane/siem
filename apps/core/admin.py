from django.contrib import admin
from .models import JoinRequest


@admin.register(JoinRequest)
class JoinRequestAdmin(admin.ModelAdmin):
    list_display = ("email", "company", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("email", "company", "full_name")
    readonly_fields = ("ip_address", "user_agent", "created_at")
