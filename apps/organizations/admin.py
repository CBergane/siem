from django.contrib import admin
from .models import Organization, APIKey, OrganizationMember


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'subscription_tier', 'is_active', 'created_at']
    list_filter = ['subscription_tier', 'is_active']
    search_fields = ['name', 'slug']


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ['name', 'organization', 'key_prefix', 'is_active', 'total_requests']
    list_filter = ['is_active', 'can_ingest']
    search_fields = ['name', 'organization__name']


@admin.register(OrganizationMember)
class OrganizationMemberAdmin(admin.ModelAdmin):
    list_display = ['user', 'organization', 'role', 'is_active']
    list_filter = ['role', 'is_active']
    search_fields = ['user__email', 'organization__name']
