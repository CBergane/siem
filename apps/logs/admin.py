"""
Admin configuration for logs app.
"""
from django.contrib import admin
from .models import SecurityLog


@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    """Admin interface for SecurityLog."""
    
    list_display = ['timestamp', 'src_ip', 'country_name', 'city', 'source_type', 'action', 'severity', 'geo_enriched']
    list_filter = ['source_type', 'action', 'severity', 'geo_enriched', 'country_code']
    search_fields = ['src_ip', 'country_name', 'city', 'isp']
    readonly_fields = ['geo_enriched', 'geo_enriched_at']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('organization', 'source_type', 'source_host', 'timestamp')
        }),
        ('Network', {
            'fields': ('src_ip', 'src_port', 'dst_ip', 'dst_port')
        }),
        ('Geographic Information', {
            'fields': ('country_code', 'country_name', 'city', 'region', 'latitude', 'longitude', 'timezone', 'geo_enriched', 'geo_enriched_at')
        }),
        ('ISP Information', {
            'fields': ('asn', 'isp', 'org')
        }),
        ('HTTP', {
            'fields': ('method', 'path', 'status_code', 'bytes_sent', 'user_agent')
        }),
        ('Action', {
            'fields': ('action', 'severity', 'reason')
        }),
        ('Raw Data', {
            'fields': ('raw_log', 'metadata'),
            'classes': ('collapse',)
        }),
    )
