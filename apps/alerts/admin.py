"""
Admin configuration for alerts app.
"""
from django.contrib import admin
from .models import AlertRule, AlertHistory, NotificationChannel


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'organization', 'enabled', 'condition_type', 'threshold', 'trigger_count', 'last_triggered']
    list_filter = ['enabled', 'condition_type', 'organization']
    search_fields = ['name', 'description']
    readonly_fields = ['last_triggered', 'trigger_count', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('organization', 'name', 'description', 'enabled', 'created_by')
        }),
        ('Condition', {
            'fields': ('condition_type', 'threshold', 'time_window_minutes')
        }),
        ('Filters', {
            'fields': ('source_type', 'action', 'severity', 'country_code', 'ip_address')
        }),
        ('Notifications', {
            'fields': ('notification_channels', 'cooldown_minutes')
        }),
        ('Statistics', {
            'fields': ('trigger_count', 'last_triggered', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(AlertHistory)
class AlertHistoryAdmin(admin.ModelAdmin):
    list_display = ['alert_rule', 'organization', 'triggered_at', 'event_count', 'severity', 'acknowledged']
    list_filter = ['severity', 'acknowledged', 'organization', 'triggered_at']
    search_fields = ['alert_rule__name']
    readonly_fields = ['triggered_at', 'notifications_sent', 'details']
    
    fieldsets = (
        ('Alert Information', {
            'fields': ('organization', 'alert_rule', 'triggered_at', 'severity')
        }),
        ('Event Details', {
            'fields': ('event_count', 'details')
        }),
        ('Notifications', {
            'fields': ('notifications_sent',)
        }),
        ('Acknowledgement', {
            'fields': ('acknowledged', 'acknowledged_by', 'acknowledged_at')
        }),
    )


@admin.register(NotificationChannel)
class NotificationChannelAdmin(admin.ModelAdmin):
    list_display = ['name', 'organization', 'channel_type', 'enabled', 'verified', 'total_notifications', 'failed_notifications']
    list_filter = ['channel_type', 'enabled', 'verified', 'organization']
    search_fields = ['name']
    readonly_fields = ['last_used', 'total_notifications', 'failed_notifications', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('organization', 'name', 'channel_type', 'enabled', 'created_by')
        }),
        ('Configuration', {
            'fields': ('config', 'verified')
        }),
        ('Statistics', {
            'fields': ('total_notifications', 'failed_notifications', 'last_used', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
