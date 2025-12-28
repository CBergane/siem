"""
URLs for alerts app.
"""
from django.urls import path
from . import views

app_name = 'alerts'

urlpatterns = [
    # Integrations
    path('integrations/', views.integrations_list, name='integrations_list'),
    path('integrations/add/<uuid:org_id>/', views.add_channel, name='add_channel'),
    path('integrations/delete/<uuid:channel_id>/', views.delete_channel, name='delete_channel'),
    path('integrations/test/<uuid:channel_id>/', views.test_channel, name='test_channel'),
    path('integrations/toggle/<uuid:channel_id>/', views.toggle_channel, name='toggle_channel'),
    
    # Alert Rules
    path('rules/', views.alert_rules_list, name='alert_rules_list'),
    path('rules/create/<uuid:org_id>/', views.create_alert_rule, name='create_alert_rule'),
    path('rules/delete/<uuid:rule_id>/', views.delete_alert_rule, name='delete_alert_rule'),
    path('rules/toggle/<uuid:rule_id>/', views.toggle_alert_rule, name='toggle_alert_rule'),
    
    # Alert History
    path('history/', views.alert_history, name='alert_history'),
    path('history/acknowledge/<uuid:alert_id>/', views.acknowledge_alert, name='acknowledge_alert'),
]
