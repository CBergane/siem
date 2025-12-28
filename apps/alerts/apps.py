"""
Alerts app configuration.
"""
from django.apps import AppConfig


class AlertsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.alerts'  # VIKTIGT: Fullständig path!
    verbose_name = 'Alerts & Notifications'
