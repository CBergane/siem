"""
Logs app configuration.
"""
from django.apps import AppConfig


class LogsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.logs'
    verbose_name = 'Security Logs'
    
    def ready(self):
        """Import signals when app is ready."""
        import apps.logs.signals  # noqa
