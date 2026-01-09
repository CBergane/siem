"""
Celery configuration.
"""
import os
from celery import Celery
from celery.schedules import crontab

# Set default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('firewall_report_center')

# Load config from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks
app.autodiscover_tasks()

# Beat schedule for periodic tasks
app.conf.beat_schedule = {
    # Check alert rules every minute
    'check-alert-rules': {
        'task': 'check_alert_rules',
        'schedule': 60.0,  # Every 60 seconds
    },
    'prune-inventory-snapshots': {
        'task': 'logs.prune_inventory_snapshots',
        'schedule': crontab(hour=3, minute=30),
        'args': (30,),
    },
}

app.conf.timezone = 'UTC'

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
