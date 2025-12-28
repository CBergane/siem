"""
Celery tasks for alerts.
"""
from celery import shared_task
from .services.alert_checker import AlertChecker
import logging

logger = logging.getLogger(__name__)


@shared_task(name='alerts.evaluate_alert_rules')  # <-- Matcha gamla namnet
def check_alert_rules():
    """
    Periodic task to check all alert rules.
    Runs every minute via Celery beat.
    """
    logger.info("Starting alert rule check...")
    
    try:
        triggered_count = AlertChecker.check_all_rules()
        logger.info(f"Alert check complete: {triggered_count} alerts triggered")
        return triggered_count
    
    except Exception as e:
        logger.error(f"Error checking alert rules: {e}", exc_info=True)
        return 0
