"""
Signals for automatic log enrichment.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import SecurityLog
from .tasks import enrich_log_with_geoip
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=SecurityLog)
def auto_enrich_log(sender, instance, created, **kwargs):
    """
    Automatically enrich new logs with GeoIP data.
    
    Triggers after a SecurityLog is created to queue a Celery task
    for GeoIP enrichment.
    """
    # Only process newly created logs
    if not created:
        return
    
    # Skip if already enriched
    if instance.geo_enriched:
        return
    
    # Skip if no source IP
    if not instance.src_ip:
        logger.debug(f"Log {instance.id} has no source IP, skipping auto-enrichment")
        return
    
    # Queue enrichment task
    try:
        enrich_log_with_geoip.delay(str(instance.id))
        logger.info(f"Queued GeoIP enrichment for log {instance.id} (IP: {instance.src_ip})")
    except Exception as e:
        logger.error(f"Failed to queue enrichment for log {instance.id}: {str(e)}")
