"""
Signals for automatic log enrichment.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import SecurityLog
from django.conf import settings
from .tasks import enqueue_geoip_enrichment
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
    
    if not getattr(settings, "ENABLE_GEO_LOOKUP", False):
        return

    # Queue enrichment task with sync fallback
    if enqueue_geoip_enrichment(instance, allow_sync=True):
        logger.info(f"Queued GeoIP enrichment for log {instance.id} (IP: {instance.src_ip})")
