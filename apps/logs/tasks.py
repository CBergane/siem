"""
Celery tasks for log processing.
"""
import logging
import time

from celery import shared_task
from django.conf import settings

from .models import SecurityLog
from .services.geoip import GeoIPService

logger = logging.getLogger(__name__)


@shared_task(name='logs.enrich_log_with_geoip')
def enrich_log_with_geoip(log_id):
    """
    Enrich log entry with GeoIP data.
    """
    try:
        log = SecurityLog.objects.get(id=log_id)
    except SecurityLog.DoesNotExist:
        logger.error(f"Log {log_id} not found")
        return
    except Exception as e:
        logger.error(f"Error enriching log {log_id}: {str(e)}")
        return

    if not getattr(settings, "ENABLE_GEO_LOOKUP", False):
        return

    try:
        GeoIPService.enrich_log(log, force=False)
    except Exception as e:
        logger.error(f"GeoIP enrich failed for log {log_id}: {str(e)}")


def get_flag_emoji(country_code):
    """Convert country code to flag emoji."""
    if country_code == 'LAN':
        return '🏠'
    if country_code == 'XX' or not country_code:
        return '🏴'
    
    # Convert country code to flag emoji
    # A = 🇦 (127462), B = 🇧 (127463), etc.
    return ''.join(chr(127397 + ord(char)) for char in country_code.upper())


@shared_task(name='logs.batch_enrich_logs')
def batch_enrich_logs():
    """
    Batch enrich logs that haven't been geo-enriched yet.
    Respects IP-API.com rate limit (45 req/min).
    """
    unenriched = SecurityLog.objects.filter(geo_enriched=False)[:45]
    
    for log in unenriched:
        enrich_log_with_geoip.delay(log.id)
        time.sleep(1.5)  # Rate limiting


@shared_task(name='logs.periodic_enrich_check')
def periodic_enrich_check():
    """
    Periodic task to check for unenriched logs.
    """
    count = SecurityLog.objects.filter(geo_enriched=False).count()
    
    if count > 0:
        logger.info(f"Found {count} unenriched logs, starting batch enrichment")
        batch_enrich_logs.delay()


def enqueue_geoip_enrichment(log, allow_sync=True):
    if not getattr(settings, "ENABLE_GEO_LOOKUP", False):
        return False
    if not log.src_ip:
        return False
    if log.geo_enriched and log.latitude is not None and log.longitude is not None:
        return False

    try:
        enrich_log_with_geoip.delay(str(log.id))
        return True
    except Exception as exc:
        logger.warning("Failed to queue GeoIP enrichment for log %s: %s", log.id, exc)
        if not allow_sync:
            return False
        try:
            return GeoIPService.enrich_log(log, force=False)
        except Exception as sync_exc:
            logger.warning("GeoIP sync enrich failed for log %s: %s", log.id, sync_exc)
            return False
