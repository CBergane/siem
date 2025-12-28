"""
Celery tasks for log processing.
"""
from celery import shared_task
from django.utils import timezone
from .models import SecurityLog
import requests
import ipaddress
import logging
import time

logger = logging.getLogger(__name__)


def is_private_ip(ip_address):
    """Check if IP is private (RFC1918)."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except:
        return False


@shared_task(name='logs.enrich_log_with_geoip')
def enrich_log_with_geoip(log_id):
    """
    Enrich log entry with GeoIP data from IP-API.com.
    Free tier: 45 requests per minute.
    """
    try:
        log = SecurityLog.objects.get(id=log_id)
        
        # Skip if already enriched
        if log.geo_enriched:
            return
        
        # Check if private IP
        if is_private_ip(log.src_ip):
            logger.info(f"Private IP detected: {log.src_ip}")
            
            # Set special values for private IPs
            log.country_code = 'LAN'
            log.country_name = 'Private Network'
            log.country_flag_emoji = '🏠'
            log.city = 'Local'
            log.region = 'Private'
            log.isp = 'Internal Network'
            log.geo_enriched = True
            log.save()
            return
        
        # Query IP-API.com for public IPs
        response = requests.get(
            f'http://ip-api.com/json/{log.src_ip}',
            params={'fields': 'status,message,country,countryCode,region,city,isp,org,as,query'},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                # Get country code
                country_code = data.get('countryCode', 'XX')
                
                # Update log - UTAN country_flag_emoji!
                log.country_code = country_code  # Property beräknar automatiskt emoji!
                log.country_name = data.get('country', 'Unknown')
                log.city = data.get('city', '')
                log.region = data.get('region', '')
                log.isp = data.get('isp', '')
                log.asn = data.get('as', '')
                log.geo_enriched = True
                log.geo_enriched_at = timezone.now()  # Glöm inte denna!
                log.save()
                
                logger.info(f"Enriched {log.src_ip} → {data.get('country')}")
            else:
                logger.warning(f"IP-API returned: {data.get('message', 'Unknown error')}")
        else:
            logger.error(f"IP-API request failed: {response.status_code}")
            
    except SecurityLog.DoesNotExist:
        logger.error(f"Log {log_id} not found")
    except Exception as e:
        logger.error(f"Error enriching log {log_id}: {str(e)}")


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
