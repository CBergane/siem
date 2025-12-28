"""
GeoIP lookup service using IP-API.com
"""
import requests
import logging
from typing import Dict, Optional
from django.utils import timezone  # ÄNDRAT: Använd Django timezone

logger = logging.getLogger(__name__)


class GeoIPService:
    """
    Service for looking up IP geolocation information.
    
    Uses IP-API.com free tier:
    - 45 requests per minute
    - No API key required
    - Fields: country, city, lat, lon, timezone, isp, org, as
    """
    
    BASE_URL = "http://ip-api.com/json/{ip}"
    FIELDS = "status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as"
    
    # Cache for private/reserved IPs
    PRIVATE_IP_RESULT = {
        'country_code': 'XX',
        'country_name': 'Private Network',
        'city': 'Internal',
        'region': '',
        'latitude': None,
        'longitude': None,
        'timezone': '',
        'asn': '',
        'isp': 'Private Network',
        'org': 'Private Network',
    }
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """Check if IP is private/reserved."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return False
    
    @classmethod
    def lookup(cls, ip: str, timeout: int = 5) -> Optional[Dict]:
        """
        Lookup IP geolocation information.
        
        Args:
            ip: IP address to lookup
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with geo information or None if lookup fails
        """
        # Check if private IP
        if cls.is_private_ip(ip):
            logger.debug(f"IP {ip} is private/reserved, skipping lookup")
            return cls.PRIVATE_IP_RESULT
        
        try:
            url = cls.BASE_URL.format(ip=ip)
            params = {'fields': cls.FIELDS}
            
            response = requests.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Check if lookup was successful
            if data.get('status') != 'success':
                logger.warning(f"GeoIP lookup failed for {ip}: {data.get('message', 'Unknown error')}")
                return None
            
            # Parse response
            result = {
                'country_code': data.get('countryCode', ''),
                'country_name': data.get('country', ''),
                'city': data.get('city', ''),
                'region': data.get('regionName', ''),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone', ''),
                'asn': data.get('as', '').split()[0] if data.get('as') else '',  # Extract AS number
                'isp': data.get('isp', ''),
                'org': data.get('org', ''),
            }
            
            logger.info(f"GeoIP lookup successful for {ip}: {result['country_code']} - {result['city']}")
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"GeoIP lookup timeout for {ip}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"GeoIP lookup error for {ip}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in GeoIP lookup for {ip}: {str(e)}")
            return None
    
    @classmethod
    def enrich_log(cls, log, force: bool = False) -> bool:
        """
        Enrich a SecurityLog instance with GeoIP data.

        force=True gör att vi kör lookup även om geo_enriched redan är True
        (bra för att reparera gamla rader som saknar lat/lon).
        """
        if not log.src_ip:
            logger.debug(f"Log {log.id} has no source IP, skipping enrichment")
            return False

        # Skip only if we ALREADY have coords (annars får kartan aldrig markörer)
        if not force and log.geo_enriched and log.latitude is not None and log.longitude is not None:
            logger.debug(f"Log {log.id} already enriched with coords, skipping")
            return True

        geo_data = cls.lookup(log.src_ip)

        if not geo_data:
            logger.warning(f"Failed to enrich log {log.id} with GeoIP data")
            return False

        # Sätt alltid fälten vi har
        log.country_code = (geo_data.get("country_code") or "").upper()
        log.country_name = geo_data.get("country_name", "") or ""
        log.city = geo_data.get("city", "") or ""
        log.region = geo_data.get("region", "") or ""
        log.timezone = geo_data.get("timezone", "") or ""
        log.isp = geo_data.get("isp", "") or ""
        log.org = geo_data.get("org", "") or ""
        log.asn = geo_data.get("asn", "") or ""

        # Plocka coords
        lat = geo_data.get("latitude")
        lon = geo_data.get("longitude")
        log.latitude = lat
        log.longitude = lon

        # Bara "geo_enriched=True" när coords faktiskt finns
        has_coords = (lat is not None and lon is not None)
        log.geo_enriched = has_coords
        log.geo_enriched_at = timezone.now() if has_coords else None

        log.save(update_fields=[
            "country_code", "country_name", "city", "region",
            "latitude", "longitude", "timezone", "asn", "isp", "org",
            "geo_enriched", "geo_enriched_at",
        ])

        logger.info(
            f"GeoIP enrich log {log.id}: coords={'yes' if has_coords else 'no'} "
            f"cc={log.country_code} city={log.city}"
        )
        return has_coords
