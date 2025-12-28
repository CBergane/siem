"""
API key authentication for ingest endpoints.
Supports both X-API-Key and Authorization: Bearer formats.
"""
from functools import wraps
import hashlib
import hmac
import os
from datetime import timedelta
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from apps.organizations.models import APIKey, Agent

# Defaults keep things small and safe without extra settings.
MAX_BODY_BYTES = getattr(settings, "INGEST_MAX_BODY_BYTES", 1024 * 1024)
TIMESTAMP_SKEW_SECONDS = getattr(settings, "INGEST_TIMESTAMP_SKEW", 300)


def api_key_required(view_func):
    """
    Decorator för att validera API key från header.
    
    Supports:
    - X-API-Key: frc_xxx...
    - Authorization: Bearer frc_xxx...
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        api_key_value = None
        
        # Try X-API-Key header first (forwarder scripts)
        api_key_value = request.headers.get('X-API-Key', '').strip()
        
        # Fall back to Authorization header
        if not api_key_value:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                api_key_value = auth_header.replace('Bearer ', '').strip()
        
        if not api_key_value:
            return JsonResponse({
                'error': 'Missing or invalid Authorization header',
                'details': 'Expected: X-API-Key: frc_xxx OR Authorization: Bearer frc_xxx'
            }, status=401)
        
        # Validera format
        if not api_key_value.startswith('frc_') or len(api_key_value) < 10:
            return JsonResponse({
                'error': 'Invalid API key format'
            }, status=401)
        
        key_prefix = api_key_value[:10]
        
        # Hitta API key
        try:
            api_key = APIKey.objects.select_related('organization').get(
                key_prefix=key_prefix,
                is_active=True
            )
        except APIKey.DoesNotExist:
            return JsonResponse({
                'error': 'Invalid API key'
            }, status=401)
        
        # Verifiera full key
        if not api_key.verify_key(api_key_value):
            return JsonResponse({
                'error': 'Invalid API key'
            }, status=401)
        
        # Kolla om key har expired
        if api_key.expires_at and api_key.expires_at < timezone.now():
            return JsonResponse({
                'error': 'API key has expired'
            }, status=401)
        
        # Kolla om org är aktiv
        if not api_key.organization.is_active:
            return JsonResponse({
                'error': 'Organization is not active'
            }, status=403)
        
        # Uppdatera usage stats
        api_key.last_used_at = timezone.now()
        api_key.total_requests += 1
        api_key.save(update_fields=['last_used_at', 'total_requests'])
        
        # Lägg till på request
        request.api_key = api_key
        request.organization = api_key.organization
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def _get_agent_secret() -> str:
    # Allow override via settings or env to keep config flexible.
    return getattr(settings, "AGENT_HMAC_SECRET", "") or os.environ.get("AGENT_HMAC_SECRET", "")


def agent_signature_required(view_func):
    """
    Validate agent headers + HMAC signature for ingest requests.
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Basic size guard using declared length and actual body.
        try:
            declared_length = int(request.META.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            declared_length = 0
        if declared_length and declared_length > MAX_BODY_BYTES:
            return JsonResponse({"error": "Payload too large"}, status=413)

        body = request.body or b""
        if len(body) > MAX_BODY_BYTES:
            return JsonResponse({"error": "Payload too large"}, status=413)

        agent_id = request.headers.get("X-Agent-Id", "").strip()
        timestamp_header = request.headers.get("X-Timestamp", "").strip()
        signature_header = request.headers.get("X-Signature", "").strip()

        if not agent_id or not timestamp_header or not signature_header:
            return JsonResponse({"error": "Missing authentication headers"}, status=400)

        if not hasattr(request, "organization"):
            return JsonResponse({"error": "Missing organization context"}, status=401)

        agent = Agent.objects.filter(
            agent_id=agent_id,
            organization=request.organization,
        ).first()
        if not agent or not agent.is_active:
            return JsonResponse({"error": "Agent not allowed"}, status=403)

        try:
            timestamp_value = int(timestamp_header)
        except ValueError:
            return JsonResponse({"error": "Invalid timestamp"}, status=400)

        now_ts = int(timezone.now().timestamp())
        if abs(now_ts - timestamp_value) > TIMESTAMP_SKEW_SECONDS:
            return JsonResponse({"error": "Expired timestamp"}, status=401)

        secret = _get_agent_secret()
        if not secret:
            return JsonResponse({"error": "Agent secret not configured"}, status=401)

        expected_signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature_header):
            return JsonResponse({"error": "Invalid signature"}, status=401)

        now = timezone.now()
        if agent.last_seen_at is None or now - agent.last_seen_at > timedelta(minutes=5):
            agent.last_seen_at = now
            agent.save(update_fields=["last_seen_at"])

        return view_func(request, *args, **kwargs)

    return wrapper
