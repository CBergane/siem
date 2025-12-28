"""
Ingest API views.
"""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .authentication import api_key_required, agent_signature_required
from .parsers.haproxy import HAProxyParser
from .parsers.nginx import NginxParser
from .parsers.crowdsec import CrowdSecParser
from .parsers.fail2ban import Fail2banParser
from apps.logs.models import SecurityLog
from apps.logs.tasks import enrich_log_with_geoip
from apps.logs.services.server_discovery import ServerDiscoveryService
import json
import logging

logger = logging.getLogger(__name__)


def _determine_action_severity(status_code):
    """Helper function to determine action and severity from status code."""
    if status_code >= 500:
        return 'deny', 'high'
    elif status_code == 403:
        return 'deny', 'medium'
    elif status_code == 429:
        return 'rate_limit', 'medium'
    elif status_code >= 400:
        return 'deny', 'low'
    else:
        return 'allow', 'low'


# ============================================================================
# SPECIFIC LOG TYPE ENDPOINTS
# ============================================================================

@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
@agent_signature_required
def ingest_haproxy(request):
    """Ingest endpoint för HAProxy logs."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Extract server name if provided
    server_name = data.get('server_name', 'unknown')
    
    parser = HAProxyParser()
    logs_created = 0
    errors = []
    
    logs = [data['log']] if 'log' in data else data.get('logs', [])
    if not logs:
        return JsonResponse({
            'error': 'Missing "log" or "logs" field'
        }, status=400)
    
    security_logs = []
    for raw_log in logs:
        parsed = parser.parse(raw_log)
        if not parsed:
            errors.append({'log': raw_log[:100], 'error': 'Parse failed'})
            continue
        
        action, severity = _determine_action_severity(parsed.get('status_code', 0))
        
        log_entry = SecurityLog(
            organization=request.organization,
            source_type='haproxy',
            source_host=server_name,
            timestamp=parsed['timestamp'],
            src_ip=parsed['src_ip'],
            src_port=parsed.get('src_port'),
            method=parsed.get('method', ''),
            path=parsed.get('path', ''),
            status_code=parsed.get('status_code'),
            bytes_sent=parsed.get('bytes_sent', 0),
            action=action,
            severity=severity,
            raw_log=parsed['raw_log'],
            metadata=parsed.get('metadata', {})
        )
        security_logs.append(log_entry)
    
    if security_logs:
        created_logs = SecurityLog.objects.bulk_create(security_logs)
        logs_created = len(created_logs)
        
        # AUTO-DISCOVERY: Track server
        if server_name and server_name != 'unknown':
            ServerDiscoveryService.discover_or_update_server(
                organization=request.organization,
                hostname=server_name
            )
        
        # Trigger GeoIP enrichment
        for log in created_logs:
            enrich_log_with_geoip.delay(log.id)
    
    return JsonResponse({
        'success': True,
        'logs_created': logs_created,
        'logs_failed': len(errors),
        'errors': errors[:10],
        'organization': request.organization.name,
        'server': server_name
    }, status=202)


@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
@agent_signature_required
def ingest_nginx(request):
    """Ingest endpoint för Nginx logs."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Extract server name if provided
    server_name = data.get('server_name', 'unknown')
    
    parser = NginxParser()
    logs_created = 0
    errors = []
    
    logs = [data['log']] if 'log' in data else data.get('logs', [])
    if not logs:
        return JsonResponse({
            'error': 'Missing "log" or "logs" field'
        }, status=400)
    
    security_logs = []
    for raw_log in logs:
        parsed = parser.parse(raw_log)
        if not parsed:
            errors.append({'log': raw_log[:100], 'error': 'Parse failed'})
            continue
        
        action, severity = _determine_action_severity(parsed.get('status_code', 0))
        
        security_logs.append(SecurityLog(
            organization=request.organization,
            source_type='nginx',
            source_host=server_name,
            timestamp=parsed['timestamp'],
            src_ip=parsed['src_ip'],
            method=parsed.get('method', ''),
            path=parsed.get('path', ''),
            user_agent=parsed.get('user_agent', ''),
            status_code=parsed.get('status_code'),
            bytes_sent=parsed.get('bytes_sent', 0),
            action=action,
            severity=severity,
            raw_log=parsed['raw_log'],
            metadata=parsed.get('metadata', {})
        ))
    
    if security_logs:
        created_logs = SecurityLog.objects.bulk_create(security_logs)
        logs_created = len(created_logs)
        
        # AUTO-DISCOVERY: Track server
        if server_name and server_name != 'unknown':
            ServerDiscoveryService.discover_or_update_server(
                organization=request.organization,
                hostname=server_name
            )
        
        # Trigger GeoIP enrichment
        for log in created_logs:
            enrich_log_with_geoip.delay(log.id)
    
    return JsonResponse({
        'success': True,
        'logs_created': logs_created,
        'logs_failed': len(errors),
        'errors': errors[:10],
        'organization': request.organization.name,
        'server': server_name
    }, status=202)


@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
@agent_signature_required
def ingest_crowdsec(request):
    """Ingest endpoint för CrowdSec decisions."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Extract server name if provided
    server_name = data.get('server_name', 'unknown')
    
    parser = CrowdSecParser()
    logs_created = 0
    errors = []
    
    # CrowdSec can send single decision or array
    if isinstance(data, dict) and 'decisions' in data:
        decisions = data['decisions']
    elif isinstance(data, list):
        decisions = data
    elif isinstance(data, dict) and any(key in data for key in ['value', 'type', 'scenario']):
        decisions = [data]
    else:
        decisions = []
    
    security_logs = []
    for decision in decisions:
        parsed = parser.parse(decision)
        if not parsed:
            errors.append({'decision': str(decision)[:100], 'error': 'Parse failed'})
            continue
        
        security_logs.append(SecurityLog(
            organization=request.organization,
            source_type='crowdsec',
            source_host=server_name,
            timestamp=parsed['timestamp'],
            src_ip=parsed['src_ip'],
            action=parsed['action'],
            severity=parsed['severity'],
            reason=parsed.get('reason', ''),
            raw_log=parsed['raw_log'],
            metadata=parsed.get('metadata', {})
        ))
    
    if security_logs:
        created_logs = SecurityLog.objects.bulk_create(security_logs)
        logs_created = len(created_logs)
        
        # AUTO-DISCOVERY: Track server
        if server_name and server_name != 'unknown':
            ServerDiscoveryService.discover_or_update_server(
                organization=request.organization,
                hostname=server_name
            )
        
        # Trigger GeoIP enrichment
        for log in created_logs:
            enrich_log_with_geoip.delay(log.id)
    
    return JsonResponse({
        'success': True,
        'logs_created': logs_created,
        'logs_failed': len(errors),
        'errors': errors[:10],
        'organization': request.organization.name,
        'server': server_name
    }, status=202)


@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
@agent_signature_required
def ingest_fail2ban(request):
    """Ingest endpoint för Fail2ban logs."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Extract server name if provided
    server_name = data.get('server_name', 'unknown')
    
    parser = Fail2banParser()
    logs_created = 0
    errors = []
    
    logs = [data['log']] if 'log' in data else data.get('logs', [])
    if not logs:
        return JsonResponse({
            'error': 'Missing "log" or "logs" field'
        }, status=400)
    
    security_logs = []
    for raw_log in logs:
        parsed = parser.parse(raw_log)
        if not parsed:
            errors.append({'log': raw_log[:100], 'error': 'Parse failed'})
            continue
        
        security_logs.append(SecurityLog(
            organization=request.organization,
            source_type='fail2ban',
            source_host=server_name,
            timestamp=parsed['timestamp'],
            src_ip=parsed['src_ip'],
            action=parsed['action'],
            severity=parsed['severity'],
            reason=parsed.get('reason', ''),
            raw_log=parsed['raw_log'],
            metadata=parsed.get('metadata', {})
        ))
    
    if security_logs:
        created_logs = SecurityLog.objects.bulk_create(security_logs)
        logs_created = len(created_logs)
        
        # AUTO-DISCOVERY: Track server
        if server_name and server_name != 'unknown':
            ServerDiscoveryService.discover_or_update_server(
                organization=request.organization,
                hostname=server_name
            )
        
        # Trigger GeoIP enrichment
        for log in created_logs:
            enrich_log_with_geoip.delay(log.id)
    
    return JsonResponse({
        'success': True,
        'logs_created': logs_created,
        'logs_failed': len(errors),
        'errors': errors[:10],
        'organization': request.organization.name,
        'server': server_name
    }, status=202)


# ============================================================================
# GENERIC ENDPOINT
# ============================================================================

@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
@agent_signature_required
def ingest_generic(request):
    """
    Generic ingest endpoint - auto-detects parser based on source_type.
    """
    try:
        organization = request.organization
        api_key = request.api_key
        
        data = json.loads(request.body)
        source_type = data.get('source_type', 'unknown')
        server_name = data.get('server_name', 'unknown')
        
        if api_key.allowed_sources and source_type not in api_key.allowed_sources:
            return JsonResponse({
                'error': f'Source type "{source_type}" not allowed for this API key',
                'allowed_sources': api_key.allowed_sources
            }, status=403)
        
        parser_map = {
            'haproxy': HAProxyParser(),
            'nginx': NginxParser(),
            'crowdsec': CrowdSecParser(),
            'fail2ban': Fail2banParser()
        }
        
        parser = parser_map.get(source_type)
        if not parser:
            return JsonResponse({
                'error': f'Unknown source_type: {source_type}',
                'valid_types': list(parser_map.keys())
            }, status=400)
        
        raw_log = data.get('message', '')
        parsed = parser.parse(raw_log)
        
        if not parsed:
            return JsonResponse({
                'error': 'Failed to parse log',
                'raw_log': raw_log[:100]
            }, status=400)
        
        log_kwargs = {
            'organization': organization,
            'source_type': source_type,
            'source_host': server_name,
            'timestamp': parsed['timestamp'],
            'src_ip': parsed['src_ip'],
            'raw_log': parsed['raw_log'],
            'metadata': parsed.get('metadata', {})
        }
        
        if source_type in ['haproxy', 'nginx']:
            action, severity = _determine_action_severity(parsed.get('status_code', 0))
            log_kwargs.update({
                'action': action,
                'severity': severity,
                'method': parsed.get('method', ''),
                'path': parsed.get('path', ''),
                'status_code': parsed.get('status_code'),
                'bytes_sent': parsed.get('bytes_sent', 0)
            })
        elif source_type in ['fail2ban', 'crowdsec']:
            log_kwargs.update({
                'action': parsed.get('action', 'unknown'),
                'severity': parsed.get('severity', 'medium'),
                'reason': parsed.get('reason', '')
            })
        
        log_entry = SecurityLog.objects.create(**log_kwargs)
        
        # AUTO-DISCOVERY: Track server
        if server_name and server_name != 'unknown':
            ServerDiscoveryService.discover_or_update_server(
                organization=organization,
                hostname=server_name
            )
        
        # Trigger enrichment
        enrich_log_with_geoip.delay(log_entry.id)
        
        logger.info(f"Log ingested via generic endpoint for {organization.name} from {server_name}")
        
        return JsonResponse({
            'status': 'success',
            'log_id': str(log_entry.id),
            'source_type': source_type,
            'server': server_name
        }, status=201)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in generic ingest: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
