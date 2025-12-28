"""
Views for logs app.
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.core.paginator import Paginator
from django.db.models import Q
from .models import SecurityLog, ServerAlias


@login_required
def log_list(request):
    """
    Display paginated list of security logs with filters.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    # Base queryset
    logs = SecurityLog.objects.filter(
        organization_id__in=user_orgs
    ).select_related('organization').order_by('-timestamp')
    
    # Get UNIQUE sources (NO DUPLICATES)
    sources = sorted(list(set(SecurityLog.objects.filter(
        organization_id__in=user_orgs
    ).values_list('source_type', flat=True))))
    
    actions = sorted(list(set(SecurityLog.objects.filter(
        organization_id__in=user_orgs
    ).values_list('action', flat=True))))
    
    # Get servers from ServerAlias (active only) - AS OBJECTS
    servers = ServerAlias.objects.filter(
        organization_id__in=user_orgs,
        is_active=True
    ).order_by('display_name')
    
    severities = ['low', 'medium', 'high', 'critical']
    
    # Get filter parameters
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    source = request.GET.get('source', '')
    action = request.GET.get('action', '')
    severity = request.GET.get('severity', '')
    ip = request.GET.get('ip', '')
    server = request.GET.get('server', '')  # This is original_hostname
    
    # Apply filters
    if date_from:
        logs = logs.filter(timestamp__date__gte=date_from)
    
    if date_to:
        logs = logs.filter(timestamp__date__lte=date_to)
    
    if source:
        logs = logs.filter(source_type=source)
    
    if action:
        logs = logs.filter(action=action)
    
    if severity:
        logs = logs.filter(severity=severity)
    
    if ip:
        logs = logs.filter(src_ip__icontains=ip)
    
    if server:
        logs = logs.filter(source_host=server)
    
    # Count total
    total_count = logs.count()
    
    # Pagination
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Build current_filters for template
    current_filters = {
        'date_from': date_from,
        'date_to': date_to,
        'source': source,
        'action': action,
        'severity': severity,
        'ip': ip,
        'server': server,
    }
    
    context = {
        'page_obj': page_obj,
        'sources': sources,
        'actions': actions,
        'severities': severities,
        'servers': servers,  # Now full ServerAlias objects
        'current_filters': current_filters,
        'total_count': total_count,
    }
    
    return render(request, 'logs/log_list.html', context)
