"""
Server management views.
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import ServerAlias, SecurityLog
from .services.server_discovery import ServerDiscoveryService


@login_required
def servers_list(request):
    """
    List all servers with management options.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    # Show active or all?
    show_archived = request.GET.get('show_archived', 'false') == 'true'
    
    # Get servers with stats
    servers_by_org = {}
    
    for org_id in user_orgs:
        from apps.organizations.models import Organization
        org = Organization.objects.get(id=org_id)
        
        stats = ServerDiscoveryService.get_server_stats(org, include_inactive=show_archived)
        
        servers_by_org[org.id] = {
            'organization': org,
            'servers': stats
        }
    
    context = {
        'servers_by_org': servers_by_org,
        'show_archived': show_archived,
    }
    
    return render(request, 'logs/servers_list.html', context)


@login_required
@require_http_methods(["POST"])
def update_server(request, server_id):
    """
    Update server display name and details.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    server = get_object_or_404(
        ServerAlias,
        id=server_id,
        organization_id__in=user_orgs
    )
    
    # Update fields
    server.display_name = request.POST.get('display_name', server.display_name)
    server.description = request.POST.get('description', '')
    server.server_type = request.POST.get('server_type', '')
    server.environment = request.POST.get('environment', 'production')
    server.save()
    
    messages.success(request, f"Updated server: {server.display_name}")
    return redirect('logs:servers_list')


@login_required
@require_http_methods(["POST"])
def toggle_server(request, server_id):
    """
    Enable/disable (archive) server tracking.
    """
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    server = get_object_or_404(
        ServerAlias,
        id=server_id,
        organization_id__in=user_orgs
    )
    
    server.is_active = not server.is_active
    server.save()
    
    status = "activated" if server.is_active else "archived"
    messages.success(request, f"Server {server.display_name} {status}.")
    
    return redirect('logs:servers_list')


@login_required
@require_http_methods(["POST"])
def delete_server(request, server_id):
    """
    Delete server alias (keeps logs).
    """
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    server = get_object_or_404(
        ServerAlias,
        id=server_id,
        organization_id__in=user_orgs
    )
    
    # Count logs
    log_count = SecurityLog.objects.filter(
        organization=server.organization,
        source_host=server.original_hostname
    ).count()
    
    server_name = server.display_name
    server.delete()
    
    messages.warning(
        request, 
        f"Deleted server: {server_name}. {log_count} logs still exist with hostname '{server.original_hostname}'."
    )
    
    return redirect('logs:servers_list')


@login_required
@require_http_methods(["POST"])
def migrate_server(request, server_id):
    """
    Migrate logs from one server hostname to another.
    """
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    server = get_object_or_404(
        ServerAlias,
        id=server_id,
        organization_id__in=user_orgs
    )
    
    new_hostname = request.POST.get('new_hostname', '').strip()
    
    if not new_hostname:
        messages.error(request, "New hostname is required")
        return redirect('logs:servers_list')
    
    # Migrate logs
    old_hostname = server.original_hostname
    logs = SecurityLog.objects.filter(
        organization=server.organization,
        source_host=old_hostname
    )
    
    count = logs.count()
    logs.update(source_host=new_hostname)
    
    # Update or create target server alias
    target_server, created = ServerAlias.objects.get_or_create(
        organization=server.organization,
        original_hostname=new_hostname,
        defaults={
            'display_name': server.display_name,
            'description': f"Migrated from {old_hostname}",
            'server_type': server.server_type,
            'environment': server.environment,
            'is_active': server.is_active,
        }
    )
    
    # Delete old alias
    server.delete()
    
    messages.success(
        request, 
        f"✅ Migrated {count} logs from '{old_hostname}' to '{new_hostname}'"
    )
    
    return redirect('logs:servers_list')
