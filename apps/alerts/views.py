"""
Views for alerts app.
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db.models import Q
from .models import NotificationChannel, AlertRule, AlertHistory
from .services.encryption import WebhookEncryption
from .services.validators import WebhookValidator
import json
from apps.logs.models import SecurityLog


# ============================================================================
# INTEGRATIONS VIEWS
# ============================================================================

@login_required
def integrations_list(request):
    """
    List all notification channels for user's organizations.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    # Get notification channels
    channels = NotificationChannel.objects.filter(
        organization_id__in=user_orgs
    ).select_related('organization', 'created_by')
    
    # Group by organization
    channels_by_org = {}
    for channel in channels:
        org_id = channel.organization.id
        if org_id not in channels_by_org:
            channels_by_org[org_id] = {
                'organization': channel.organization,
                'channels': []
            }
        
        # Mask webhook URL for display
        if channel.channel_type in ['slack', 'discord', 'webhook']:
            webhook_url = channel.config.get('webhook_url', '')
            if webhook_url:
                # Decrypt and mask
                try:
                    decrypted = WebhookEncryption.decrypt(webhook_url)
                    channel.masked_url = WebhookEncryption.mask_url(decrypted, show_chars=12)
                except:
                    channel.masked_url = "***"
        
        channels_by_org[org_id]['channels'].append(channel)
    
    context = {
        'channels_by_org': channels_by_org,
    }
    
    return render(request, 'alerts/integrations_list.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def add_channel(request, org_id):
    """
    Add new notification channel.
    """
    # Verify user has access to organization
    membership = request.user.organization_memberships.filter(
        organization_id=org_id,
        is_active=True
    ).first()
    
    if not membership:
        messages.error(request, "You don't have access to this organization.")
        return redirect('alerts:integrations_list')
    
    organization = membership.organization
    
    if request.method == 'POST':
        channel_type = request.POST.get('channel_type')
        name = request.POST.get('name')
        
        # Validate based on channel type
        if channel_type == 'email':
            # Email configuration
            recipients = request.POST.get('recipients', '').split(',')
            recipients = [email.strip() for email in recipients if email.strip()]
            
            # Validate emails
            is_valid, error = WebhookValidator.validate_email_list(recipients)
            if not is_valid:
                messages.error(request, f"Invalid email: {error}")
                return redirect('alerts:add_channel', org_id=org_id)
            
            config = {
                'recipients': recipients
            }
        
        elif channel_type in ['slack', 'discord', 'webhook']:
            # Webhook configuration
            webhook_url = request.POST.get('webhook_url', '').strip()
            
            # Validate webhook URL
            is_valid, error = WebhookValidator.validate_url(webhook_url, channel_type)
            if not is_valid:
                messages.error(request, f"Invalid webhook URL: {error}")
                return redirect('alerts:add_channel', org_id=org_id)
            
            # Encrypt webhook URL
            encrypted_url = WebhookEncryption.encrypt(webhook_url)
            
            config = {
                'webhook_url': encrypted_url
            }
        
        else:
            messages.error(request, "Invalid channel type.")
            return redirect('alerts:add_channel', org_id=org_id)
        
        # Create channel
        channel = NotificationChannel.objects.create(
            organization=organization,
            channel_type=channel_type,
            name=name,
            config=config,
            created_by=request.user,
            enabled=True,
            verified=False
        )
        
        messages.success(request, f"Added {channel.get_channel_type_display()} channel: {name}")
        return redirect('alerts:integrations_list')
    
    context = {
        'organization': organization,
    }
    
    return render(request, 'alerts/add_channel.html', context)


@login_required
@require_http_methods(["POST"])
def delete_channel(request, channel_id):
    """
    Delete notification channel.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    channel = get_object_or_404(
        NotificationChannel,
        id=channel_id,
        organization_id__in=user_orgs
    )
    
    channel_name = channel.name
    channel.delete()
    
    messages.success(request, f"Deleted channel: {channel_name}")
    return redirect('alerts:integrations_list')


@login_required
@require_http_methods(["POST"])
def test_channel(request, channel_id):
    """
    Test notification channel by sending test message.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    channel = get_object_or_404(
        NotificationChannel,
        id=channel_id,
        organization_id__in=user_orgs
    )
    
    # Import notifier service
    try:
        from .services.notifiers import NotificationService
        
        success = NotificationService.send_test_notification(channel)
        
        if success:
            channel.verified = True
            channel.save()
            messages.success(request, f"Test successful! Channel {channel.name} is working.")
        else:
            messages.error(request, f"Test failed for channel {channel.name}. Please check configuration.")
    
    except Exception as e:
        messages.error(request, f"Test failed: {str(e)}")
    
    return redirect('alerts:integrations_list')


@login_required
@require_http_methods(["POST"])
def toggle_channel(request, channel_id):
    """
    Enable/disable notification channel.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    channel = get_object_or_404(
        NotificationChannel,
        id=channel_id,
        organization_id__in=user_orgs
    )
    
    channel.enabled = not channel.enabled
    channel.save()
    
    status = "enabled" if channel.enabled else "disabled"
    messages.success(request, f"Channel {channel.name} {status}.")
    
    return redirect('alerts:integrations_list')


# ============================================================================
# ALERT RULES VIEWS
# ============================================================================

@login_required
def alert_rules_list(request):
    """
    List all alert rules for user's organizations.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    # Get alert rules
    rules = AlertRule.objects.filter(
        organization_id__in=user_orgs
    ).select_related('organization', 'created_by')
    
    # Get recent alert history
    recent_alerts = AlertHistory.objects.filter(
        organization_id__in=user_orgs
    ).select_related('organization', 'alert_rule').order_by('-triggered_at')[:10]
    
    context = {
        'rules': rules,
        'recent_alerts': recent_alerts,
    }
    
    return render(request, 'alerts/alert_rules_list.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def create_alert_rule(request, org_id):
    """
    Create new alert rule.
    """
    # Verify user has access to organization
    membership = request.user.organization_memberships.filter(
        organization_id=org_id,
        is_active=True
    ).first()
    
    if not membership:
        messages.error(request, "You don't have access to this organization.")
        return redirect('alerts:alert_rules_list')
    
    organization = membership.organization
    
    # Get available notification channels
    channels = NotificationChannel.objects.filter(
        organization=organization,
        enabled=True
    )
    
    if request.method == 'POST':
        # Basic info
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        
        # Condition
        condition_type = request.POST.get('condition_type', 'count')
        threshold = int(request.POST.get('threshold', 10))
        time_window_minutes = int(request.POST.get('time_window_minutes', 5))
        
        # Filters
        source_type = request.POST.get('source_type', '')
        action = request.POST.get('action', '')
        severity = request.POST.get('severity', '')
        country_code = request.POST.get('country_code', '')
        ip_address = request.POST.get('ip_address', '') or None
        
        # Notifications
        selected_channels = request.POST.getlist('notification_channels')
        notification_channels = []
        
        for channel_id in selected_channels:
            try:
                channel = NotificationChannel.objects.get(
                    id=channel_id,
                    organization=organization
                )
                notification_channels.append({
                    'channel_id': str(channel.id),
                    'channel_type': channel.channel_type,
                    'channel_name': channel.name
                })
            except NotificationChannel.DoesNotExist:
                pass
        
        # Cooldown
        cooldown_minutes = int(request.POST.get('cooldown_minutes', 15))
        
        # Create rule
        rule = AlertRule.objects.create(
            organization=organization,
            name=name,
            description=description,
            enabled=True,
            condition_type=condition_type,
            source_type=source_type,
            action=action,
            severity=severity,
            country_code=country_code,
            ip_address=ip_address,
            threshold=threshold,
            time_window_minutes=time_window_minutes,
            notification_channels=notification_channels,
            cooldown_minutes=cooldown_minutes,
            created_by=request.user
        )
        
        messages.success(request, f"Created alert rule: {name}")
        return redirect('alerts:alert_rules_list')
    
    source_types = SecurityLog.objects.filter(
        organization_id=org_id
    ).values_list('source_type', flat=True).distinct().order_by('source_type')

    # Actions - distinct and ordered
    actions = SecurityLog.objects.filter(
        organization_id=org_id
    ).values_list('action', flat=True).distinct().order_by('action')

    # Severities - distinct and ordered
    severities = SecurityLog.objects.filter(
        organization_id=org_id
    ).values_list('severity', flat=True).distinct().order_by('severity')

    # Countries - distinct, ordered, exclude empty
    countries = SecurityLog.objects.filter(
        organization_id=org_id,
        geo_enriched=True
    ).exclude(
        country_code__in=['', 'XX']
    ).values('country_code', 'country_name').distinct().order_by('country_name')
     
    context = {
        'organization': organization,
        'channels': channels,
        'source_types': source_types,
        'actions': actions,
        'severities': severities,
        'countries': countries,
    }
    
    return render(request, 'alerts/create_alert_rule.html', context)


@login_required
@require_http_methods(["POST"])
def delete_alert_rule(request, rule_id):
    """
    Delete alert rule.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    rule = get_object_or_404(
        AlertRule,
        id=rule_id,
        organization_id__in=user_orgs
    )
    
    rule_name = rule.name
    rule.delete()
    
    messages.success(request, f"Deleted alert rule: {rule_name}")
    return redirect('alerts:alert_rules_list')


@login_required
@require_http_methods(["POST"])
def toggle_alert_rule(request, rule_id):
    """
    Enable/disable alert rule.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    rule = get_object_or_404(
        AlertRule,
        id=rule_id,
        organization_id__in=user_orgs
    )
    
    rule.enabled = not rule.enabled
    rule.save()
    
    status = "enabled" if rule.enabled else "disabled"
    messages.success(request, f"Alert rule {rule.name} {status}.")
    
    return redirect('alerts:alert_rules_list')


@login_required
def alert_history(request):
    """
    View alert history.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    # Get alert history
    alerts = AlertHistory.objects.filter(
        organization_id__in=user_orgs
    ).select_related('organization', 'alert_rule', 'acknowledged_by').order_by('-triggered_at')
    
    # Filters
    rule_id = request.GET.get('rule')
    severity = request.GET.get('severity')
    acknowledged = request.GET.get('acknowledged')
    
    if rule_id:
        alerts = alerts.filter(alert_rule_id=rule_id)
    if severity:
        alerts = alerts.filter(severity=severity)
    if acknowledged == 'yes':
        alerts = alerts.filter(acknowledged=True)
    elif acknowledged == 'no':
        alerts = alerts.filter(acknowledged=False)
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(alerts, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get available rules for filter
    rules = AlertRule.objects.filter(organization_id__in=user_orgs)
    
    context = {
        'page_obj': page_obj,
        'rules': rules,
    }
    
    return render(request, 'alerts/alert_history.html', context)


@login_required
@require_http_methods(["POST"])
def acknowledge_alert(request, alert_id):
    """
    Acknowledge an alert.
    """
    # Get user's organizations
    user_orgs = request.user.organization_memberships.filter(
        is_active=True
    ).values_list('organization_id', flat=True)
    
    alert = get_object_or_404(
        AlertHistory,
        id=alert_id,
        organization_id__in=user_orgs
    )
    
    from django.utils import timezone
    
    alert.acknowledged = True
    alert.acknowledged_by = request.user
    alert.acknowledged_at = timezone.now()
    alert.save()
    
    messages.success(request, "Alert acknowledged.")
    return redirect('alerts:alert_history')
