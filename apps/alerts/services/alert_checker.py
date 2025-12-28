"""
Alert checker service - evaluates rules against logs.
"""
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from apps.alerts.models import AlertRule, AlertHistory, NotificationChannel
from apps.logs.models import SecurityLog
from .notifiers import NotificationService
import logging

logger = logging.getLogger(__name__)


class AlertChecker:
    """Check alert rules and trigger notifications."""
    
    @staticmethod
    def check_all_rules():
        """
        Check all enabled alert rules across all organizations.
        Called periodically by Celery beat.
        """
        rules = AlertRule.objects.filter(enabled=True)
        
        logger.info(f"Checking {rules.count()} alert rules...")
        
        triggered_count = 0
        for rule in rules:
            if AlertChecker.check_rule(rule):
                triggered_count += 1
        
        logger.info(f"Triggered {triggered_count} alerts")
        return triggered_count
    
    @staticmethod
    def check_rule(rule):
        """
        Check a single alert rule.
        Returns True if alert was triggered.
        """
        # Skip if in cooldown
        if rule.is_in_cooldown():
            logger.debug(f"Rule {rule.name} is in cooldown")
            return False
        
        # Build query based on rule filters
        time_threshold = timezone.now() - timedelta(minutes=rule.time_window_minutes)
        
        logs = SecurityLog.objects.filter(
            organization=rule.organization,
            timestamp__gte=time_threshold
        )
        
        # Apply filters
        if rule.source_type:
            logs = logs.filter(source_type=rule.source_type)
        if rule.action:
            logs = logs.filter(action=rule.action)
        if rule.severity:
            logs = logs.filter(severity=rule.severity)
        if rule.country_code:
            logs = logs.filter(country_code=rule.country_code)
        if rule.ip_address:
            logs = logs.filter(src_ip=rule.ip_address)
        
        # Count events
        event_count = logs.count()
        
        # Check if threshold exceeded
        if event_count < rule.threshold:
            return False
        
        logger.info(f"Alert triggered: {rule.name} ({event_count} events)")
        
        # Gather details
        top_ips = logs.values('src_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        top_ips_list = [
            {'ip': item['src_ip'], 'count': item['count']}
            for item in top_ips
        ]
        
        # Get affected servers
        servers = list(logs.values_list('source_host', flat=True).distinct())
        
        details = {
            'event_count': event_count,
            'time_window': f"{rule.time_window_minutes} minutes",
            'top_ips': top_ips_list,
            'servers': servers,
            'filters': {
                'source_type': rule.source_type or 'All',
                'action': rule.action or 'All',
                'severity': rule.severity or 'All',
            }
        }
        
        # Determine severity for alert history
        if event_count >= rule.threshold * 3:
            alert_severity = 'critical'
        elif event_count >= rule.threshold * 2:
            alert_severity = 'high'
        elif event_count >= rule.threshold * 1.5:
            alert_severity = 'medium'
        else:
            alert_severity = 'low'
        
        # Create alert history
        alert_history = AlertHistory.objects.create(
            organization=rule.organization,
            alert_rule=rule,
            event_count=event_count,
            details=details,
            severity=alert_severity,
            notifications_sent=[]
        )
        
        # Send notifications
        notifications_sent = AlertChecker._send_notifications(
            rule, alert_history, details
        )
        
        # Update alert history with notification results
        alert_history.notifications_sent = notifications_sent
        alert_history.save()
        
        # Update rule
        rule.last_triggered = timezone.now()
        rule.trigger_count += 1
        rule.save()
        
        return True
    
    @staticmethod
    def _send_notifications(rule, alert_history, details):
        """Send notifications for triggered alert."""
        notifications_sent = []
        
        if not rule.notification_channels:
            logger.warning(f"No notification channels for rule: {rule.name}")
            return notifications_sent
        
        # Build alert message
        title = f"🚨 {rule.name}"
        
        message_parts = []
        if rule.description:
            message_parts.append(rule.description)
        
        message_parts.append(f"\n**{details['event_count']} events** detected in {details['time_window']}")
        
        # Add filter info
        filters = details['filters']
        filter_info = []
        if filters['source_type'] != 'All':
            filter_info.append(f"Source: {filters['source_type']}")
        if filters['action'] != 'All':
            filter_info.append(f"Action: {filters['action']}")
        if filters['severity'] != 'All':
            filter_info.append(f"Severity: {filters['severity']}")
        
        if filter_info:
            message_parts.append(f"\n**Filters:** {', '.join(filter_info)}")
        
        message = "\n".join(message_parts)
        
        # Prepare alert data
        alert_data = {
            'title': title,
            'message': message,
            'severity': alert_history.severity,
            'details': details
        }
        
        # Send to each channel
        for channel_config in rule.notification_channels:
            channel_id = channel_config.get('channel_id')
            
            try:
                channel = NotificationChannel.objects.get(
                    id=channel_id,
                    enabled=True
                )
                
                success = NotificationService.send_alert(channel, alert_data)
                
                notifications_sent.append({
                    'channel_id': channel_id,
                    'channel_name': channel.name,
                    'channel_type': channel.channel_type,
                    'success': success,
                    'timestamp': timezone.now().isoformat()
                })
                
                # Update channel stats
                if success:
                    channel.last_used = timezone.now()
                    channel.total_notifications += 1
                else:
                    channel.failed_notifications += 1
                channel.save()
                
            except NotificationChannel.DoesNotExist:
                logger.error(f"Notification channel {channel_id} not found")
                notifications_sent.append({
                    'channel_id': channel_id,
                    'success': False,
                    'error': 'Channel not found',
                    'timestamp': timezone.now().isoformat()
                })
        
        return notifications_sent
