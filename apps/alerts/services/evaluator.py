"""
Alert rule evaluation service.
"""
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from apps.logs.models import SecurityLog
from apps.alerts.models import AlertRule, AlertHistory, NotificationChannel
from .notifiers import NotificationService
import logging

logger = logging.getLogger(__name__)


class AlertEvaluator:
    """
    Service for evaluating alert rules against logs.
    """
    
    @staticmethod
    def evaluate_all_rules():
        """
        Evaluate all enabled alert rules.
        
        Returns:
            dict: Summary of evaluation results
        """
        results = {
            'rules_checked': 0,
            'alerts_triggered': 0,
            'notifications_sent': 0,
            'errors': []
        }
        
        # Get all enabled rules
        rules = AlertRule.objects.filter(enabled=True).select_related('organization')
        
        for rule in rules:
            results['rules_checked'] += 1
            
            try:
                triggered = AlertEvaluator.evaluate_rule(rule)
                
                if triggered:
                    results['alerts_triggered'] += 1
                    results['notifications_sent'] += len(rule.notification_channels)
                    
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.id}: {str(e)}")
                results['errors'].append({
                    'rule_id': str(rule.id),
                    'rule_name': rule.name,
                    'error': str(e)
                })
        
        return results
    
    @staticmethod
    def evaluate_rule(rule: AlertRule) -> bool:
        """
        Evaluate a single alert rule.
        
        Args:
            rule: AlertRule instance to evaluate
            
        Returns:
            True if alert was triggered, False otherwise
        """
        # Check if rule is in cooldown
        if rule.is_in_cooldown():
            logger.debug(f"Rule {rule.name} is in cooldown, skipping")
            return False
        
        # Calculate time window
        now = timezone.now()
        time_window_start = now - timedelta(minutes=rule.time_window_minutes)
        
        # Build query based on rule filters
        query = Q(
            organization=rule.organization,
            timestamp__gte=time_window_start,
            timestamp__lte=now
        )
        
        # Apply filters
        if rule.source_type:
            query &= Q(source_type=rule.source_type)
        
        if rule.action:
            query &= Q(action=rule.action)
        
        if rule.severity:
            query &= Q(severity=rule.severity)
        
        if rule.country_code:
            query &= Q(country_code=rule.country_code)
        
        if rule.ip_address:
            query &= Q(src_ip=rule.ip_address)
        
        # Count matching events
        event_count = SecurityLog.objects.filter(query).count()
        
        logger.debug(f"Rule {rule.name}: {event_count} events in last {rule.time_window_minutes} min (threshold: {rule.threshold})")
        
        # Check if threshold is exceeded
        if event_count >= rule.threshold:
            logger.info(f"🚨 Rule {rule.name} triggered! {event_count} events >= {rule.threshold}")
            
            # Get details for alert
            logs = SecurityLog.objects.filter(query).order_by('-timestamp')[:100]
            
            # Aggregate details
            details = AlertEvaluator._aggregate_log_details(logs)
            
            # Determine severity based on how much threshold was exceeded
            if event_count >= rule.threshold * 3:
                severity = 'critical'
            elif event_count >= rule.threshold * 2:
                severity = 'high'
            elif event_count >= rule.threshold * 1.5:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Create alert history
            alert = AlertHistory.objects.create(
                organization=rule.organization,
                alert_rule=rule,
                event_count=event_count,
                severity=severity,
                details=details
            )
            
            # Send notifications
            AlertEvaluator._send_notifications(rule, alert)
            
            # Update rule
            rule.last_triggered = now
            rule.trigger_count += 1
            rule.save()
            
            return True
        
        return False
    
    @staticmethod
    def _aggregate_log_details(logs) -> dict:
        """
        Aggregate log details for alert.
        
        Args:
            logs: QuerySet of SecurityLog instances
            
        Returns:
            dict: Aggregated details
        """
        details = {
            'top_ips': [],
            'top_countries': [],
            'sources': {},
            'actions': {},
        }
        
        # Count IPs
        ip_counts = {}
        country_counts = {}
        source_counts = {}
        action_counts = {}
        
        for log in logs:
            # IPs
            ip = log.src_ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            # Countries
            if log.country_name:
                country = f"{log.country_flag_emoji} {log.country_name}"
                country_counts[country] = country_counts.get(country, 0) + 1
            
            # Sources
            source_counts[log.source_type] = source_counts.get(log.source_type, 0) + 1
            
            # Actions
            action_counts[log.action] = action_counts.get(log.action, 0) + 1
        
        # Top 5 IPs
        details['top_ips'] = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Top 5 Countries
        details['top_countries'] = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Sources
        details['sources'] = source_counts
        
        # Actions
        details['actions'] = action_counts
        
        return details
    
    @staticmethod
    def _send_notifications(rule: AlertRule, alert: AlertHistory):
        """
        Send notifications for triggered alert.
        
        Args:
            rule: AlertRule that triggered
            alert: AlertHistory instance
        """
        notifications_sent = []
        
        for channel_config in rule.notification_channels:
            channel_id = channel_config.get('channel_id')
            
            try:
                channel = NotificationChannel.objects.get(
                    id=channel_id,
                    enabled=True
                )
                
                logger.info(f"Sending notification to {channel.name} ({channel.channel_type})")
                
                success = NotificationService.send_alert_notification(channel, alert)
                
                notifications_sent.append({
                    'channel_id': str(channel.id),
                    'channel_name': channel.name,
                    'channel_type': channel.channel_type,
                    'success': success,
                    'timestamp': timezone.now().isoformat()
                })
                
                if success:
                    # Update channel stats
                    channel.total_notifications += 1
                    channel.last_used = timezone.now()
                    channel.save()
                else:
                    # Update failed count
                    channel.failed_notifications += 1
                    channel.save()
                    
            except NotificationChannel.DoesNotExist:
                logger.error(f"Notification channel {channel_id} not found or disabled")
                notifications_sent.append({
                    'channel_id': channel_id,
                    'success': False,
                    'error': 'Channel not found or disabled',
                    'timestamp': timezone.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Failed to send notification: {str(e)}")
                notifications_sent.append({
                    'channel_id': channel_id,
                    'success': False,
                    'error': str(e),
                    'timestamp': timezone.now().isoformat()
                })
        
        # Update alert with notification results
        alert.notifications_sent = notifications_sent
        alert.save()
