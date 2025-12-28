"""
Notification service for sending alerts.
"""
import requests
import json
from django.core.mail import send_mail
from django.conf import settings
from .encryption import WebhookEncryption
import logging

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending notifications through various channels."""
    
    @staticmethod
    def send_test_notification(channel):
        """Send a test notification to verify channel works."""
        if channel.channel_type == 'discord':
            return NotificationService._send_discord(
                channel,
                "🧪 Test Alert",
                "This is a test message from Firewall Report Center!",
                color=0x00FF00  # Green
            )
        elif channel.channel_type == 'slack':
            return NotificationService._send_slack(
                channel,
                "�� Test Alert",
                "This is a test message from Firewall Report Center!"
            )
        elif channel.channel_type == 'email':
            return NotificationService._send_email(
                channel,
                "Test Alert - Firewall Report Center",
                "This is a test message from Firewall Report Center!"
            )
        return False
    
    @staticmethod
    def send_alert(channel, alert_data):
        """Send an alert notification."""
        title = alert_data.get('title', 'Security Alert')
        message = alert_data.get('message', '')
        severity = alert_data.get('severity', 'medium')
        details = alert_data.get('details', {})
        
        # Color based on severity
        colors = {
            'low': 0x3B82F6,      # Blue
            'medium': 0xEAB308,   # Yellow
            'high': 0xF97316,     # Orange
            'critical': 0xEF4444   # Red
        }
        color = colors.get(severity, 0x3B82F6)
        
        if channel.channel_type == 'discord':
            return NotificationService._send_discord(
                channel, title, message, color, details
            )
        elif channel.channel_type == 'slack':
            return NotificationService._send_slack(
                channel, title, message
            )
        elif channel.channel_type == 'email':
            return NotificationService._send_email(
                channel, title, message
            )
        return False
    
    @staticmethod
    def _send_discord(channel, title, message, color=0x3B82F6, details=None):
        """Send message to Discord webhook."""
        try:
            webhook_url = WebhookEncryption.decrypt(
                channel.config.get('webhook_url', '')
            )
        except Exception as e:
            logger.error(f"Failed to decrypt Discord webhook: {e}")
            return False
        
        # Build embed fields from details
        fields = []
        if details:
            if 'event_count' in details:
                fields.append({
                    "name": "Events",
                    "value": str(details['event_count']),
                    "inline": True
                })
            if 'time_window' in details:
                fields.append({
                    "name": "Time Window",
                    "value": details['time_window'],
                    "inline": True
                })
            if 'top_ips' in details:
                ips = details['top_ips'][:5]  # Top 5
                ip_list = "\n".join([f"• {ip['ip']} ({ip['count']} events)" for ip in ips])
                fields.append({
                    "name": "Top IPs",
                    "value": ip_list or "N/A",
                    "inline": False
                })
            if 'server' in details:
                fields.append({
                    "name": "Server",
                    "value": details['server'],
                    "inline": True
                })
        
        payload = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": color,
                "fields": fields,
                "timestamp": __import__('datetime').datetime.utcnow().isoformat(),
                "footer": {
                    "text": "Firewall Report Center"
                }
            }]
        }
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            success = response.status_code in [200, 204]
            
            if success:
                logger.info(f"Discord notification sent to {channel.name}")
            else:
                logger.error(f"Discord notification failed: {response.status_code} {response.text[:100]}")
            
            return success
            
        except Exception as e:
            logger.error(f"Discord send error: {e}")
            return False
    
    @staticmethod
    def _send_slack(channel, title, message):
        """Send message to Slack webhook."""
        try:
            webhook_url = WebhookEncryption.decrypt(
                channel.config.get('webhook_url', '')
            )
        except Exception as e:
            logger.error(f"Failed to decrypt Slack webhook: {e}")
            return False
        
        payload = {
            "text": f"*{title}*\n{message}"
        }
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            success = response.status_code == 200
            
            if success:
                logger.info(f"Slack notification sent to {channel.name}")
            else:
                logger.error(f"Slack notification failed: {response.status_code}")
            
            return success
            
        except Exception as e:
            logger.error(f"Slack send error: {e}")
            return False
    
    @staticmethod
    def _send_email(channel, subject, message):
        """Send email notification."""
        recipients = channel.config.get('recipients', [])
        
        if not recipients:
            logger.error("No recipients configured for email channel")
            return False
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=False
            )
            logger.info(f"Email notification sent to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False
