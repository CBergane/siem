"""
Alert system models.
"""
from django.db import models
from apps.core.models import BaseModel


class AlertRule(BaseModel):
    """
    Alert rule configuration.
    Each rule belongs to an organization and defines conditions for triggering alerts.
    """
    
    # Multi-tenancy
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='alert_rules'
    )
    
    # Rule identification
    name = models.CharField(max_length=255, help_text="Alert rule name")
    description = models.TextField(blank=True, help_text="Description of what this rule detects")
    
    # Enabled/disabled
    enabled = models.BooleanField(default=True, db_index=True)
    
    # Condition Type
    CONDITION_TYPES = [
        ('count', 'Event Count'),           # X events in Y minutes
        ('threshold', 'Threshold'),         # Value > threshold
        ('spike', 'Spike Detection'),       # Sudden increase
        ('pattern', 'Pattern Match'),       # Specific pattern
    ]
    condition_type = models.CharField(
        max_length=20,
        choices=CONDITION_TYPES,
        default='count'
    )
    
    # Filters (what logs to check)
    source_type = models.CharField(
        max_length=50,
        blank=True,
        help_text="Filter by source type (empty = all sources)"
    )
    action = models.CharField(
        max_length=20,
        blank=True,
        help_text="Filter by action (empty = all actions)"
    )
    severity = models.CharField(
        max_length=20,
        blank=True,
        help_text="Filter by severity (empty = all severities)"
    )
    country_code = models.CharField(
        max_length=2,
        blank=True,
        help_text="Filter by country (empty = all countries)"
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Filter by specific IP address"
    )
    
    # Condition parameters
    threshold = models.IntegerField(
        default=10,
        help_text="Number of events to trigger alert"
    )
    time_window_minutes = models.IntegerField(
        default=5,
        help_text="Time window in minutes"
    )
    
    # Notification channels (encrypted JSON)
    notification_channels = models.JSONField(
        default=list,
        help_text="List of notification channels with encrypted webhooks"
    )
    
    # Cooldown to prevent spam
    cooldown_minutes = models.IntegerField(
        default=15,
        help_text="Minimum minutes between alerts"
    )
    
    # Tracking
    last_triggered = models.DateTimeField(null=True, blank=True)
    trigger_count = models.IntegerField(default=0)
    
    # Ownership
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_alert_rules'
    )
    
    class Meta:
        verbose_name = 'Alert Rule'
        verbose_name_plural = 'Alert Rules'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'enabled']),
            models.Index(fields=['organization', 'last_triggered']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.organization.name})"
    
    def is_in_cooldown(self):
        """Check if rule is in cooldown period."""
        if not self.last_triggered:
            return False
        
        from django.utils import timezone
        from datetime import timedelta
        
        cooldown_until = self.last_triggered + timedelta(minutes=self.cooldown_minutes)
        return timezone.now() < cooldown_until


class AlertHistory(BaseModel):
    """
    History of triggered alerts.
    """
    
    # Multi-tenancy
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='alert_history'
    )
    
    # Alert rule that triggered
    alert_rule = models.ForeignKey(
        AlertRule,
        on_delete=models.CASCADE,
        related_name='history'
    )
    
    # When it triggered
    triggered_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    # Event details
    event_count = models.IntegerField(help_text="Number of events that triggered the alert")
    
    # Details about what triggered it
    details = models.JSONField(
        default=dict,
        help_text="Details about the alert (IPs, countries, etc)"
    )
    
    # Notification status
    notifications_sent = models.JSONField(
        default=list,
        help_text="List of notifications sent (channel, status, timestamp)"
    )
    
    # Severity at time of trigger
    severity = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        default='medium'
    )
    
    # Acknowledged
    acknowledged = models.BooleanField(default=False, db_index=True)
    acknowledged_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_alerts'
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'Alert History'
        verbose_name_plural = 'Alert Histories'
        ordering = ['-triggered_at']
        indexes = [
            models.Index(fields=['organization', 'triggered_at']),
            models.Index(fields=['organization', 'acknowledged']),
            models.Index(fields=['alert_rule', 'triggered_at']),
        ]
    
    def __str__(self):
        return f"{self.alert_rule.name} - {self.triggered_at}"


class NotificationChannel(BaseModel):
    """
    Notification channel configuration per organization.
    Webhooks are stored encrypted.
    """
    
    # Multi-tenancy
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='notification_channels'
    )
    
    # Channel type
    CHANNEL_TYPES = [
        ('email', 'Email'),
        ('slack', 'Slack'),
        ('discord', 'Discord'),
        ('webhook', 'Generic Webhook'),
    ]
    channel_type = models.CharField(
        max_length=20,
        choices=CHANNEL_TYPES
    )
    
    # Channel name/label
    name = models.CharField(
        max_length=255,
        help_text="Friendly name for this channel"
    )
    
    # Configuration (encrypted for webhooks)
    config = models.JSONField(
        default=dict,
        help_text="Channel configuration (encrypted webhooks, email lists, etc)"
    )
    
    # Status
    enabled = models.BooleanField(default=True, db_index=True)
    verified = models.BooleanField(
        default=False,
        help_text="Has this channel been tested/verified?"
    )
    
    # Tracking
    last_used = models.DateTimeField(null=True, blank=True)
    total_notifications = models.IntegerField(default=0)
    failed_notifications = models.IntegerField(default=0)
    
    # Ownership
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_notification_channels'
    )
    
    class Meta:
        verbose_name = 'Notification Channel'
        verbose_name_plural = 'Notification Channels'
        ordering = ['channel_type', 'name']
        indexes = [
            models.Index(fields=['organization', 'enabled']),
            models.Index(fields=['organization', 'channel_type']),
        ]
        unique_together = [['organization', 'channel_type', 'name']]
    
    def __str__(self):
        return f"{self.get_channel_type_display()} - {self.name} ({self.organization.name})"
