"""
Security logs models.
"""
from django.db import models
from apps.core.models import BaseModel


class SecurityLog(BaseModel):
    """
    Security log entry from various sources.
    """
    
    # Organization (multi-tenancy)
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='security_logs'
    )
    
    # Source Information
    source_type = models.CharField(
        max_length=50,
        choices=[
            ('haproxy', 'HAProxy'),
            ('nginx', 'Nginx'),
            ('crowdsec', 'CrowdSec'),
            ('fail2ban', 'Fail2ban'),
        ],
        db_index=True
    )
    source_host = models.CharField(max_length=255)
    
    # Timestamp
    timestamp = models.DateTimeField(db_index=True)
    
    # Network Information
    src_ip = models.GenericIPAddressField(db_index=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    
    # GeoIP Information (NEW!)
    country_code = models.CharField(max_length=2, blank=True, db_index=True, help_text="ISO 3166-1 alpha-2 country code")
    country_name = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    timezone = models.CharField(max_length=50, blank=True)
    
    # ISP/ASN Information (NEW!)
    asn = models.CharField(max_length=20, blank=True, db_index=True, help_text="Autonomous System Number")
    isp = models.CharField(max_length=255, blank=True, help_text="Internet Service Provider")
    org = models.CharField(max_length=255, blank=True, help_text="Organization name")
    
    # GeoIP Status (NEW!)
    geo_enriched = models.BooleanField(default=False, db_index=True)
    geo_enriched_at = models.DateTimeField(null=True, blank=True)
    
    # HTTP Information
    method = models.CharField(max_length=10, blank=True)
    path = models.CharField(max_length=2048, blank=True)
    status_code = models.IntegerField(null=True, blank=True, db_index=True)
    bytes_sent = models.BigIntegerField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    
    # Action taken
    action = models.CharField(
        max_length=20,
        choices=[
            ('allow', 'Allow'),
            ('deny', 'Deny'),
            ('ban', 'Ban'),
            ('rate_limit', 'Rate Limit'),
            ('challenge', 'Challenge'),
        ],
        db_index=True
    )
    
    # Severity
    severity = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        db_index=True
    )
    
    # Additional Info
    reason = models.CharField(max_length=255, blank=True)
    
    # Raw log and metadata
    raw_log = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = 'Security Log'
        verbose_name_plural = 'Security Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', 'timestamp']),
            models.Index(fields=['src_ip', 'timestamp']),
            models.Index(fields=['action', 'severity']),
            models.Index(fields=['source_type', 'timestamp']),
            models.Index(fields=['country_code', 'timestamp']),
            models.Index(fields=['geo_enriched']),
        ]
    
    def __str__(self):
        return f"{self.source_type} - {self.src_ip} - {self.action} - {self.timestamp}"
    
    @property
    def country_flag_emoji(self):
        """Get country flag emoji from country code."""
        if not self.country_code:
            return "🌍"
        
        # Convert country code to flag emoji
        # A = 0x1F1E6, B = 0x1F1E7, etc.
        code = self.country_code.upper()
        if len(code) != 2:
            return "🌍"
        
        return chr(ord(code[0]) + 0x1F1A5) + chr(ord(code[1]) + 0x1F1A5)

# Import ServerAlias model
from .models_server_alias import ServerAlias
