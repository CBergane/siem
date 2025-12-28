"""
Organization models for multi-tenancy.
"""
from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from apps.core.models import BaseModel
from cryptography.fernet import Fernet
import secrets
import base64
import hashlib


class Organization(BaseModel):
    """Multi-tenant organization model."""
    
    name = models.CharField(max_length=255)
    slug = models.SlugField(
        max_length=100,
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^[a-z0-9-]+$',
                message='Slug can only contain lowercase letters, numbers, and hyphens.'
            )
        ]
    )
    
    # Subscription & Limits
    is_active = models.BooleanField(default=True)
    max_users = models.IntegerField(default=5)
    max_api_keys = models.IntegerField(default=3)
    max_logs_per_month = models.IntegerField(default=1000000)
    
    # Billing
    subscription_tier = models.CharField(
        max_length=20,
        choices=[
            ('free', 'Free'),
            ('starter', 'Starter'),
            ('professional', 'Professional'),
            ('enterprise', 'Enterprise'),
        ],
        default='free'
    )
    subscription_ends_at = models.DateTimeField(null=True, blank=True)
    
    # Settings
    log_retention_days = models.IntegerField(default=90)
    enable_email_notifications = models.BooleanField(default=True)
    enable_slack_notifications = models.BooleanField(default=False)
    slack_webhook_url = models.URLField(blank=True)
    
    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'
        ordering = ['name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return self.name


class APIKey(BaseModel):
    """API keys for ingesting logs."""
    
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='api_keys'
    )
    name = models.CharField(max_length=100)
    key_prefix = models.CharField(max_length=10, unique=True, db_index=True)
    key_hash = models.CharField(max_length=255)
    
    # Permissions
    can_ingest = models.BooleanField(default=True)
    allowed_sources = models.JSONField(
        default=list,
        help_text="List of allowed sources: ['haproxy', 'nginx', 'crowdsec', 'fail2ban']"
    )
    
    # Rate limiting
    rate_limit = models.CharField(
        max_length=20,
        default='1000/hour',
        help_text="Rate limit in format: '1000/hour'"
    )
    
    # Usage tracking
    last_used_at = models.DateTimeField(null=True, blank=True)
    total_requests = models.BigIntegerField(default=0)
    
    # Status
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.key_prefix}...)"
    
    @staticmethod
    def generate_key():
        """Generate a new API key."""
        return f"frc_{secrets.token_urlsafe(32)}"
    
    @staticmethod
    def _get_fernet_key():
        """Generate a valid Fernet key from SECRET_KEY."""
        # Hash SECRET_KEY to get consistent 32 bytes
        key_bytes = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        # Base64 encode for Fernet
        return base64.urlsafe_b64encode(key_bytes)
    
    def encrypt_key(self, plain_key):
        """Encrypt and store the API key."""
        fernet_key = self._get_fernet_key()
        cipher = Fernet(fernet_key)
        self.key_hash = cipher.encrypt(plain_key.encode()).decode()
        self.key_prefix = plain_key[:10]
    
    def verify_key(self, plain_key):
        """Verify if the provided key matches."""
        try:
            fernet_key = self._get_fernet_key()
            cipher = Fernet(fernet_key)
            decrypted = cipher.decrypt(self.key_hash.encode()).decode()
            return decrypted == plain_key
        except Exception:
            return False


class Agent(BaseModel):
    """Agent registry for ingest authentication."""

    agent_id = models.CharField(max_length=64, unique=True)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='agents'
    )
    is_active = models.BooleanField(default=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['agent_id']

    def __str__(self):
        return self.agent_id


class OrganizationMember(BaseModel):
    """Many-to-many relationship between users and organizations with roles."""
    
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='members'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='organization_memberships'
    )
    
    # Role-based access control
    role = models.CharField(
        max_length=20,
        choices=[
            ('owner', 'Owner'),
            ('admin', 'Admin'),
            ('analyst', 'Analyst'),
            ('readonly', 'Read Only'),
        ],
        default='readonly'
    )
    
    # Permissions
    can_manage_users = models.BooleanField(default=False)
    can_manage_api_keys = models.BooleanField(default=False)
    can_create_alerts = models.BooleanField(default=False)
    can_export_data = models.BooleanField(default=False)
    
    # Status
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name = 'Organization Member'
        verbose_name_plural = 'Organization Members'
        unique_together = [['organization', 'user']]
    
    def __str__(self):
        return f"{self.user.email} - {self.organization.name} ({self.role})"
    
    def save(self, *args, **kwargs):
        """Set permissions based on role."""
        if self.role in ['owner', 'admin']:
            self.can_manage_users = True
            self.can_manage_api_keys = True
            self.can_create_alerts = True
            self.can_export_data = True
        elif self.role == 'analyst':
            self.can_create_alerts = True
            self.can_export_data = True
        
        super().save(*args, **kwargs)
