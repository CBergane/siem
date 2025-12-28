"""
Server alias model for custom server naming.
"""
from django.db import models
from django.conf import settings


class ServerAlias(models.Model):
    """
    Custom names/aliases for servers.
    Allows users to give friendly names to their servers.
    """
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='server_aliases'
    )
    
    # Original hostname from logs (e.g., "ubuntu-linode-123456")
    original_hostname = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Original hostname from security logs"
    )
    
    # User-friendly display name
    display_name = models.CharField(
        max_length=255,
        help_text="Custom display name for this server"
    )
    
    description = models.TextField(
        blank=True,
        help_text="Optional description of server purpose"
    )
    
    # Server metadata
    server_type = models.CharField(
        max_length=50,
        blank=True,
        help_text="Server type: web, api, database, etc"
    )
    
    environment = models.CharField(
        max_length=50,
        default='production',
        choices=[
            ('production', 'Production'),
            ('staging', 'Staging'),
            ('development', 'Development'),
            ('testing', 'Testing'),
        ]
    )
    
    # Status tracking
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this server is currently active"
    )
    
    last_seen = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time logs were received from this server"
    )
    
    # Metadata
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_server_aliases'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Server Alias"
        verbose_name_plural = "Server Aliases"
        ordering = ['display_name']
        unique_together = ['organization', 'original_hostname']
    
    def __str__(self):
        return f"{self.display_name} ({self.original_hostname})"
    
    def update_last_seen(self):
        """Update last_seen timestamp to now."""
        from django.utils import timezone
        self.last_seen = timezone.now()
        self.save(update_fields=['last_seen'])
