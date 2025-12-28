"""
Server discovery and management service.
"""
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from apps.logs.models import ServerAlias, SecurityLog


class ServerDiscoveryService:
    """
    Automatically discover and track servers from incoming logs.
    """
    
    @staticmethod
    def discover_or_update_server(organization, hostname):
        """
        Discover new server or update last_seen timestamp.
        
        Returns: (ServerAlias, created: bool)
        """
        if not hostname or hostname in ['unknown', 'nginx', 'haproxy', 'fail2ban', 'crowdsec']:
            return None, False
        
        # Get or create server alias
        server, created = ServerAlias.objects.get_or_create(
            organization=organization,
            original_hostname=hostname,
            defaults={
                'display_name': hostname,
                'description': 'Auto-discovered server',
                'is_active': True,
                'last_seen': timezone.now(),
            }
        )
        
        # Update last_seen if not created
        if not created:
            server.update_last_seen()
        
        return server, created
    
    @staticmethod
    def get_server_stats(organization, include_inactive=False):
        """
        Get statistics for all servers in organization.
        """
        servers = ServerAlias.objects.filter(
            organization=organization
        )
        
        if not include_inactive:
            servers = servers.filter(is_active=True)
        
        stats = []
        last_24h = timezone.now() - timedelta(hours=24)
        
        for server in servers:
            # Count logs from this server
            log_count = SecurityLog.objects.filter(
                organization=organization,
                source_host=server.original_hostname
            ).count()
            
            # Last 24h logs
            recent_count = SecurityLog.objects.filter(
                organization=organization,
                source_host=server.original_hostname,
                timestamp__gte=last_24h
            ).count()
            
            # Health check: has recent activity?
            is_healthy = recent_count > 0 and server.is_active
            
            stats.append({
                'server': server,
                'total_logs': log_count,
                'recent_logs': recent_count,
                'is_healthy': is_healthy,
            })
        
        return stats
