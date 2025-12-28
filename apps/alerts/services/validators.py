"""
Webhook validation service.
"""
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class WebhookValidator:
    """
    Service for validating webhook URLs.
    """
    
    # Allowed domains per channel type
    ALLOWED_DOMAINS = {
        'slack': ['hooks.slack.com'],
        'discord': ['discord.com', 'discordapp.com'],
        'webhook': [],  # Generic webhooks - any HTTPS
    }
    
    @staticmethod
    def validate_url(url: str, channel_type: str) -> tuple[bool, str]:
        """
        Validate webhook URL.
        
        Args:
            url: Webhook URL to validate
            channel_type: Type of channel (slack, discord, webhook)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Must not be empty
        if not url:
            return False, "Webhook URL is required"
        
        # Must be valid URL
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Invalid URL format"
        
        # Must have scheme
        if not parsed.scheme:
            return False, "URL must include protocol (https://)"
        
        # Must be HTTPS (security requirement)
        if parsed.scheme != 'https':
            return False, "Webhook URL must use HTTPS"
        
        # Must have domain
        if not parsed.netloc:
            return False, "Invalid URL domain"
        
        # Check domain whitelist for specific channel types
        if channel_type in WebhookValidator.ALLOWED_DOMAINS:
            allowed = WebhookValidator.ALLOWED_DOMAINS[channel_type]
            
            # If whitelist is defined, check it
            if allowed:
                domain_match = any(
                    domain in parsed.netloc 
                    for domain in allowed
                )
                
                if not domain_match:
                    expected = ', '.join(allowed)
                    return False, f"Invalid domain. Expected: {expected}"
        
        return True, ""
    
    @staticmethod
    def validate_email(email: str) -> tuple[bool, str]:
        """
        Validate email address.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import re
        
        if not email:
            return False, "Email address is required"
        
        # Basic email regex
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_regex, email):
            return False, "Invalid email format"
        
        return True, ""
    
    @staticmethod
    def validate_email_list(emails: list) -> tuple[bool, str]:
        """
        Validate list of email addresses.
        
        Args:
            emails: List of email addresses
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not emails:
            return False, "At least one email address is required"
        
        for email in emails:
            is_valid, error = WebhookValidator.validate_email(email)
            if not is_valid:
                return False, f"{email}: {error}"
        
        return True, ""
