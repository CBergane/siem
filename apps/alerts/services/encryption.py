"""
Webhook encryption service.
"""
from cryptography.fernet import Fernet
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class WebhookEncryption:
    """
    Service for encrypting/decrypting webhook URLs.
    
    Uses Fernet symmetric encryption to protect webhook URLs in database.
    """
    
    @staticmethod
    def get_cipher():
        """Get Fernet cipher instance."""
        key = settings.WEBHOOK_ENCRYPTION_KEY.encode()
        return Fernet(key)
    
    @staticmethod
    def encrypt(webhook_url: str) -> str:
        """
        Encrypt webhook URL.
        
        Args:
            webhook_url: Plain text webhook URL
            
        Returns:
            Encrypted webhook URL as string
        """
        if not webhook_url:
            return ''
        
        try:
            cipher = WebhookEncryption.get_cipher()
            encrypted = cipher.encrypt(webhook_url.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Failed to encrypt webhook URL: {str(e)}")
            raise
    
    @staticmethod
    def decrypt(encrypted_url: str) -> str:
        """
        Decrypt webhook URL.
        
        Args:
            encrypted_url: Encrypted webhook URL
            
        Returns:
            Plain text webhook URL
        """
        if not encrypted_url:
            return ''
        
        try:
            cipher = WebhookEncryption.get_cipher()
            decrypted = cipher.decrypt(encrypted_url.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt webhook URL: {str(e)}")
            raise
    
    @staticmethod
    def mask_url(url: str, show_chars: int = 8) -> str:
        """
        Mask URL for display (show only last N chars).
        
        Args:
            url: URL to mask
            show_chars: Number of chars to show at end
            
        Returns:
            Masked URL like "...xxx/abc123"
        """
        if not url or len(url) <= show_chars:
            return "***"
        
        return f"...{url[-show_chars:]}"
