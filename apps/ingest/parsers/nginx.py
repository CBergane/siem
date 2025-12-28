"""
Nginx log parser for combined log format.
"""
import re
from datetime import datetime
from typing import Dict, Optional
from django.utils import timezone


class NginxParser:
    """
    Parser för Nginx combined log format.
    
    Format:
    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    
    Exempel:
    192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /api/test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
    """
    
    # Full combined format
    PATTERN_COMBINED = re.compile(
        r'(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'-\s+'
        r'(?P<remote_user>\S+)\s+'
        r'\[(?P<time_local>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<body_bytes_sent>\d+)\s+'
        r'"(?P<http_referer>[^"]*)"\s+'
        r'"(?P<http_user_agent>[^"]*)"'
    )
    
    # Common format (utan referer och user_agent)
    PATTERN_COMMON = re.compile(
        r'(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'-\s+'
        r'(?P<remote_user>\S+)\s+'
        r'\[(?P<time_local>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<body_bytes_sent>\d+)'
    )
    
    def parse(self, raw_log: str) -> Optional[Dict]:
        """
        Parse en Nginx log rad.
        
        Returns:
            Dict med parsed data eller None om parsing misslyckas
        """
        raw_log = raw_log.strip()
        
        # Try combined format first
        match = self.PATTERN_COMBINED.match(raw_log)
        
        # If no match, try common format
        if not match:
            match = self.PATTERN_COMMON.match(raw_log)
        
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse request line (GET /path HTTP/1.1)
        request_parts = data['request'].split(' ')
        method = request_parts[0] if len(request_parts) > 0 else ''
        path = request_parts[1] if len(request_parts) > 1 else ''
        
        # Parse timestamp (format: 01/Jan/2024:12:00:00 +0000)
        try:
            # Remove timezone for simplicity
            timestamp_str = data['time_local'].split(' ')[0]
            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
            if timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
        except Exception:
            timestamp = timezone.now()
        
        # Get user agent (if exists)
        user_agent = data.get('http_user_agent', '')
        if user_agent == '-':
            user_agent = ''
        
        # Get referer (if exists)
        referer = data.get('http_referer', '')
        if referer == '-':
            referer = ''
        
        return {
            'timestamp': timestamp,
            'src_ip': data['remote_addr'],
            'method': method,
            'path': path,
            'status_code': int(data['status']),
            'bytes_sent': int(data['body_bytes_sent']),
            'user_agent': user_agent,
            'referer': referer,
            'source_host': 'nginx',
            'raw_log': raw_log,
            'metadata': {
                'remote_user': data['remote_user'] if data['remote_user'] != '-' else '',
                'request_full': data['request']
            }
        }
