"""
Fail2ban log parser.
"""
import re
from datetime import datetime
from typing import Dict, Optional


class Fail2banParser:
    """
    Parser för Fail2ban logs.
    
    Fail2ban kan ha olika format beroende på version och konfiguration.
    
    Format 1 (standard log):
    2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
    
    Format 2 (kort format):
    [sshd] Ban 192.168.1.100
    
    Format 3 (med duration):
    2024-01-01 12:00:00 fail2ban.actions: [nginx] Ban 192.168.1.100 (duration: 3600s)
    """
    
    # Pattern för fullt format med timestamp (case-insensitive)
    PATTERN_FULL = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})[,\s]+.*?'
        r'\[(?P<jail>[^\]]+)\]\s+'
        r'(?P<action>ban|unban)\s+'
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.IGNORECASE  # <-- VIKTIGT: Case-insensitive!
    )
    
    # Pattern för kort format utan timestamp
    PATTERN_SHORT = re.compile(
        r'\[(?P<jail>[^\]]+)\]\s+'
        r'(?P<action>ban|unban)\s+'
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.IGNORECASE  # <-- VIKTIGT: Case-insensitive!
    )
    
    # Duration pattern (optional)
    DURATION_PATTERN = re.compile(r'duration:\s*(\d+)s')
    
    def parse(self, raw_log: str) -> Optional[Dict]:
        """
        Parse en Fail2ban log rad.
        
        Returns:
            Dict med parsed data eller None om parsing misslyckas
        """
        raw_log = raw_log.strip()
        
        # Try full pattern first
        match = self.PATTERN_FULL.match(raw_log)
        has_timestamp = True
        
        # If no match, try short pattern
        if not match:
            match = self.PATTERN_SHORT.match(raw_log)
            has_timestamp = False
        
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        if has_timestamp:
            try:
                timestamp_str = data['timestamp']
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except Exception:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        # Determine action (normalize to lowercase)
        action_str = data['action'].lower()
        if action_str == 'ban':
            action = 'ban'
            severity = 'high'
        else:  # unban
            action = 'allow'
            severity = 'low'
        
        # Extract jail (service)
        jail = data['jail']
        
        # Check for duration in log
        duration_match = self.DURATION_PATTERN.search(raw_log)
        duration = int(duration_match.group(1)) if duration_match else None
        
        # Map common jails to more descriptive names
        jail_map = {
            'sshd': 'SSH Brute Force',
            'nginx-limit-req': 'Nginx Rate Limit',
            'nginx-botsearch': 'Nginx Bot Search',
            'apache-auth': 'Apache Authentication',
            'dovecot': 'Dovecot Mail',
            'postfix': 'Postfix SMTP',
        }
        
        reason = jail_map.get(jail, f'Fail2ban: {jail}')
        
        return {
            'timestamp': timestamp,
            'src_ip': data['ip'],
            'action': action,
            'severity': severity,
            'reason': reason,
            'source_host': 'fail2ban',
            'raw_log': raw_log,
            'metadata': {
                'jail': jail,
                'fail2ban_action': data['action'],
                'duration_seconds': duration
            }
        }
