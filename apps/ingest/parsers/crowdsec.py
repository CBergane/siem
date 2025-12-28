"""
CrowdSec decision parser.
"""
import json
from typing import Dict, Optional
from django.utils import timezone


class CrowdSecParser:
    """
    Parser för CrowdSec decisions (JSON format).
    
    CrowdSec skickar decisions när en IP ska bannas/challengas.
    
    Exempel JSON:
    {
      "duration": "4h",
      "id": 1234,
      "origin": "cscli",
      "scenario": "crowdsecurity/http-bad-user-agent",
      "scope": "Ip",
      "type": "ban",
      "value": "192.168.1.100"
    }
    """
    
    def parse(self, raw_log: str) -> Optional[Dict]:
        """
        Parse en CrowdSec decision (JSON).
        
        Returns:
            Dict med parsed data eller None om parsing misslyckas
        """
        try:
            # Parse JSON
            if isinstance(raw_log, str):
                data = json.loads(raw_log)
            else:
                data = raw_log
        except (json.JSONDecodeError, TypeError):
            return None
        
        # Validate required fields
        if 'value' not in data or 'type' not in data:
            return None
        
        # Extract IP address
        src_ip = data.get('value', '')
        
        # Determine action based on type
        decision_type = data.get('type', 'ban').lower()
        action_map = {
            'ban': 'ban',
            'captcha': 'challenge',
            'throttle': 'rate_limit'
        }
        action = action_map.get(decision_type, 'deny')
        
        # Determine severity based on scenario
        scenario = data.get('scenario', '').lower()
        if 'exploit' in scenario or 'cve' in scenario:
            severity = 'critical'
        elif 'attack' in scenario or 'scan' in scenario:
            severity = 'high'
        else:
            severity = 'medium'
        
        return {
            'timestamp': timezone.now(),  # CrowdSec doesn't always include timestamp
            'src_ip': src_ip,
            'action': action,
            'severity': severity,
            'reason': data.get('scenario', 'Unknown scenario'),
            'source_host': data.get('origin', 'crowdsec'),
            'raw_log': raw_log if isinstance(raw_log, str) else json.dumps(raw_log),
            'metadata': {
                'decision_id': data.get('id'),
                'duration': data.get('duration', ''),
                'scope': data.get('scope', 'Ip'),
                'scenario': data.get('scenario', ''),
                'origin': data.get('origin', '')
            }
        }
