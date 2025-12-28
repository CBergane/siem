"""
HAProxy log parser.
"""
import re
from datetime import datetime
from typing import Dict, Optional


class HAProxyParser:
    """
    Parser för HAProxy HTTP logs.
    
    Format:
    <client_ip>:<client_port> [<accept_date>] <frontend_name> <backend_name>/<server_name> 
    <Tq>/<Tw>/<Tc>/<Tr>/<Tt> <status_code> <bytes_read> - - ---- 
    <actconn>/<feconn>/<beconn>/<srv_conn>/<retries> <srv_queue>/<backend_queue> 
    "<http_request>"
    
    Exempel:
    192.168.1.100:54321 [01/Jan/2024:12:00:00.000] frontend backend/server1 0/0/0/12/12 200 1234 - - ---- 1/1/0/0/0 0/0 "GET /api/test HTTP/1.1"
    """
    
    PATTERN = re.compile(
        r'(?P<client_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<client_port>\d+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'(?P<frontend_name>\S+)\s+'
        r'(?P<backend_name>\S+)/(?P<server_name>\S+)\s+'
        r'(?P<tq>-?\d+)/(?P<tw>-?\d+)/(?P<tc>-?\d+)/(?P<tr>-?\d+)/(?P<tt>\d+)\s+'
        r'(?P<status_code>\d+)\s+'
        r'(?P<bytes_read>\d+)\s+'
        r'.*?'
        r'"(?P<http_request>[^"]*)"'
    )
    
    def parse(self, raw_log: str) -> Optional[Dict]:
        """
        Parse en HAProxy log rad.
        
        Returns:
            Dict med parsed data eller None om parsing misslyckas
        """
        match = self.PATTERN.match(raw_log.strip())
        
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse HTTP request
        http_parts = data['http_request'].split(' ')
        method = http_parts[0] if len(http_parts) > 0 else ''
        path = http_parts[1] if len(http_parts) > 1 else ''
        
        # Parse timestamp (format: 01/Jan/2024:12:00:00.000)
        try:
            timestamp_str = data['timestamp'].split('.')[0]
            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
        except Exception:
            timestamp = datetime.now()
        
        return {
            'timestamp': timestamp,
            'src_ip': data['client_ip'],
            'src_port': int(data['client_port']),
            'method': method,
            'path': path,
            'status_code': int(data['status_code']),
            'bytes_sent': int(data['bytes_read']),
            'source_host': data['server_name'],
            'raw_log': raw_log,
            'metadata': {
                'frontend': data['frontend_name'],
                'backend': data['backend_name'],
                'timings': {
                    'tq': int(data['tq']),
                    'tw': int(data['tw']),
                    'tc': int(data['tc']),
                    'tr': int(data['tr']),
                    'tt': int(data['tt']),
                }
            }
        }
