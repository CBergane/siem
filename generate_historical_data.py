#!/usr/bin/env python3
"""Generate historical data spanning multiple hours/days."""
import requests
import random
from datetime import datetime, timedelta
import sys

# Django setup
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from apps.logs.models import SecurityLog
from apps.organizations.models import Organization

# Sample data
ATTACKER_IPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
    "10.0.0.50", "10.0.0.51", "10.0.0.52",
    "172.16.1.10", "172.16.1.11", "172.16.1.12"
]

SOURCES = ['haproxy', 'nginx', 'crowdsec', 'fail2ban']
ACTIONS = ['allow', 'deny', 'ban', 'rate_limit']
SEVERITIES = ['low', 'medium', 'high', 'critical']

def generate_historical_logs(hours_back=72, logs_per_hour=10):
    """Generate logs going back in time."""
    
    org = Organization.objects.first()
    if not org:
        print("❌ No organization found!")
        return
    
    print(f"📊 Generating {hours_back} hours of historical data...")
    print(f"   {logs_per_hour} logs per hour = {hours_back * logs_per_hour} total logs")
    print("")
    
    logs_to_create = []
    now = datetime.now()
    
    for hour in range(hours_back):
        timestamp = now - timedelta(hours=hour)
        
        for _ in range(logs_per_hour):
            # Random variance in minutes
            actual_time = timestamp - timedelta(minutes=random.randint(0, 59))
            
            # 70% low severity, 20% medium, 8% high, 2% critical
            severity_rand = random.random()
            if severity_rand < 0.70:
                severity = 'low'
                action = 'allow'
            elif severity_rand < 0.90:
                severity = 'medium'
                action = random.choice(['allow', 'deny'])
            elif severity_rand < 0.98:
                severity = 'high'
                action = random.choice(['deny', 'rate_limit'])
            else:
                severity = 'critical'
                action = random.choice(['ban', 'deny'])
            
            log = SecurityLog(
                organization=org,
                source_type=random.choice(SOURCES),
                source_host=random.choice(['server1', 'server2', 'firewall']),
                timestamp=actual_time,
                src_ip=random.choice(ATTACKER_IPS),
                src_port=random.randint(1024, 65535),
                method=random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                path=random.choice(['/api/users', '/admin', '/api/test', '/.env']),
                status_code=random.choice([200, 403, 500, 429]),
                action=action,
                severity=severity,
                raw_log=f"Historical log at {actual_time}",
                metadata={}
            )
            logs_to_create.append(log)
        
        # Batch create every 100 logs
        if len(logs_to_create) >= 100:
            SecurityLog.objects.bulk_create(logs_to_create)
            print(f"   Created {len(logs_to_create)} logs (up to {hour}h ago)")
            logs_to_create = []
    
    # Create remaining
    if logs_to_create:
        SecurityLog.objects.bulk_create(logs_to_create)
        print(f"   Created final {len(logs_to_create)} logs")
    
    total = SecurityLog.objects.count()
    print("")
    print(f"✅ Done! Total logs in database: {total}")
    print(f"   Oldest log: {SecurityLog.objects.order_by('timestamp').first().timestamp}")
    print(f"   Newest log: {SecurityLog.objects.order_by('-timestamp').first().timestamp}")

if __name__ == "__main__":
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 72
    logs_per_hour = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    generate_historical_logs(hours, logs_per_hour)
