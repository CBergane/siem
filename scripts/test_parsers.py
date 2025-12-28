#!/usr/bin/env python3
import os
import sys

API_KEY = os.getenv("TEST_API_KEY", "").strip()
if not API_KEY:
    print("Skipping parser tests: TEST_API_KEY not set.")
    sys.exit(0)

import requests
import json

BASE_URL = "http://localhost:8000/api/v1/ingest"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def test_parser(name, endpoint, data):
    print(f"\n{'='*50}")
    print(f"Testing {name}")
    print(f"{'='*50}")
    
    response = requests.post(f"{BASE_URL}/{endpoint}/", headers=HEADERS, json=data)
    result = response.json()
    
    if result.get('success'):
        print(f"✅ {result['logs_created']} logs created")
    else:
        print(f"❌ Error: {result.get('error')}")
    
    if result.get('errors'):
        print(f"⚠️  {len(result['errors'])} errors")
    
    return result

# Test HAProxy
test_parser("HAProxy", "haproxy", {
    "logs": [
        '10.0.1.1:12345 [01/Jan/2024:15:00:00.000] frontend backend/srv1 0/0/0/5/5 200 1234 - - ---- 1/1/0/0/0 0/0 "GET /api/health HTTP/1.1"',
        '10.0.1.2:12346 [01/Jan/2024:15:00:01.000] frontend backend/srv1 0/0/0/8/8 403 567 - - ---- 1/1/0/0/0 0/0 "POST /admin/backdoor HTTP/1.1"'
    ]
})

# Test Nginx
test_parser("Nginx", "nginx", {
    "logs": [
        '10.0.2.1 - - [01/Jan/2024:15:01:00 +0000] "GET /api/products HTTP/1.1" 200 3456 "-" "curl/7.68.0"',
        '10.0.2.2 - admin [01/Jan/2024:15:01:01 +0000] "POST /api/delete_all HTTP/1.1" 500 123 "https://evil.com" "EvilBot/1.0"'
    ]
})

# Test CrowdSec
test_parser("CrowdSec", "crowdsec", [
    {"duration": "24h", "id": 5001, "origin": "cscli", "scenario": "crowdsecurity/ssh-bf", "scope": "Ip", "type": "ban", "value": "10.0.3.1"},
    {"duration": "4h", "id": 5002, "origin": "cscli", "scenario": "crowdsecurity/http-exploit", "scope": "Ip", "type": "ban", "value": "10.0.3.2"}
])

# Test Fail2ban
test_parser("Fail2ban", "fail2ban", {
    "logs": [
        "2024-01-01 15:02:00 fail2ban.actions: [sshd] Ban 10.0.4.1",
        "[nginx-limit-req] Ban 10.0.4.2"
    ]
})

print(f"\n{'='*50}")
print("✅ All parsers tested!")
print(f"{'='*50}")
print("\nCheck results at: http://localhost:8000/admin/logs/securitylog/")
