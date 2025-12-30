#!/usr/bin/env python3
"""Generate demo data with PUBLIC IP addresses for GeoIP testing."""
import requests
import random

API_KEY = ''
BASE_URL = "http://localhost:8000/api/v1/ingest"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Real public IP addresses from DIFFERENT countries (more diversity!)
PUBLIC_IPS = {
    # North America
    "8.8.8.8": "USA",           # Google DNS
    "208.67.222.222": "USA",    # OpenDNS
    
    # Europe
    "194.242.2.2": "Sweden",    # Mullvad
    "185.228.168.9": "Germany", # Quad9
    "89.233.43.71": "Russia",   # Russia
    "151.80.31.5": "France",    # OVH
    "185.220.101.1": "Netherlands",
    "77.88.8.8": "Russia",      # Yandex DNS
    "193.17.47.1": "Spain",
    "151.101.1.140": "UK",      # Fastly
    
    # Asia
    "202.12.27.33": "Thailand",
    "103.86.96.100": "Singapore",
    "43.230.161.132": "China",
    "210.25.98.203": "Japan",
    "168.95.1.1": "Taiwan",
    "203.248.252.2": "South Korea",
    "103.47.170.88": "India",
    "119.160.208.251": "Vietnam",
    
    # South America
    "200.221.11.101": "Brazil",
    "190.93.246.4": "Argentina",
    "200.57.7.61": "Chile",
    
    # Africa
    "41.203.245.222": "South Africa",
    "196.216.2.19": "Kenya",
    "41.207.233.18": "Egypt",
    
    # Oceania
    "1.1.1.1": "Australia",     # Cloudflare (based in Australia)
    "202.14.67.4": "Australia",
    "103.37.160.1": "New Zealand",
}

def generate_nginx_logs(count=30):
    """Generate Nginx logs with diverse public IPs."""
    logs = []
    ips = list(PUBLIC_IPS.keys())
    
    for i in range(count):
        ip = random.choice(ips)
        status = random.choice([200, 200, 200, 403, 500, 429])
        path = random.choice(["/api/users", "/api/products", "/admin", "/.env", "/wp-admin"])
        method = random.choice(["GET", "POST", "PUT"])
        
        log = f'{ip} - - [13/Nov/2025:17:30:{i:02d} +0000] "{method} {path} HTTP/1.1" {status} {random.randint(100,5000)} "-" "Mozilla/5.0"'
        logs.append(log)
    
    response = requests.post(f"{BASE_URL}/nginx/", headers=HEADERS, json={"logs": logs})
    result = response.json()
    print(f"Nginx: {result['logs_created']} logs created")
    return result

def generate_haproxy_logs(count=30):
    """Generate HAProxy logs with diverse public IPs."""
    logs = []
    ips = list(PUBLIC_IPS.keys())
    
    for i in range(count):
        ip = random.choice(ips)
        port = random.randint(1024, 65535)
        status = random.choice([200, 200, 403, 500, 429])
        path = random.choice(["/api/test", "/admin", "/api/crash", "/shell.php"])
        
        log = f'{ip}:{port} [13/Nov/2025:17:31:{i:02d}.000] frontend backend/srv1 0/0/0/{random.randint(5,50)}/{random.randint(10,100)} {status} {random.randint(100,5000)} - - ---- 1/1/0/0/0 0/0 "GET {path} HTTP/1.1"'
        logs.append(log)
    
    response = requests.post(f"{BASE_URL}/haproxy/", headers=HEADERS, json={"logs": logs})
    result = response.json()
    print(f"HAProxy: {result['logs_created']} logs created")
    return result

def generate_crowdsec_decisions(count=20):
    """Generate CrowdSec decisions with diverse IPs."""
    decisions = []
    ips = list(PUBLIC_IPS.keys())
    scenarios = [
        "crowdsecurity/ssh-bf",
        "crowdsecurity/http-scan-unmanaged",
        "crowdsecurity/http-exploit",
        "crowdsecurity/http-bad-user-agent"
    ]
    
    for i in range(count):
        ip = random.choice(ips)
        decision = {
            "duration": random.choice(["1h", "4h", "24h"]),
            "id": 7000 + i,
            "origin": "cscli",
            "scenario": random.choice(scenarios),
            "scope": "Ip",
            "type": random.choice(["ban", "captcha"]),
            "value": ip
        }
        decisions.append(decision)
    
    response = requests.post(f"{BASE_URL}/crowdsec/", headers=HEADERS, json=decisions)
    result = response.json()
    print(f"CrowdSec: {result['logs_created']} decisions created")
    return result

if __name__ == "__main__":
    print("🌍 Generating logs with diverse PUBLIC IP addresses...")
    print(f"IP pool: {len(PUBLIC_IPS)} unique IPs from different countries")
    print("=" * 60)
    
    generate_nginx_logs(40)
    generate_haproxy_logs(40)
    generate_crowdsec_decisions(20)
    
    print("=" * 60)
    print(f"✅ Generated ~100 logs from {len(PUBLIC_IPS)} countries!")
    print("\nRun these commands:")
    print("1. python manage.py enrich_logs --limit 100 --async")
    print("2. Wait 3-4 minutes")
    print("3. Reload dashboard: http://localhost:8000/")
    print("\nYou should see attacks from ~27 different countries! 🌍")
