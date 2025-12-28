#!/usr/bin/env python3
"""Generate demo data for dashboard testing."""
import requests
import random
from datetime import datetime, timedelta

API_KEY = 'frc_t3pAnXEtcirZE0p-hceTyDXfkPamVACd33z1IBigu3Y'
BASE_URL = "http://localhost:8000/api/v1/ingest"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Sample IPs
ATTACKER_IPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
    "10.0.0.50", "10.0.0.51", "10.0.0.52",
    "172.16.1.10", "172.16.1.11", "172.16.1.12"
]

GOOD_IPS = [
    "192.168.1.200", "192.168.1.201", "10.0.0.100"
]

# Sample paths
ATTACK_PATHS = [
    "/admin", "/wp-admin", "/.env", "/api/admin",
    "/shell.php", "/backup.sql", "/config.php"
]

NORMAL_PATHS = [
    "/api/users", "/api/products", "/api/health",
    "/api/status", "/dashboard", "/api/login"
]

def generate_haproxy_logs(count=20):
    """Generate HAProxy logs."""
    logs = []
    for i in range(count):
        is_attack = random.random() < 0.3  # 30% attacks
        ip = random.choice(ATTACKER_IPS if is_attack else GOOD_IPS)
        port = random.randint(1024, 65535)
        status = random.choice([403, 429, 500]) if is_attack else random.choice([200, 200, 200, 404])
        path = random.choice(ATTACK_PATHS if is_attack else NORMAL_PATHS)
        method = random.choice(["GET", "POST", "PUT"])
        
        log = f'{ip}:{port} [01/Jan/2024:16:00:{i:02d}.000] frontend backend/srv1 0/0/0/{random.randint(5,50)}/{random.randint(10,100)} {status} {random.randint(100,5000)} - - ---- 1/1/0/0/0 0/0 "{method} {path} HTTP/1.1"'
        logs.append(log)
    
    response = requests.post(f"{BASE_URL}/haproxy/", headers=HEADERS, json={"logs": logs})
    print(f"HAProxy: {response.json()}")

def generate_nginx_logs(count=20):
    """Generate Nginx logs."""
    logs = []
    for i in range(count):
        is_attack = random.random() < 0.3
        ip = random.choice(ATTACKER_IPS if is_attack else GOOD_IPS)
        status = random.choice([403, 500]) if is_attack else random.choice([200, 200, 200, 404])
        path = random.choice(ATTACK_PATHS if is_attack else NORMAL_PATHS)
        method = random.choice(["GET", "POST"])
        user_agent = "EvilBot/1.0" if is_attack else "Mozilla/5.0"
        
        log = f'{ip} - - [01/Jan/2024:16:01:{i:02d} +0000] "{method} {path} HTTP/1.1" {status} {random.randint(100,5000)} "-" "{user_agent}"'
        logs.append(log)
    
    response = requests.post(f"{BASE_URL}/nginx/", headers=HEADERS, json={"logs": logs})
    print(f"Nginx: {response.json()}")

def generate_crowdsec_decisions(count=10):
    """Generate CrowdSec decisions."""
    decisions = []
    scenarios = [
        "crowdsecurity/ssh-bf",
        "crowdsecurity/http-scan-unmanaged",
        "crowdsecurity/http-exploit",
        "crowdsecurity/http-bad-user-agent"
    ]
    
    for i in range(count):
        ip = random.choice(ATTACKER_IPS)
        decision = {
            "duration": random.choice(["1h", "4h", "24h"]),
            "id": 6000 + i,
            "origin": "cscli",
            "scenario": random.choice(scenarios),
            "scope": "Ip",
            "type": random.choice(["ban", "captcha"]),
            "value": ip
        }
        decisions.append(decision)
    
    response = requests.post(f"{BASE_URL}/crowdsec/", headers=HEADERS, json=decisions)
    print(f"CrowdSec: {response.json()}")

def generate_fail2ban_logs(count=15):
    """Generate Fail2ban logs."""
    logs = []
    jails = ["sshd", "nginx-limit-req", "nginx-botsearch", "apache-auth"]
    
    for i in range(count):
        ip = random.choice(ATTACKER_IPS)
        jail = random.choice(jails)
        log = f"2024-01-01 16:02:{i:02d} fail2ban.actions: [{jail}] Ban {ip}"
        logs.append(log)
    
    response = requests.post(f"{BASE_URL}/fail2ban/", headers=HEADERS, json={"logs": logs})
    print(f"Fail2ban: {response.json()}")

if __name__ == "__main__":
    print("🔥 Generating demo data for dashboard...")
    print("=" * 50)
    
    generate_haproxy_logs(30)
    generate_nginx_logs(30)
    generate_crowdsec_decisions(15)
    generate_fail2ban_logs(20)
    
    print("=" * 50)
    print("✅ Demo data generated!")
    print("\n🌐 View dashboard at: http://localhost:8000/")
