# 🚀 Firewall Report Center - Production Log Forwarder Setup

Complete guide for setting up nginx and fail2ban log forwarders on production servers.

---

## �� Prerequisites

- Ubuntu/Debian server (tested on Ubuntu 24.04)
- Nginx installed and running
- Fail2ban installed (optional but recommended)
- Python 3 with `requests` module
- Network access to your Django API
- Valid API key from Django admin

---

## 🔑 Step 1: Get Your API Key

1. Log into Django admin: `https://your-domain.com/admin/`
2. Navigate to **Organizations** → **API Keys**
3. Create new API key or copy existing one
4. Format: `frc_xxxxxxxxxxxxxxxxxxxxxxxxxx`
5. **Save this securely!**

---

## 📡 Step 2: Get Your API Endpoint

Your endpoints will be:
- Nginx logs: `https://your-domain.com/api/v1/ingest/nginx/`
- Fail2ban logs: `https://your-domain.com/api/v1/ingest/fail2ban/`

**Note:** If using Cloudflare Tunnel, use the tunnel URL instead.

---

## 📝 Step 3: Create Nginx Log Forwarder Script
```bash
cat > /usr/local/bin/firewall-log-forwarder.py << 'SCRIPT_EOF'
#!/usr/bin/env python3
"""
Nginx Access Log Forwarder
Monitors nginx access logs and forwards to API in real-time.
"""
import sys
import time
import json
import requests
from datetime import datetime
import socket

# Force unbuffered output for systemd
sys.stdout = sys.stderr = open(sys.stdout.fileno(), 'w', buffering=1)

# ============================================================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================================================
API_URL = "https://your-domain.com/api/v1/ingest/nginx/"
API_KEY = "frc_your_api_key_here"
LOG_FILE = "/var/log/nginx/access.log"
SERVER_NAME = socket.gethostname()

def log_message(msg):
    """Print timestamped message."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def send_log(log_line):
    """Send a single log line to the API."""
    payload = {
        "log": log_line.strip(),
        "server_name": SERVER_NAME
    }
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            API_URL, 
            json=payload, 
            headers=headers,
            timeout=10
        )
        
        if response.status_code in [200, 201, 202]:
            log_message(f"✅ Sent log: {log_line[:60]}...")
            return True
        else:
            log_message(f"❌ Error {response.status_code}: {response.text[:100]}")
            return False
    
    except Exception as e:
        log_message(f"❌ Failed to send log: {e}")
        return False

def tail_file(filename):
    """Tail a file and yield new lines."""
    log_message(f"📖 Opening file: {filename}")
    
    try:
        with open(filename, 'r') as file:
            # Go to end of file
            file.seek(0, 2)
            position = file.tell()
            log_message(f"📍 Starting at position: {position}")
            log_message("⏳ Waiting for new lines...")
            
            while True:
                line = file.readline()
                if line:
                    log_message(f"📝 New line detected ({len(line)} bytes)")
                    yield line
                else:
                    time.sleep(0.1)
    
    except FileNotFoundError:
        log_message(f"❌ File not found: {filename}")
        sys.exit(1)
    except Exception as e:
        log_message(f"❌ Error reading file: {e}")
        sys.exit(1)

def main():
    """Main function."""
    log_message("🚀 Starting Nginx Log Forwarder...")
    log_message(f"📡 API: {API_URL}")
    log_message(f"🖥️  Server: {SERVER_NAME}")
    log_message(f"📄 Log: {LOG_FILE}")
    
    try:
        for line in tail_file(LOG_FILE):
            send_log(line)
    except KeyboardInterrupt:
        log_message("👋 Stopped by user")
    except Exception as e:
        log_message(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
SCRIPT_EOF

chmod +x /usr/local/bin/firewall-log-forwarder.py
```

**⚠️ IMPORTANT: Edit the configuration:**
```bash
nano /usr/local/bin/firewall-log-forwarder.py
# Update API_URL and API_KEY on lines 17-18
```

---

## 🚨 Step 4: Create Fail2ban Log Forwarder Script
```bash
cat > /usr/local/bin/fail2ban-log-forwarder.py << 'SCRIPT_EOF'
#!/usr/bin/env python3
"""
Fail2ban Log Forwarder
Monitors fail2ban logs and forwards bans to API.
"""
import sys
import time
import json
import requests
import socket
from datetime import datetime

# Force unbuffered output
sys.stdout = sys.stderr = open(sys.stdout.fileno(), 'w', buffering=1)

# ============================================================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================================================
API_URL = "https://your-domain.com/api/v1/ingest/fail2ban/"
API_KEY = "frc_your_api_key_here"
LOG_FILE = "/var/log/fail2ban.log"
SERVER_NAME = socket.gethostname()

def log_message(msg):
    """Print timestamped message."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def send_log(log_line):
    """Send a single log line to the API."""
    payload = {
        "log": log_line.strip(),
        "server_name": SERVER_NAME
    }
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            API_URL, 
            json=payload, 
            headers=headers,
            timeout=10
        )
        
        if response.status_code in [200, 201, 202]:
            log_message(f"✅ Sent ban: {log_line[:60]}...")
            return True
        else:
            log_message(f"❌ Error {response.status_code}: {response.text[:100]}")
            return False
    
    except Exception as e:
        log_message(f"❌ Failed to send log: {e}")
        return False

def tail_file(filename):
    """Tail a file and yield new lines."""
    log_message(f"📖 Opening file: {filename}")
    
    try:
        with open(filename, 'r') as file:
            # Go to end of file
            file.seek(0, 2)
            position = file.tell()
            log_message(f"📍 Starting at position: {position}")
            log_message("⏳ Waiting for bans...")
            
            while True:
                line = file.readline()
                if line:
                    # Only forward ban/unban events
                    if 'Ban' in line or 'Unban' in line:
                        log_message(f"🚨 Ban detected!")
                        yield line
                else:
                    time.sleep(0.1)
    
    except FileNotFoundError:
        log_message(f"❌ File not found: {filename}")
        log_message("Install fail2ban: apt install fail2ban")
        sys.exit(1)
    except Exception as e:
        log_message(f"❌ Error reading file: {e}")
        sys.exit(1)

def main():
    """Main function."""
    log_message("🚀 Starting Fail2ban Log Forwarder...")
    log_message(f"📡 API: {API_URL}")
    log_message(f"🖥️  Server: {SERVER_NAME}")
    log_message(f"📄 Log: {LOG_FILE}")
    
    try:
        for line in tail_file(LOG_FILE):
            send_log(line)
    except KeyboardInterrupt:
        log_message("👋 Stopped by user")
    except Exception as e:
        log_message(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
SCRIPT_EOF

chmod +x /usr/local/bin/fail2ban-log-forwarder.py
```

**⚠️ IMPORTANT: Edit the configuration:**
```bash
nano /usr/local/bin/fail2ban-log-forwarder.py
# Update API_URL and API_KEY on lines 18-19
```

---

## 🔧 Step 5: Create Systemd Services

### Nginx Forwarder Service
```bash
cat > /etc/systemd/system/nginx-log-forwarder.service << 'SERVICE_EOF'
[Unit]
Description=Nginx Log Forwarder to Firewall Report Center
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=root
Environment="PYTHONUNBUFFERED=1"
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 -u /usr/local/bin/firewall-log-forwarder.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nginx-forwarder

# Restart limits
StartLimitInterval=200
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF
```

### Fail2ban Forwarder Service
```bash
cat > /etc/systemd/system/fail2ban-log-forwarder.service << 'SERVICE_EOF'
[Unit]
Description=Fail2ban Log Forwarder to Firewall Report Center
After=network.target fail2ban.service
Wants=fail2ban.service
Requires=fail2ban.service

[Service]
Type=simple
User=root
Environment="PYTHONUNBUFFERED=1"
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 -u /usr/local/bin/fail2ban-log-forwarder.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fail2ban-forwarder

# Restart limits
StartLimitInterval=200
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF
```

---

## ▶️ Step 6: Enable and Start Services
```bash
# Reload systemd
systemctl daemon-reload

# Enable services (start on boot)
systemctl enable nginx-log-forwarder
systemctl enable fail2ban-log-forwarder

# Start services now
systemctl start nginx-log-forwarder
systemctl start fail2ban-log-forwarder

# Verify they're running
systemctl status nginx-log-forwarder
systemctl status fail2ban-log-forwarder
```

---

## 🔍 Step 7: Create Monitoring Script
```bash
cat > /usr/local/bin/check-forwarders.sh << 'EOF'
#!/bin/bash

echo "🔍 Firewall Log Forwarders Status"
echo "=================================="
echo ""

# Nginx Forwarder
if systemctl is-active --quiet nginx-log-forwarder; then
    echo "✅ Nginx Forwarder: RUNNING"
    
    # Show uptime
    UPTIME=$(systemctl show nginx-log-forwarder -p ActiveEnterTimestamp --value | cut -d' ' -f2-4)
    echo "   └─ Started: $UPTIME"
    
    # Count logs in last 5 min (using grep with fixed string)
    SENT_5MIN=$(journalctl -u nginx-log-forwarder --since "5 minutes ago" --no-pager 2>/dev/null | grep -F "✅ Sent log:" | wc -l)
    echo "   └─ Logs forwarded: $SENT_5MIN (last 5 min)"
    
    # Count errors in last 5 min
    ERR_5MIN=$(journalctl -u nginx-log-forwarder --since "5 minutes ago" --no-pager 2>/dev/null | grep -F "❌" | wc -l)
    if [ $ERR_5MIN -gt 0 ]; then
        echo "   └─ ⚠️  Errors: $ERR_5MIN (last 5 min)"
    fi
else
    echo "❌ Nginx Forwarder: STOPPED"
    echo "   └─ Start with: systemctl start nginx-log-forwarder"
fi

echo ""

# Fail2ban Forwarder
if systemctl is-active --quiet fail2ban-log-forwarder; then
    echo "✅ Fail2ban Forwarder: RUNNING"
    
    # Show uptime
    UPTIME=$(systemctl show fail2ban-log-forwarder -p ActiveEnterTimestamp --value | cut -d' ' -f2-4)
    echo "   └─ Started: $UPTIME"
    
    # Count bans in last 5 min
    SENT_5MIN=$(journalctl -u fail2ban-log-forwarder --since "5 minutes ago" --no-pager 2>/dev/null | grep -F "✅ Sent ban:" | wc -l)
    echo "   └─ Bans forwarded: $SENT_5MIN (last 5 min)"
    
    # Count errors
    ERR_5MIN=$(journalctl -u fail2ban-log-forwarder --since "5 minutes ago" --no-pager 2>/dev/null | grep -F "❌" | wc -l)
    if [ $ERR_5MIN -gt 0 ]; then
        echo "   └─ ⚠️  Errors: $ERR_5MIN (last 5 min)"
    fi
else
    echo "❌ Fail2ban Forwarder: STOPPED"
    echo "   └─ Start with: systemctl start fail2ban-log-forwarder"
fi

echo ""
echo "💡 Logs are being sent to Django dashboard"
echo "   Check: http://your-dashboard-url/dashboard/"
echo ""
echo "🔧 Useful Commands:"
echo "   journalctl -u nginx-log-forwarder -f       # Watch nginx logs"
echo "   journalctl -u fail2ban-log-forwarder -f    # Watch fail2ban logs"
echo "   systemctl restart nginx-log-forwarder      # Restart service"
EOF

chmod +x /usr/local/bin/check-forwarders.sh
```

---

## ✅ Step 8: Verify Everything Works

### Test Scripts Manually
```bash
# Test nginx forwarder (Ctrl+C to stop)
python3 /usr/local/bin/firewall-log-forwarder.py

# Test fail2ban forwarder (Ctrl+C to stop)
python3 /usr/local/bin/fail2ban-log-forwarder.py
```

### Generate Test Traffic
```bash
# Generate nginx logs
curl http://localhost/
curl http://localhost/test
curl http://localhost/admin

# Wait a few seconds
sleep 3

# Check status
check-forwarders.sh
```

### View Live Logs
```bash
# Watch nginx forwarder in real-time
journalctl -u nginx-log-forwarder -f

# Watch fail2ban forwarder in real-time
journalctl -u fail2ban-log-forwarder -f

# Watch both at once
journalctl -u nginx-log-forwarder -u fail2ban-log-forwarder -f
```

---

## 🔧 Common Management Commands

### Service Control
```bash
# Start services
systemctl start nginx-log-forwarder
systemctl start fail2ban-log-forwarder

# Stop services
systemctl stop nginx-log-forwarder
systemctl stop fail2ban-log-forwarder

# Restart services
systemctl restart nginx-log-forwarder
systemctl restart fail2ban-log-forwarder

# Check status
systemctl status nginx-log-forwarder
systemctl status fail2ban-log-forwarder

# Enable/disable auto-start
systemctl enable nginx-log-forwarder
systemctl disable nginx-log-forwarder
```

### Viewing Logs
```bash
# Last 50 lines
journalctl -u nginx-log-forwarder -n 50

# Since 1 hour ago
journalctl -u nginx-log-forwarder --since "1 hour ago"

# Follow in real-time
journalctl -u nginx-log-forwarder -f

# Show only errors
journalctl -u nginx-log-forwarder | grep "Error"

# Export to file
journalctl -u nginx-log-forwarder --since "1 day ago" > nginx-forwarder.log
```

---

## 🐛 Troubleshooting

### Service Won't Start
```bash
# Check for syntax errors
systemd-analyze verify /etc/systemd/system/nginx-log-forwarder.service

# Check permissions
ls -la /usr/local/bin/firewall-log-forwarder.py

# Should show: -rwxr-xr-x (executable)
```

### No Logs Being Sent
```bash
# Check if script can access log file
ls -la /var/log/nginx/access.log

# Test API connection manually
curl -X POST https://your-domain.com/api/v1/ingest/nginx/ \
  -H "X-API-Key: frc_your_key" \
  -H "Content-Type: application/json" \
  -d '{"log":"test","server_name":"test"}'

# Should return 200/201/202
```

### Authentication Errors (401)
```bash
# Verify API key format
echo "frc_xxxxxxxxxxxxx" | wc -c  # Should be > 30 characters

# Check Django logs for details
# On Django server:
tail -f /path/to/django/logs
```

### Script Crashes Immediately
```bash
# Run manually to see errors
python3 /usr/local/bin/firewall-log-forwarder.py

# Check Python dependencies
python3 -c "import requests; print('OK')"

# Install if missing
pip3 install requests
```

---

## 📊 Performance & Monitoring

### Resource Usage
```bash
# Check memory usage
systemctl status nginx-log-forwarder | grep Memory

# Check CPU usage
top -p $(pgrep -f firewall-log-forwarder)
```

### Log Rotation
The forwarders automatically handle log rotation. Logs are stored in journald and auto-rotated by systemd.

### Rate Limiting
If you're sending > 1000 logs/minute, consider implementing batching in the scripts.

---

## 🔒 Security Best Practices

1. **Protect API Keys**
   - Never commit API keys to git
   - Use environment variables in production
   - Rotate keys regularly

2. **Network Security**
   - Use HTTPS for API endpoints
   - Consider IP whitelisting
   - Use Cloudflare or similar CDN

3. **Log Privacy**
   - Logs may contain sensitive data
   - Review what gets forwarded
   - Implement data retention policies

4. **Access Control**
   - Limit script file permissions
   - Run as dedicated user (not root) if possible
   - Monitor for unauthorized changes

---

## 📈 Next Steps

1. **Set up Discord/Slack alerts** in Django admin
2. **Create alert rules** for critical events
3. **Monitor dashboard** at https://your-domain.com/dashboard/
4. **Review server management** at https://your-domain.com/logs/servers/

---

## 📞 Support

For issues or questions:
- Check Django admin logs
- Review systemd journal logs
- Test API endpoints manually
- Verify network connectivity

---

**Version:** 1.0  
**Last Updated:** 2025-11-18  
**Tested On:** Ubuntu 24.04, Python 3.11+
