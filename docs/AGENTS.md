# Agents

Agents authenticate to ingest endpoints using headers and HMAC signatures.

## Identity
- Each agent has a stable `agent_id` (created in Org Settings).
- The backend validates the agent ID exists and is active.

## Required headers
```
X-Agent-Id: <agent_id>
X-Timestamp: <unix_epoch_seconds>
X-Signature: <hex_hmac_sha256_of_raw_body>
```

The signature is `HMAC-SHA256(secret, raw_request_body)` using the per-agent secret.

## Timestamp skew
- Allowed drift is ±300 seconds.
- Requests outside the window are rejected.

## Secret strategy
Agents use per-agent secrets generated in the org settings UI. The secret is shown once on create/rotate and stored encrypted.

Environment example (agent side):
```
FRC_AGENT_SECRET=change-me
```

## Install (systemd + bash)
Prereqs: `curl`, `openssl`, `python3`, `systemctl`.

1) Create an API key: `/org/settings/keys/`
2) Create an agent ID + secret: `/org/settings/agents/`
3) Run the installer on the server:
```
sudo FRC_URL=https://your-domain.example \
  FRC_API_KEY=frc_your_api_key_here \
  FRC_AGENT_ID=agent-1 \
  FRC_AGENT_SECRET=your_agent_secret \
  ENABLE_NGINX_AGENT=1 \
  ENABLE_FAIL2BAN_AGENT=1 \
  ENABLE_INVENTORY_AGENT=1 \
  ./scripts/install_agent.sh
```

This writes `/etc/frc-agent.env` (0600), installs scripts to `/usr/local/bin`, and installs systemd units.

## Install via UI
Use the in-app guide at `/dashboard/agents/install/` for copy/paste commands, verification, and troubleshooting.

## Inventory UI
Inventory snapshots are visible at Dashboard > Servers > Inventory. The UI shows a summary and a sanitized raw JSON view with secrets redacted.
Inventory collection is enabled by running `scripts/install_agent.sh` with `ENABLE_INVENTORY_AGENT=1`.
The inventory timer runs hourly by default; override it with a systemd drop-in if you need a different interval:
```
sudo systemctl edit frc-inventory.timer
# Add:
[Timer]
OnUnitActiveSec=30min
```

## Retention
Inventory snapshots older than 30 days are pruned by a daily Celery beat task. You can also run:
```
python manage.py prune_inventory_snapshots --days 30
```

## Permissions and log paths
- Nginx log tailer: `/var/log/nginx/access.log` (override with `FRC_NGINX_LOG_PATH`)
- Fail2ban tailer: `/var/log/fail2ban.log` (override with `FRC_FAIL2BAN_LOG_PATH`) or journald (`journalctl -fu fail2ban`)
- Ensure the `frc-agent` user can read log files (e.g., add to `adm` group where needed).

## Verify
```
systemctl status frc-nginx.service
systemctl status frc-fail2ban.service
systemctl status frc-inventory.timer
journalctl -u frc-inventory.service -n 50 --no-pager
```

Quick curl test (inventory endpoint):
```
body='{"server_name":"test","timestamp":'"$(date +%s)"',"payload":{"hostname":"test"}}'
sig="$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$FRC_AGENT_SECRET" -hex | awk '{print $2}')"
curl -sS -H "Content-Type: application/json" \
  -H "X-API-Key: $FRC_API_KEY" \
  -H "X-Agent-Id: $FRC_AGENT_ID" \
  -H "X-Timestamp: $(date +%s)" \
  -H "X-Signature: $sig" \
  --data-binary "$body" \
  "$FRC_URL/api/v1/ingest/inventory/"
```

## Troubleshooting
- HTTP 400: missing headers or invalid JSON.
- HTTP 401: invalid signature or timestamp skew.
- HTTP 403: agent inactive or wrong org.
- HTTP 500: server-side error; check app logs.
- Check env file permissions: `ls -l /etc/frc-agent.env` (should be 600).
