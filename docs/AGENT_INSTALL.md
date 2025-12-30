# Agent Install (Service Inventory)

Minimal agent for posting systemd service inventory to the ingest endpoint.

## Prereqs
- `curl`
- `openssl`
- `systemctl` (systemd)

## Create credentials
1) In the app, go to `/org/settings/keys/` and create an API key.
2) Go to `/org/settings/agents/` and create an agent ID.

## Install the script
```bash
sudo install -m 0755 scripts/agent/frc-agent-services /usr/local/bin/frc-agent-services
```

## Environment file
Create `/etc/frc-agent.env` (600 permissions):
```bash
sudo sh -c 'cat > /etc/frc-agent.env <<EOF
FRC_URL=https://your-domain.example
FRC_API_KEY=frc_your_api_key_here
FRC_AGENT_ID=agent-1
FRC_AGENT_SECRET=your_agent_secret
# Optional: comma-separated allowlist
# FRC_ALLOWLIST=sshd.service,nginx.service
EOF'
sudo chmod 600 /etc/frc-agent.env
```

## Systemd unit + timer
```bash
sudo install -m 0644 scripts/agent/frc-agent.service /etc/systemd/system/frc-agent.service
sudo install -m 0644 scripts/agent/frc-agent.timer /etc/systemd/system/frc-agent.timer
sudo useradd -r -s /usr/sbin/nologin frc-agent || true
sudo systemctl daemon-reload
sudo systemctl enable --now frc-agent.timer
```

## Troubleshooting
- Logs: `journalctl -u frc-agent.service -n 50 --no-pager`
- Manual run: `FRC_DRY_RUN=1 /usr/local/bin/frc-agent-services`
- Expect HTTP 202 from the server.

## Notes
- HTTPS is recommended for real deployments.
- Cloudflare Tunnel is OK for dev.
