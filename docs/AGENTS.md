# Agents

Agents authenticate to ingest endpoints using headers and HMAC signatures.

## Identity
- Each agent has a stable `agent_id` (use the API key prefix for now).
- The backend validates the agent ID exists and is active.

## Required headers
```
X-Agent-Id: <agent_id>
X-Timestamp: <unix_epoch_seconds>
X-Signature: <hex_hmac_sha256_of_raw_body>
```

The signature is `HMAC-SHA256(secret, raw_request_body)` using the shared agent secret.

## Timestamp skew
- Allowed drift is ±300 seconds.
- Requests outside the window are rejected.

## Secret strategy (recommended)
Prefer deriving per-agent secrets from a single master secret, so you avoid storing secrets in the database.

Example derivation:
```
agent_secret = HMAC-SHA256(AGENT_HMAC_MASTER_SECRET, agent_id)
```

Environment examples:
```
AGENT_HMAC_SECRET=change-me
AGENT_HMAC_MASTER_SECRET=change-me
```
