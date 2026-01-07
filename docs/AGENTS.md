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

## Secret strategy
Agents use per-agent secrets generated in the org settings UI. The secret is shown once on create/rotate and stored encrypted.

Environment example (agent side):
```
FRC_AGENT_SECRET=change-me
```
