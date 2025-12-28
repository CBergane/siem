# Backlog

## P0 - Security baseline (Done)
- [x] Add `.env.example` + `docs/ENV.md`
- [x] Add `scripts/env_audit.py`
  - [x] Validates `.env` vs `.env.example`
  - [x] Detects unsafe placeholder values
  - [x] Checks `.env` permissions (600 recommended)
- [x] Ensure `.env` is ignored by git
- [x] Ensure compose requires POSTGRES_PASSWORD (no `changeme` default)

## P1 - Agent ingest security
- [x] Define ingest auth headers:
  - X-Agent-Id, X-Timestamp, X-Signature (HMAC-SHA256)
- [x] Backend verifies signature + timestamp skew
- [x] Add request size limit + rate limiting plan (doc)
- [x] Verify ingest HMAC startup & basic behavior
- [ ] Add `/health` endpoint
- [ ] Align app healthcheck config with `/health`
- [ ] Avoid auto-migrate race on startup
- [ ] Tenant/agent registry docs-first; prefer master-secret derivation for agent secrets

## P2 - Service inventory
- [ ] Agent module collects systemd services (basic)
- [ ] Event schema `service_inventory` stored in DB
- [ ] UI page lists services per host (basic)

## P3 - Ops / reliability
- [ ] Agent retry + exponential backoff
- [ ] Optional spool queue on disk
