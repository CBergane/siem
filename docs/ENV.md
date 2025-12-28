# Environment Baseline

This project expects configuration via `.env` aligned with `.env.example`.

## Critical variables
- `SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS`
- `DATABASE_URL` (or `POSTGRES_DB`/`POSTGRES_USER`/`POSTGRES_PASSWORD`)
- `AGENT_HMAC_SECRET` (agent signing)
- `REQUEST_JOIN` (webhook endpoint)
- `TIME_ZONE`, `BASE_DOMAIN`, `EMAIL_BACKEND`, `DEFAULT_FROM_EMAIL`

## Forbidden placeholder values
The audit fails any value matching (case-insensitive, underscores or hyphens ignored): `CHANGE_ME`, `changeme`, `password`, `1234`.

## Permissions
Keep secrets readable only to you: run `chmod 600 .env`. The audit warns on looser permissions.

## Audit script
- Run: `python scripts/env_audit.py`
- Exit codes: `0` OK, `2` warnings (e.g., file permissions), `3` errors (missing keys, empty/unsafe values, or missing files).

## Dev flow (local)
Recommended sequence: `make up` → `make migrate` → `make superuser`. Run `make collectstatic` when needed.

Dev note: nginx is disabled in `podman-compose.yaml`, access the app at `http://localhost:8000`.
Note: For production, keep migrations/collectstatic explicit or use a dedicated prod compose file if you want auto-run steps.
