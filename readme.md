# Firewall & Intrusion Report Center

Multi-tenant SaaS för centraliserad logganalys från HAProxy, Nginx, CrowdSec, Fail2ban.

## Stack
- **Backend**: Django 5 + Python 3.12 + DRF
- **Frontend**: HTMX + Tailwind CSS + Lucide icons
- **Database**: PostgreSQL 16
- **Cache/Queue**: Redis + Celery
- **Containers**: Podman + podman-compose
- **Observability**: Prometheus metrics + Sentry

## Snabbstart

```bash
# 1. Kopiera och konfigurera environment
cp .env.example .env
# Redigera .env med dina värden

# 2. Bygg och starta alla services
make up

# 3. Kör migrations och skapa superuser
make migrate
make superuser

# 4. Seed demo-data (valfritt)
make seed

# 5. Öppna http://localhost:8000
```

## Makefile kommandon

```bash
make dev          # Starta utvecklingsserver
make up           # Starta alla containers
make down         # Stoppa containers
make migrate      # Kör Django migrations
make superuser    # Skapa superuser
make seed         # Lägg in demo-data
make shell        # Django shell
make test         # Kör tester
make lint         # Linting (ruff/black)
make logs         # Visa container logs
make clean        # Rensa containers och volumes
```

## Arkitektur

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Firewalls  │────▶│ Nginx/Traefik│────▶│   Django    │
│HAProxy/etc  │     │ Reverse Proxy│     │   Web App   │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                  │
                    ┌─────────────────────────────┼────────┐
                    │                             │        │
              ┌─────▼─────┐              ┌───────▼──┐  ┌──▼──────┐
              │ PostgreSQL│              │  Redis   │  │ Celery  │
              │     DB    │              │  Cache   │  │ Workers │
              └───────────┘              └──────────┘  └─────────┘
```

## Endpoints

### API Ingest
- `POST /api/v1/ingest/haproxy/` - HAProxy logs
- `POST /api/v1/ingest/nginx/` - Nginx logs
- `POST /api/v1/ingest/crowdsec/` - CrowdSec decisions
- `POST /api/v1/ingest/fail2ban/` - Fail2ban events

### Dashboard
- `GET /dashboard/` - Main dashboard
- `GET /dashboard/attacks/` - Attack timeline
- `GET /dashboard/geo/` - Geographic view
- `GET /dashboard/export/` - Export data

### Auth
- `GET /accounts/login/` - Login
- `GET /accounts/signup/` - Signup (org creation)
- `GET /accounts/2fa/` - 2FA setup

## Multi-tenancy

Systemet använder subdomain-baserad multi-tenancy:
- `org1.example.com` → Organization 1
- `org2.example.com` → Organization 2

DNS wildcards eller Cloudflare måste konfigureras.

## Säkerhet

- ✅ Security headers (CSP, X-Frame-Options, HSTS)
- ✅ Rate limiting per org och API-token
- ✅ API-nycklar krypteras (Fernet)
- ✅ Input validation & schema
- ✅ Tenant isolation tests
- ✅ 2FA (TOTP)
- ✅ RBAC (Owner/Admin/Analyst/ReadOnly)

## Development

```bash
# Installera dependencies lokalt (för IDE)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Kör tester
make test

# Format kod
make format

# Lint
make lint
```

## Cloudflare Setup

1. Lägg till din domän i Cloudflare
2. Skapa wildcard DNS record: `*.example.com` → server IP
3. SSL/TLS: Full (strict)
4. Page Rules:
   - Cache Level: Standard för `/static/*`
   - Always Use HTTPS
5. Firewall: Rate limiting rules

## Deployment

Se [DEPLOYMENT.md](DEPLOYMENT.md) för produktionsdistribution.

## Licens

Proprietary - All rights reserved