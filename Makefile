.PHONY: help up down restart build migrate superuser seed shell test lint format logs clean dev env-check

help:
	@echo "Firewall Report Center - Makefile commands"
	@echo ""
	@echo "  make up          - Start all containers"
	@echo "  make down        - Stop all containers"
	@echo "  make restart     - Restart all containers"
	@echo "  make build       - Build containers"
	@echo "  make migrate     - Run Django migrations"
	@echo "  make superuser   - Create Django superuser"
	@echo "  make seed        - Load demo data"
	@echo "  make shell       - Django shell"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run linters"
	@echo "  make format      - Format code"
	@echo "  make logs        - Show container logs"
	@echo "  make clean       - Remove containers and volumes"
	@echo "  make dev         - Start development server"
	@echo "  make env-check   - Audit .env against .env.example"

up:
	podman-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Services started! Access at http://localhost:8000"

down:
	podman-compose down

restart: down up

build:
	podman-compose build

migrate:
	podman-compose exec web python manage.py migrate

makemigrations:
	podman-compose exec web python manage.py makemigrations

superuser:
	podman-compose exec web python manage.py createsuperuser

seed:
	podman-compose exec web python manage.py seed_data

shell:
	podman-compose exec web python manage.py shell

test:
	podman-compose exec web python manage.py test

lint:
	podman-compose exec web ruff check .
	podman-compose exec web black --check .

format:
	podman-compose exec web black .
	podman-compose exec web ruff check --fix .

logs:
	podman-compose logs -f

logs-web:
	podman-compose logs -f web

logs-worker:
	podman-compose logs -f celery-worker

clean:
	podman-compose down -v
	@echo "All containers and volumes removed"

dev:
	podman-compose up web

collectstatic:
	podman-compose exec web python manage.py collectstatic --noinput

env-check:
	python scripts/env_audit.py

# Local development without containers
local-install:
	python -m venv venv
	./venv/bin/pip install -r requirements.txt

local-dev:
	./venv/bin/python manage.py runserver 0.0.0.0:8000

# Database operations
db-backup:
	podman-compose exec postgres pg_dump -U firewall_user firewall_db > backup_$$(date +%Y%m%d_%H%M%S).sql

db-restore:
	@read -p "Enter backup file: " backup; \
	podman-compose exec -T postgres psql -U firewall_user firewall_db < $$backup
