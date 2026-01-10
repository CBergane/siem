# --- Stage 1: build Tailwind assets ---
FROM node:20-slim AS assets
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

# Copy only what Tailwind needs
COPY tailwind.config.* postcss.config.* ./
COPY templates ./templates
COPY apps ./apps
COPY static ./static

RUN npm run build


# --- Stage 2: Python runtime ---
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client gcc python3-dev musl-dev libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy built static (includes dist/app.css etc)
COPY --from=assets /app/static /app/static

RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/staticfiles /app/media /app/logs && \
    chown -R appuser:appuser /app

USER appuser

RUN python manage.py collectstatic --noinput --clear || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/health/ || exit 1

EXPOSE 8000
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120"]
