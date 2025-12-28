"""
Management command to enrich logs with GeoIP data (repair/backfill).
"""
import time
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from apps.logs.models import SecurityLog


class Command(BaseCommand):
    help = "Enrich logs with GeoIP data (also repairs rows missing lat/lon)"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=200, help="Maximum number of logs to process")
        parser.add_argument("--hours", type=int, default=24, help="Look back N hours (default 24)")
        parser.add_argument("--async", action="store_true", help="Use Celery for async processing")
        parser.add_argument("--force", action="store_true", help="Force re-enrich even if geo_enriched=True")

    def handle(self, *args, **options):
        limit = options["limit"]
        hours = options["hours"]
        use_async = options["async"]
        force = options["force"]

        since = timezone.now() - timedelta(hours=hours)

        # Ta:
        # - geo_enriched=False
        # - ELLER coords saknas (det är ditt case)
        logs = (
            SecurityLog.objects.filter(timestamp__gte=since)
            .filter(Q(geo_enriched=False) | Q(latitude__isnull=True) | Q(longitude__isnull=True))
            .order_by("-timestamp")[:limit]
        )

        total = logs.count()
        if total == 0:
            self.stdout.write(self.style.SUCCESS("✅ Nothing to enrich/repair in selected time window."))
            return

        self.stdout.write(f"Found {total} logs to enrich/repair (hours={hours}, force={force}, async={use_async})")

        if use_async:
            from apps.logs.tasks import enrich_log_with_geoip
            for log in logs:
                enrich_log_with_geoip.delay(str(log.id))
            self.stdout.write(self.style.SUCCESS(f"✅ Queued {total} logs for enrichment"))
            return

        from apps.logs.services.geoip import GeoIPService

        success_count = 0
        for i, log in enumerate(logs, 1):
            ok = GeoIPService.enrich_log(log, force=force)
            if ok:
                success_count += 1

            if i % 10 == 0:
                self.stdout.write(f"Processed {i}/{total} logs...")

            # Rate limiting: 45 req/min => ~1.4s per request
            time.sleep(1.5)

        self.stdout.write(self.style.SUCCESS(f"✅ Successfully enriched {success_count}/{total} logs with coords"))
