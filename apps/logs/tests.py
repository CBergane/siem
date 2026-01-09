from datetime import timedelta
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.logs.models import InventorySnapshot, SecurityLog
from apps.logs.tasks import prune_inventory_snapshots
from apps.organizations.models import Organization


@override_settings(ENABLE_GEO_LOOKUP=True)
class GeoIPEnrichmentTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

    @mock.patch("apps.logs.tasks.enrich_log_with_geoip.delay", side_effect=Exception("no celery"))
    @mock.patch("apps.logs.services.geoip.GeoIPService.lookup")
    def test_auto_enrich_sync_fallback(self, mock_lookup, _mock_delay):
        mock_lookup.return_value = {
            "country_code": "US",
            "country_name": "United States",
            "city": "Mountain View",
            "region": "California",
            "latitude": 37.3861,
            "longitude": -122.0839,
            "timezone": "America/Los_Angeles",
            "asn": "AS15169",
            "isp": "Google",
            "org": "Google LLC",
        }

        log = SecurityLog.objects.create(
            organization=self.org,
            source_type="nginx",
            source_host="host-1",
            timestamp=timezone.now(),
            src_ip="8.8.8.8",
            action="allow",
            severity="low",
            raw_log="test",
        )

        log.refresh_from_db()
        self.assertTrue(log.geo_enriched)
        self.assertEqual(log.country_code, "US")
        self.assertEqual(log.city, "Mountain View")
        self.assertIsNotNone(log.latitude)

    @mock.patch("apps.logs.tasks.enrich_log_with_geoip.delay")
    def test_auto_enrich_queues_task(self, mock_delay):
        log = SecurityLog.objects.create(
            organization=self.org,
            source_type="nginx",
            source_host="host-1",
            timestamp=timezone.now(),
            src_ip="8.8.8.8",
            action="allow",
            severity="low",
            raw_log="test",
        )

        mock_delay.assert_called_with(str(log.id))


class InventoryPruneTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

    def test_prune_inventory_snapshots(self):
        old_snapshot = InventorySnapshot.objects.create(
            organization=self.org,
            source_host="server-a",
            timestamp=timezone.now(),
            payload={"os": "Ubuntu"},
        )
        InventorySnapshot.objects.filter(id=old_snapshot.id).update(
            created_at=timezone.now() - timedelta(days=31)
        )
        InventorySnapshot.objects.create(
            organization=self.org,
            source_host="server-a",
            timestamp=timezone.now(),
            payload={"os": "Ubuntu"},
        )

        deleted = prune_inventory_snapshots(days=30)
        self.assertGreaterEqual(deleted, 1)
        self.assertEqual(InventorySnapshot.objects.count(), 1)
