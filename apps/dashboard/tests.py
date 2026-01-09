from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.dashboard import views as dashboard_views
from apps.logs.models import InventorySnapshot, SecurityLog, ServerAlias
from apps.organizations.models import Organization, OrganizationMember


class GeographicDataTests(TestCase):
    def test_top_countries_includes_flag(self):
        user = get_user_model().objects.create_user(
            email="user@example.com",
            username="user",
            password="password123",
        )
        org = Organization.objects.create(name="Org", slug="org")
        OrganizationMember.objects.create(organization=org, user=user, role="owner", is_active=True)

        SecurityLog.objects.create(
            organization=org,
            source_type="nginx",
            source_host="host-1",
            timestamp=timezone.now(),
            src_ip="8.8.8.8",
            action="allow",
            severity="low",
            raw_log="test",
            country_code="US",
            country_name="United States",
            latitude=37.3861,
            longitude=-122.0839,
            geo_enriched=True,
        )

        self.client.force_login(user)
        response = self.client.get(reverse("dashboard:geographic_data"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["top_countries"])
        self.assertIn("flag", payload["top_countries"][0])


class InventoryOverviewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="inventory@example.com",
            username="inventory",
            password="password123",
        )
        self.org = Organization.objects.create(name="Org A", slug="org-a")
        OrganizationMember.objects.create(
            organization=self.org,
            user=self.user,
            role="owner",
            is_active=True,
        )
        self.other_org = Organization.objects.create(name="Org B", slug="org-b")

        self.snapshot_a = InventorySnapshot.objects.create(
            organization=self.org,
            source_host="server-a",
            timestamp=timezone.now(),
            payload={"os": "Ubuntu 22.04", "kernel": "6.5.0"},
        )
        self.snapshot_b = InventorySnapshot.objects.create(
            organization=self.org,
            source_host="server-b",
            timestamp=timezone.now(),
            payload={"os": "Debian"},
        )
        InventorySnapshot.objects.create(
            organization=self.other_org,
            source_host="server-other",
            timestamp=timezone.now(),
            payload={"os": "RHEL"},
        )

        ServerAlias.objects.create(
            organization=self.org,
            original_hostname="server-a",
            display_name="Server A",
            created_by=self.user,
        )

    def test_inventory_scoped_to_org(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard:inventory_overview"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-server-name="server-a"')
        self.assertContains(response, 'data-server-name="server-b"')
        self.assertNotContains(response, 'data-server-name="server-other"')

    def test_inventory_server_filter(self):
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("dashboard:inventory_overview"),
            {"server": "server-a"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-server-name="server-a"')
        self.assertNotContains(response, 'data-server-name="server-b"')

    def test_inventory_sanitizer_redacts(self):
        payload = {
            "api_key": "frc_secret",
            "nested": {"token": "abc"},
            "jwt": "a.b.c",
            "hex": "a" * 64,
            "safe": "hello",
        }
        sanitized = dashboard_views.sanitize_inventory_payload(payload)
        self.assertEqual(sanitized["api_key"], "[redacted]")
        self.assertEqual(sanitized["nested"]["token"], "[redacted]")
        self.assertEqual(sanitized["jwt"], "[redacted]")
        self.assertEqual(sanitized["hex"], "[redacted]")
        self.assertEqual(sanitized["safe"], "hello")
