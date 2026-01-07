from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.logs.models import SecurityLog
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
