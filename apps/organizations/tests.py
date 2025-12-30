from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Agent, APIKey, Organization, OrganizationMember


class OrgSettingsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="owner@example.com",
            username="owner",
            password="password123",
        )
        self.org = Organization.objects.create(name="Alpha Org", slug="alpha-org")
        self.member = OrganizationMember.objects.create(
            organization=self.org,
            user=self.user,
            role="owner",
            is_active=True,
        )

    @mock.patch.object(APIKey, "generate_key", return_value="frc_test_key_1234567890")
    def test_api_key_shown_once(self, _mock_key):
        self.client.force_login(self.user)
        response = self.client.post(
            f"/org/settings/keys/?org={self.org.slug}",
            {"action": "create", "name": "Test Key"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "frc_test_key_1234567890")

        response = self.client.get(f"/org/settings/keys/?org={self.org.slug}")
        self.assertNotContains(response, "frc_test_key_1234567890")

    def test_non_owner_cannot_create_key(self):
        viewer = get_user_model().objects.create_user(
            email="viewer@example.com",
            username="viewer",
            password="password123",
        )
        OrganizationMember.objects.create(
            organization=self.org,
            user=viewer,
            role="analyst",
            is_active=True,
        )
        self.client.force_login(viewer)
        response = self.client.post(
            f"/org/settings/keys/?org={self.org.slug}",
            {"action": "create", "name": "Nope"},
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_secret_shown_once(self):
        self.client.force_login(self.user)
        response = self.client.post(
            f"/org/settings/agents/?org={self.org.slug}",
            {"action": "create", "agent_id": "agent-1", "metadata": "{}", "is_active": "1"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "FRC_AGENT_SECRET=")

        response = self.client.get(f"/org/settings/agents/?org={self.org.slug}")
        self.assertNotContains(response, "FRC_AGENT_SECRET=")

    def test_non_owner_cannot_create_agent(self):
        viewer = get_user_model().objects.create_user(
            email="viewer2@example.com",
            username="viewer2",
            password="password123",
        )
        OrganizationMember.objects.create(
            organization=self.org,
            user=viewer,
            role="readonly",
            is_active=True,
        )
        self.client.force_login(viewer)
        response = self.client.post(
            f"/org/settings/agents/?org={self.org.slug}",
            {"action": "create", "agent_id": "agent-2"},
        )
        self.assertEqual(response.status_code, 403)
