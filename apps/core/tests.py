import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.organizations.models import Organization


class HealthCheckTests(TestCase):
    def test_health_check_ok(self):
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


class RootRedirectTests(TestCase):
    def test_root_redirects_to_landing(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/landing/")


class SuperJoinRequestsTests(TestCase):
    def test_super_join_requests_forbidden_for_non_superuser(self):
        user = get_user_model().objects.create_user(
            email="user@example.com",
            username="user",
            password="password123",
        )
        self.client.force_login(user)
        response = self.client.get("/super/join-requests/")
        self.assertEqual(response.status_code, 403)

    def test_super_join_requests_ok_for_superuser(self):
        admin = get_user_model().objects.create_superuser(
            email="admin@example.com",
            username="admin",
            password="password123",
        )
        self.client.force_login(admin)
        response = self.client.get("/super/join-requests/")
        self.assertEqual(response.status_code, 200)


class SuperuserNavLinkTests(TestCase):
    def test_super_link_visible_for_superuser_only(self):
        admin = get_user_model().objects.create_superuser(
            email="admin@example.com",
            username="admin",
            password="password123",
        )
        self.client.force_login(admin)
        response = self.client.get("/dashboard/")
        self.assertContains(response, "/super/join-requests/")

        user = get_user_model().objects.create_user(
            email="user@example.com",
            username="user",
            password="password123",
        )
        self.client.force_login(user)
        response = self.client.get("/dashboard/")
        self.assertNotContains(response, "/super/join-requests/")


class JoinRequestNotificationTests(TestCase):
    @override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
    @mock.patch("apps.core.views.requests.post")
    def test_notify_discord_called_when_enabled(self, mock_post):
        mock_post.return_value.status_code = 204
        with mock.patch.dict(
            os.environ,
            {"ENABLE_DISCORD_NOTIFICATIONS": "true", "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1443243068559200337/9jl8IctoAgIEBKYpFwlOynaXaYWL2ESZVV3B4GuZN64YVx1jBty0h3vBDJmAM4U3VBUO"},
            clear=False,
        ):
            response = self.client.post(
                "/request-join/",
                {
                    "email": "new@example.com",
                    "full_name": "New User",
                    "company": "Acme",
                    "message": "Please add me",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(mock_post.called)


class SuperTenantsTests(TestCase):
    def test_super_tenants_access_and_rows(self):
        admin = get_user_model().objects.create_superuser(
            email="admin@example.com",
            username="admin",
            password="password123",
        )
        self.client.force_login(admin)
        org = Organization.objects.create(name="Alpha Org", slug="alpha-org")
        response = self.client.get("/super/tenants/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, org.name)
        self.assertContains(response, "Allowed servers: 2")

    def test_super_tenants_forbidden_for_non_superuser(self):
        user = get_user_model().objects.create_user(
            email="user@example.com",
            username="user",
            password="password123",
        )
        self.client.force_login(user)
        response = self.client.get("/super/tenants/")
        self.assertEqual(response.status_code, 403)
