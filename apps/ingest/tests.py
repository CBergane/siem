import hashlib
import hmac
import json
import time
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from apps.ingest.authentication import TIMESTAMP_SKEW_SECONDS
from apps.logs.models import ServiceSnapshot, InventorySnapshot
from apps.organizations.models import APIKey, Agent, Organization


class AgentSignatureTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org", slug="test-org")
        self.api_key_value = APIKey.generate_key()
        self.api_key = APIKey(organization=self.organization, name="Agent Key")
        self.api_key.encrypt_key(self.api_key_value)
        self.api_key.save()
        self.agent_secret = Agent.generate_secret()
        self.agent = Agent(
            agent_id="agent-1",
            organization=self.organization,
            is_active=True,
        )
        self.agent.set_secret(self.agent_secret)
        self.agent.save()

        self.url = reverse("ingest:ingest_fail2ban")
        self.body_dict = {"log": "[sshd] Ban 10.0.0.1"}
        self.body = json.dumps(self.body_dict)

    def _signature(self, body: str) -> str:
        return hmac.new(self.agent_secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    def _headers(self, *, timestamp=None, signature=None, agent_id=None):
        ts = timestamp if timestamp is not None else int(time.time())
        sig = signature if signature is not None else self._signature(self.body)
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.api_key_value}",
            "HTTP_X_AGENT_ID": agent_id or self.agent.agent_id,
            "HTTP_X_TIMESTAMP": str(ts),
            "HTTP_X_SIGNATURE": sig,
        }

    @mock.patch("apps.ingest.views.enrich_log_with_geoip.delay")
    def test_valid_request(self, mock_geoip_delay):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(),
        )
        self.assertEqual(response.status_code, 202)
        self.agent.refresh_from_db()
        self.assertIsNotNone(self.agent.last_seen_at)
        mock_geoip_delay.assert_called()

    def test_unknown_agent(self):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(agent_id="missing-agent"),
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_wrong_org(self):
        other_org = Organization.objects.create(name="Other Org", slug="other-org")
        other_agent = Agent.objects.create(
            agent_id="agent-other",
            organization=other_org,
            is_active=True,
        )
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(agent_id=other_agent.agent_id),
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_inactive(self):
        self.agent.is_active = False
        self.agent.save(update_fields=["is_active"])
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(),
        )
        self.assertEqual(response.status_code, 403)

    def test_invalid_signature(self):
        bad_signature = hmac.new(b"wrong-secret", self.body.encode(), hashlib.sha256).hexdigest()
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(signature=bad_signature),
        )
        self.assertEqual(response.status_code, 401)

    def test_expired_timestamp(self):
        old_ts = int(time.time()) - (TIMESTAMP_SKEW_SECONDS + 10)
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(timestamp=old_ts),
        )
        self.assertEqual(response.status_code, 401)


class ServiceInventoryTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org", slug="test-org")
        self.api_key_value = APIKey.generate_key()
        self.api_key = APIKey(organization=self.organization, name="Agent Key")
        self.api_key.encrypt_key(self.api_key_value)
        self.api_key.save()
        self.agent_secret = Agent.generate_secret()
        self.agent = Agent(
            agent_id="agent-1",
            organization=self.organization,
            is_active=True,
        )
        self.agent.set_secret(self.agent_secret)
        self.agent.save()

        self.url = reverse("ingest:ingest_service_inventory")
        self.body_dict = {
            "server_name": "host-01",
            "services": [{"name": "ssh.service", "state": "active", "enabled": True}],
        }
        self.body = json.dumps(self.body_dict)

    def _signature(self, body: str) -> str:
        return hmac.new(self.agent_secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    def _headers(self, body: str):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.api_key_value}",
            "HTTP_X_AGENT_ID": self.agent.agent_id,
            "HTTP_X_TIMESTAMP": str(int(time.time())),
            "HTTP_X_SIGNATURE": self._signature(body),
        }

    def test_missing_services(self):
        body = json.dumps({"server_name": "host-01"})
        response = self.client.post(
            self.url,
            data=body,
            content_type="application/json",
            **self._headers(body),
        )
        self.assertEqual(response.status_code, 400)

    def test_invalid_auth(self):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_valid_inventory(self):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(self.body),
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(ServiceSnapshot.objects.count(), 1)


class InventorySnapshotTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org", slug="test-org")
        self.api_key_value = APIKey.generate_key()
        self.api_key = APIKey(organization=self.organization, name="Agent Key")
        self.api_key.encrypt_key(self.api_key_value)
        self.api_key.save()
        self.agent_secret = Agent.generate_secret()
        self.agent = Agent(
            agent_id="agent-1",
            organization=self.organization,
            is_active=True,
        )
        self.agent.set_secret(self.agent_secret)
        self.agent.save()

        self.url = reverse("ingest:ingest_inventory")
        self.body_dict = {
            "server_name": "host-01",
            "payload": {"os": "Ubuntu", "kernel": "6.8.0", "uptime_seconds": 120},
        }
        self.body = json.dumps(self.body_dict)

    def _signature(self, body: str) -> str:
        return hmac.new(self.agent_secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    def _headers(self, body: str):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.api_key_value}",
            "HTTP_X_AGENT_ID": self.agent.agent_id,
            "HTTP_X_TIMESTAMP": str(int(time.time())),
            "HTTP_X_SIGNATURE": self._signature(body),
        }

    def test_invalid_auth(self):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_valid_inventory(self):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(self.body),
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(InventorySnapshot.objects.count(), 1)
