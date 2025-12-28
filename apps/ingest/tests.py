import hashlib
import hmac
import json
import time
from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from apps.ingest.authentication import TIMESTAMP_SKEW_SECONDS
from apps.organizations.models import APIKey, Organization


@override_settings(AGENT_HMAC_SECRET="test-secret")
class AgentSignatureTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org", slug="test-org")
        self.api_key_value = APIKey.generate_key()
        self.api_key = APIKey(organization=self.organization, name="Agent Key")
        self.api_key.encrypt_key(self.api_key_value)
        self.api_key.save()

        self.url = reverse("ingest:ingest_fail2ban")
        self.body_dict = {"log": "[sshd] Ban 10.0.0.1"}
        self.body = json.dumps(self.body_dict)

    def _signature(self, body: str) -> str:
        return hmac.new(b"test-secret", body.encode(), hashlib.sha256).hexdigest()

    def _headers(self, *, timestamp=None, signature=None):
        ts = timestamp if timestamp is not None else int(time.time())
        sig = signature if signature is not None else self._signature(self.body)
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.api_key_value}",
            "HTTP_X_AGENT_ID": self.api_key.key_prefix,
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
        mock_geoip_delay.assert_called()

    def test_invalid_signature(self):
        response = self.client.post(
            self.url,
            data=self.body,
            content_type="application/json",
            **self._headers(signature="bad-signature"),
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
