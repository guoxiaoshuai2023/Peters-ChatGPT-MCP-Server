import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx2
import jwt

from peters_mcp import agent_file_auth


ISSUER = "https://test-team.cloudflareaccess.com"
AUDIENCE = "a" * 64
CODEX_CREDENTIAL = "cd" * 16 + ".access"
OTHER_CREDENTIAL = "dc" * 16 + ".access"


class MachineAccessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.verifier = agent_file_auth.MachineAccessVerifier(ISSUER, AUDIENCE)
        now = int(time.time())
        self.claims = {
            "iss": ISSUER, "aud": [AUDIENCE], "exp": now + 300, "iat": now - 1,
            "sub": "", "type": "app", "common_name": CODEX_CREDENTIAL,
        }

    def verify(self, claims=None, *, headers=None):
        token = jwt.encode(
            self.claims if claims is None else claims, self.key, algorithm="RS256",
            headers=headers if headers is not None else {"kid": "test-key"},
        )
        finder = SimpleNamespace(key=self.key.public_key())
        with patch.object(self.verifier.keys, "get_signing_key_from_jwt", return_value=finder):
            return self.verifier.verify(token)

    def test_signed_machine_identity_changes_with_the_credential(self):
        self.assertEqual(self.verify().key, (ISSUER, AUDIENCE, CODEX_CREDENTIAL))
        self.assertEqual(self.verify().expires_at, self.claims["exp"])
        changed = self.verify({**self.claims, "common_name": OTHER_CREDENTIAL, "aud": AUDIENCE})
        self.assertEqual(changed.key, (ISSUER, AUDIENCE, OTHER_CREDENTIAL))

    def test_rejects_human_and_wrong_application_claims(self):
        for change in (
            {"sub": "human"},
            {"email": "same-human@example.com"},
            {"aud": ["b" * 64]},
            {"aud": ["b" * 64, AUDIENCE]},
            {"iss": "https://other-team.cloudflareaccess.com"},
            {"type": "org"},
            {"common_name": "claimed-client-name"},
        ):
            with self.subTest(changed=tuple(change)), self.assertRaises(jwt.InvalidTokenError):
                self.verify({**self.claims, **change})
        for field in ("sub", "common_name", "iss", "aud", "type", "exp", "iat"):
            claims = self.claims.copy()
            del claims[field]
            with self.subTest(missing=field), self.assertRaises(jwt.InvalidTokenError):
                self.verify(claims)

    def test_rejects_expiry_bad_time_types_and_future_assertions(self):
        for change in (
            {"exp": self.claims["iat"] - 1},
            {"iat": True},
            {"iat": str(self.claims["iat"])},
            {"exp": float(self.claims["exp"])},
            {"nbf": self.claims["exp"]},
        ):
            with self.subTest(changed=tuple(change)), self.assertRaises(jwt.InvalidTokenError):
                self.verify({**self.claims, **change})

    def test_rejects_wrong_signature_and_untrusted_key_header(self):
        token = jwt.encode(self.claims, self.key, algorithm="RS256", headers={"kid": "test-key"})
        unrelated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with patch.object(self.verifier.keys, "get_signing_key_from_jwt",
                          return_value=SimpleNamespace(key=unrelated.public_key())):
            with self.assertRaises(jwt.InvalidTokenError):
                self.verifier.verify(token)
        for field in ("jku", "jwk", "x5u", "crit"):
            with self.subTest(header=field), self.assertRaises(jwt.InvalidTokenError):
                self.verify(headers={"kid": "test-key", field: "https://untrusted.example.test"})
        with patch.object(self.verifier.keys, "get_signing_key_from_jwt") as lookup:
            with self.assertRaises(jwt.InvalidTokenError):
                self.verifier.verify(jwt.encode(self.claims, "s" * 32, algorithm="HS256",
                                                headers={"kid": "test-key"}))
            lookup.assert_not_called()

    def test_key_transport_is_pinned_and_has_no_redirect_or_proxy(self):
        keys = self.verifier.keys
        original_client = httpx2.Client
        requests = []

        def handler(request):
            requests.append(request)
            return httpx2.Response(307, headers={"Location": "https://untrusted.example.test/certs"})

        def factory(**options):
            self.assertFalse(options["trust_env"])
            self.assertFalse(options["follow_redirects"])
            return original_client(transport=httpx2.MockTransport(handler), **options)

        with patch.object(agent_file_auth.httpx2, "Client", side_effect=factory):
            with self.assertRaises(jwt.PyJWKClientConnectionError):
                keys.fetch_data()
        self.assertEqual([str(request.url) for request in requests], [ISSUER + "/cdn-cgi/access/certs"])
        self.assertNotIn("authorization", requests[0].headers)

    def test_rejects_ambiguous_jwks_key_ids_and_does_not_cache(self):
        keys = self.verifier.keys
        original_client = httpx2.Client
        data = json.dumps({"keys": [{"kid": "same"}, {"kid": "same"}]}).encode()

        def handler(_):
            return httpx2.Response(200, stream=httpx2.ByteStream(data))

        with patch.object(agent_file_auth.httpx2, "Client",
                          side_effect=lambda **options: original_client(
                              transport=httpx2.MockTransport(handler), **options)):
            with self.assertRaises(jwt.PyJWKClientConnectionError):
                keys.fetch_data()
        self.assertIsNone(keys.jwk_set_cache.get())

    def test_jwks_lookup_and_signature_verification_use_the_cached_key(self):
        original_client = httpx2.Client
        public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        public_jwk.update(kid="test-key", alg="RS256", use="sig")
        data = json.dumps({"keys": [public_jwk]}).encode()
        requests = []

        def handler(request):
            requests.append(request)
            return httpx2.Response(200, stream=httpx2.ByteStream(data))

        token = jwt.encode(self.claims, self.key, algorithm="RS256", headers={"kid": "test-key"})
        with patch.object(agent_file_auth.httpx2, "Client",
                          side_effect=lambda **options: original_client(
                              transport=httpx2.MockTransport(handler), **options)):
            for _ in range(2):
                self.assertEqual(self.verifier.verify(token).key, (ISSUER, AUDIENCE, CODEX_CREDENTIAL))
        self.assertEqual(len(requests), 1)
