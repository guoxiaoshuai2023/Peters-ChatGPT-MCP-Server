import asyncio
from dataclasses import replace
import io
import logging
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.responses import JSONResponse

from peters_mcp.cloudflare import AccessMiddleware, AccessSettings, AccessVerifier


class CloudflareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.settings = AccessSettings("https://test-team.cloudflareaccess.com", "a" * 64,
                                       "mcp.example.com", ("owner@example.com",))
        self.verifier = AccessVerifier(self.settings)
        self.verifier.keys = Mock()
        self.verifier.keys.get_signing_key_from_jwt.return_value = SimpleNamespace(key=self.key.public_key())
        now = int(time.time())
        self.claims = {"iss": self.settings.team_domain, "aud": [self.settings.audience],
                       "exp": now + 300, "iat": now - 10, "sub": "test-subject",
                       "email": "owner@example.com"}

    def token(self, changes=None, key=None):
        return jwt.encode({**self.claims, **(changes or {})}, key or self.key,
                          algorithm="RS256", headers={"kid": "test-key"})

    def test_valid_signature_and_identity(self):
        self.assertEqual(self.verifier.verify(self.token())["email"], "owner@example.com")

    def test_wrong_issuer_audience_identity_expiry_and_future_issue(self):
        for change in ({"iss": "https://other.cloudflareaccess.com"}, {"aud": ["b" * 64]},
                       {"email": "stranger@example.com"}, {"exp": int(time.time()) - 60},
                       {"iat": int(time.time()) + 60}):
            with self.subTest(change=change), self.assertRaises(jwt.PyJWTError):
                self.verifier.verify(self.token(change))

    def test_wrong_signature_and_unsigned_token(self):
        for token in (self.token(key=self.other_key), jwt.encode(self.claims, key="", algorithm="none"),
                      "malformed", "x" * 17000):
            with self.subTest(kind=len(token)), self.assertRaises(jwt.PyJWTError):
                self.verifier.verify(token)

    def test_missing_required_claims(self):
        for name in self.claims:
            claims = {key: value for key, value in self.claims.items() if key != name}
            token = jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})
            with self.subTest(name=name), self.assertRaises(jwt.PyJWTError):
                self.verifier.verify(token)

    def test_configuration_rejects_untrusted_key_sources(self):
        for domain in ("http://test.cloudflareaccess.com", "https://cloudflareaccess.com.attacker.test",
                       "https://127.0.0.1", "https://test.cloudflareaccess.com/path"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                replace(self.settings, team_domain=domain)
        with self.assertRaises(ValueError):
            replace(self.settings, allowed_emails=())

    def test_middleware_rejects_missing_duplicate_and_forged_assertions(self):
        called = []
        logs = io.StringIO()
        audit = logging.Logger("test.cloudflare")
        audit.addHandler(logging.StreamHandler(logs))

        async def app(scope, receive, send):
            called.append(True)
            await JSONResponse({"ok": True})(scope, receive, send)

        middleware = AccessMiddleware(app, self.verifier, audit)

        async def run(headers):
            messages = []
            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}
            async def send(message):
                messages.append(message)
            await middleware({"type": "http", "headers": headers}, receive, send)
            return messages[0]["status"]

        valid = self.token().encode()
        for headers in ([], [(b"authorization", b"Bearer " + valid)],
                        [(b"cf-access-jwt-assertion", b"forged")],
                        [(b"cf-access-jwt-assertion", valid), (b"cf-access-jwt-assertion", valid)]):
            self.assertEqual(asyncio.run(run(headers)), 401)
        self.assertEqual(called, [])
        self.assertNotIn("forged", logs.getvalue())
        self.assertEqual(asyncio.run(run([(b"cf-access-jwt-assertion", valid)])), 200)
        self.assertEqual(called, [True])


if __name__ == "__main__":
    unittest.main()
