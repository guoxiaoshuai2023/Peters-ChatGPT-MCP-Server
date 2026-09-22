import asyncio
from dataclasses import replace
import io
import json
import logging
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

import anyio
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from starlette.responses import JSONResponse

from peters_mcp.cloudflare import AccessMiddleware, AccessSettings, AccessVerifier
from peters_mcp.audit import audit_request_id


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

    async def request(self, middleware, token):
        messages = []
        async def receive():
            return {"type": "http.request", "body": b"private-document-marker", "more_body": False}
        async def send(message):
            messages.append(message)
        await middleware({"type": "http", "headers": [
            (b"cf-access-jwt-assertion", token.encode()),
            (b"x-request-id", b"untrusted-client-request-id"),
        ]}, receive, send)
        return messages

    def test_key_network_errors_are_retryable_without_access_or_sensitive_logs(self):
        for failure in (jwt.PyJWKClientConnectionError("private-network-error-marker"),
                        OSError("private-network-error-marker")):
            with self.subTest(failure=type(failure).__name__):
                verifier = Mock()
                verifier.verify.side_effect = failure
                called = []
                logs = io.StringIO()
                audit = logging.Logger("test.cloudflare.unavailable")
                audit.addHandler(logging.StreamHandler(logs))
                async def app(scope, receive, send):
                    called.append(True)
                token = self.token()
                messages = asyncio.run(self.request(AccessMiddleware(app, verifier, audit), token))
                self.assertEqual(messages[0]["status"], 503)
                headers = dict(messages[0]["headers"])
                self.assertEqual(headers[b"retry-after"], b"5")
                self.assertEqual(headers[b"cache-control"], b"no-store")
                self.assertNotIn(b"www-authenticate", headers)
                self.assertEqual(json.loads(messages[1]["body"])["code"], "authentication_unavailable")
                self.assertEqual(called, [])
                record = json.loads(logs.getvalue())
                self.assertEqual(set(record), {"time", "event", "request_id", "ok", "error_code",
                                               "status_code", "elapsed_ms"})
                self.assertEqual(record["error_code"], "authentication_unavailable")
                self.assertEqual(record["status_code"], 503)
                self.assertFalse(record["ok"])
                self.assertEqual(record["request_id"].encode(), headers[b"x-request-id"])
                self.assertGreaterEqual(record["elapsed_ms"], 0)
                exposed = logs.getvalue() + str(messages)
                for private in (token, "owner@example.com", "private-document-marker",
                                "private-network-error-marker", "untrusted-client-request-id"):
                    self.assertNotIn(private, exposed)
                self.assertIsNone(audit_request_id.get())

    def test_actual_jwk_fetch_failure_is_503_but_unknown_key_is_401(self):
        verifier = AccessVerifier(self.settings)
        called = []
        async def app(scope, receive, send):
            called.append(True)
        middleware = AccessMiddleware(app, verifier)
        opener = Mock()
        opener.open.side_effect = URLError("synthetic network failure")
        with patch("jwt.jwks_client.urllib.request.build_opener", return_value=opener):
            messages = asyncio.run(self.request(middleware, self.token()))
        self.assertEqual(messages[0]["status"], 503)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="different-key", use="sig", alg="RS256")
        with patch.object(verifier.keys, "fetch_data", return_value={"keys": [jwk]}):
            messages = asyncio.run(self.request(middleware, self.token()))
        self.assertEqual(messages[0]["status"], 401)
        self.assertNotIn(b"retry-after", dict(messages[0]["headers"]))
        self.assertEqual(called, [])

    def test_expired_bad_signature_and_identity_remain_401(self):
        async def app(scope, receive, send):
            self.fail("Denied assertions must not execute the app")
        middleware = AccessMiddleware(app, self.verifier)
        for token in (self.token({"exp": int(time.time()) - 60}),
                      self.token({"email": "stranger@example.com"}),
                      self.token(key=self.other_key), "malformed"):
            messages = asyncio.run(self.request(middleware, token))
            self.assertEqual(messages[0]["status"], 401)
            self.assertEqual(json.loads(messages[1]["body"])["code"], "authentication_required")
            self.assertNotIn(b"retry-after", dict(messages[0]["headers"]))

    def public_jwk(self, **changes):
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {**jwk, "kid": "test-key", "use": "sig", "alg": "RS256", **changes}

    def test_malformed_or_unusable_key_sources_are_retryable_and_private(self):
        sources = [
            b"private-source-marker: not JSON", b"\xff", b"[]", b"null",
            {}, {"keys": "private-source-marker"}, {"keys": []}, {"keys": [None]},
            {"keys": [{"kty": "unsupported", "private": "private-source-marker"}]},
            {"keys": [self.public_jwk(n="")]},
            {"keys": [self.public_jwk(use="enc")]},
            {"keys": [self.public_jwk(kid=None)]},
        ]
        for source in sources:
            with self.subTest(source=source):
                verifier = AccessVerifier(self.settings)
                logs = io.StringIO()
                audit = logging.Logger("test.cloudflare.key-source")
                audit.addHandler(logging.StreamHandler(logs))
                async def app(scope, receive, send):
                    self.fail("Unusable key source must not execute the app")
                raw = source if isinstance(source, bytes) else json.dumps(source).encode()
                opener = Mock()
                opener.open.return_value = io.BytesIO(raw)
                with patch("jwt.jwks_client.urllib.request.build_opener", return_value=opener):
                    messages = asyncio.run(self.request(AccessMiddleware(app, verifier, audit), self.token()))
                self.assertEqual(messages[0]["status"], 503)
                headers = dict(messages[0]["headers"])
                self.assertEqual(headers[b"retry-after"], b"5")
                self.assertEqual(headers[b"cache-control"], b"no-store")
                self.assertNotIn(b"www-authenticate", headers)
                self.assertEqual(json.loads(messages[1]["body"])["code"], "authentication_unavailable")
                record = json.loads(logs.getvalue())
                self.assertEqual(record["error_code"], "authentication_unavailable")
                self.assertEqual(record["request_id"].encode(), headers[b"x-request-id"])
                self.assertNotIn("private-source-marker", logs.getvalue() + str(messages))

    def test_invalid_key_cache_recovers_without_serving_expired_keys(self):
        verifier = AccessVerifier(self.settings)
        called = []
        async def app(scope, receive, send):
            called.append(True)
            await JSONResponse({"ok": True})(scope, receive, send)
        middleware = AccessMiddleware(app, verifier)
        valid = json.dumps({"keys": [self.public_jwk()]}).encode()
        opener = Mock()
        opener.open.side_effect = [io.BytesIO(b'{"keys": []}'), io.BytesIO(valid),
                                   URLError("synthetic outage")]
        with patch("jwt.jwks_client.urllib.request.build_opener", return_value=opener):
            self.assertEqual(asyncio.run(self.request(middleware, self.token()))[0]["status"], 503)
            self.assertEqual(asyncio.run(self.request(middleware, self.token()))[0]["status"], 200)
            self.assertEqual(asyncio.run(self.request(middleware, self.token()))[0]["status"], 200)
            self.assertEqual(opener.open.call_count, 2)
            self.assertEqual(verifier.keys.jwk_set_cache.lifespan, 300)
            with patch.object(verifier.keys.jwk_set_cache, "is_expired", return_value=True):
                self.assertEqual(asyncio.run(self.request(middleware, self.token()))[0]["status"], 503)
        self.assertEqual(len(called), 2)

    def test_real_key_source_preserves_token_rejections(self):
        verifier = AccessVerifier(self.settings)
        async def app(scope, receive, send):
            self.fail("Invalid token must not execute the app")
        middleware = AccessMiddleware(app, verifier)
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps({"keys": [self.public_jwk()]}).encode())
        tokens = [self.token(key=self.other_key), self.token({"exp": int(time.time()) - 60}),
                  self.token({"email": "stranger@example.com"}), "malformed",
                  jwt.encode(self.claims, self.key, algorithm="RS256", headers={"kid": "unknown-key"})]
        with patch("jwt.jwks_client.urllib.request.build_opener", return_value=opener):
            for token in tokens:
                messages = asyncio.run(self.request(middleware, token))
                self.assertEqual(messages[0]["status"], 401)
                self.assertEqual(json.loads(messages[1]["body"])["code"], "authentication_required")
                self.assertNotIn(b"retry-after", dict(messages[0]["headers"]))

    def test_request_ids_are_isolated_propagated_to_workers_and_reset(self):
        seen = []
        logs = io.StringIO()
        audit = logging.Logger("test.cloudflare.requests")
        audit.addHandler(logging.StreamHandler(logs))
        async def app(scope, receive, send):
            request_id = audit_request_id.get()
            await asyncio.sleep(0)
            worker_id = await anyio.to_thread.run_sync(audit_request_id.get)
            seen.append((request_id, worker_id))
            await JSONResponse({"ok": True}, headers={"X-Request-ID": "do-not-reuse"})(scope, receive, send)
        middleware = AccessMiddleware(app, self.verifier, audit)
        token = self.token()
        async def run():
            parent = audit_request_id.set("parent-context")
            try:
                result = await asyncio.gather(self.request(middleware, token), self.request(middleware, token))
                result.append(await self.request(middleware, token))
                self.assertEqual(audit_request_id.get(), "parent-context")
                return result
            finally:
                audit_request_id.reset(parent)
        messages = asyncio.run(run())
        ids = [dict(response[0]["headers"])[b"x-request-id"].decode() for response in messages]
        self.assertEqual(len(set(ids)), 3)
        self.assertEqual({item[0] for item in seen}, set(ids))
        self.assertTrue(all(request_id == worker_id for request_id, worker_id in seen))
        for record in map(json.loads, logs.getvalue().splitlines()):
            self.assertTrue(record["ok"])
            self.assertEqual(record["status_code"], 200)
            self.assertIsNone(record["error_code"])
        self.assertIsNone(audit_request_id.get())

    def test_unexpected_verifier_error_is_not_logged_as_success(self):
        verifier = Mock()
        verifier.verify.side_effect = RuntimeError("private-exception-marker")
        logs = io.StringIO()
        audit = logging.Logger("test.cloudflare.internal")
        audit.addHandler(logging.StreamHandler(logs))
        async def app(scope, receive, send):
            self.fail("Verification failure must not execute the app")
        messages = asyncio.run(self.request(AccessMiddleware(app, verifier, audit), self.token()))
        self.assertEqual(messages[0]["status"], 500)
        headers = dict(messages[0]["headers"])
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertNotIn(b"www-authenticate", headers)
        body = json.loads(messages[1]["body"])
        self.assertEqual(body["code"], "authentication_internal_error")
        self.assertNotIn("authentication required", body["error"])
        record = json.loads(logs.getvalue())
        self.assertFalse(record["ok"])
        self.assertEqual(record["error_code"], "authentication_internal_error")
        self.assertEqual(record["status_code"], 500)
        self.assertEqual(record["request_id"].encode(), headers[b"x-request-id"])
        self.assertNotIn("private-exception-marker", logs.getvalue() + str(messages))
        self.assertIsNone(audit_request_id.get())


if __name__ == "__main__":
    unittest.main()
