"""Synthetic verified read identities, fixed expiry, and request context isolation."""
import asyncio
from dataclasses import FrozenInstanceError
import time
import unittest
from unittest.mock import patch

from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.responses import JSONResponse

from peters_mcp.catalog import AccessError
from peters_mcp.cloudflare import AccessMiddleware
from peters_mcp.file_context import (
    ExportActor, actor_digest, current_export_actor, current_file_actor,
    export_actor_from_verified, verified_export_actor, verified_file_actor,
)


ISSUER = 'https://synthetic-issuer.example.test'


def sdk_user(subject='first-owner', *, issuer=ISSUER, expires_at=None, client_id='shared-client'):
    token = AccessToken(token='synthetic-not-a-credential', client_id=client_id,
                        scopes=['files:read'], subject=subject, claims={'iss': issuer},
                        expires_at=int(time.time()) + 300 if expires_at is None else expires_at)
    return AuthenticatedUser(token)


async def request(app, *, user=None, subject='first-owner'):
    messages = []

    async def receive():
        return {'type': 'http.request', 'body': b'', 'more_body': False}

    async def send(message):
        messages.append(message)

    scope = {'type': 'http', 'method': 'POST', 'path': '/mcp', 'user': user,
             'headers': [(b'cf-access-jwt-assertion', subject.encode()),
                         (b'x-actor', b'untrusted-owner')]}
    await app(scope, receive, send)
    return messages


class ExportContextTests(unittest.TestCase):
    def setUp(self):
        for variable in (verified_export_actor, verified_file_actor, auth_context_var):
            token = variable.set(None)
            self.addCleanup(variable.reset, token)

    def assert_authentication_required(self, operation):
        with self.assertRaises(AccessError) as caught:
            operation()
        self.assertEqual(caught.exception.code, 'authentication_required')

    def test_factory_captures_frozen_identity_and_both_fixed_expiry_clocks(self):
        wall_now, monotonic_now = time.time(), time.monotonic()
        expiry = wall_now + 300
        with patch('peters_mcp.file_context.time.time', return_value=wall_now), \
                patch('peters_mcp.file_context.time.monotonic', return_value=monotonic_now):
            actor = export_actor_from_verified(ISSUER, 'first-owner', expiry)
        self.assertEqual(actor.key, actor_digest(ISSUER, 'first-owner'))
        self.assertEqual(actor.expires_at, expiry)
        self.assertEqual(actor.deadline, monotonic_now + 300)
        actor.check(wall_clock=lambda: expiry - 1, monotonic=lambda: actor.deadline - 1)
        self.assert_authentication_required(
            lambda: actor.check(wall_clock=lambda: expiry, monotonic=lambda: actor.deadline - 1))
        # A wall-clock rollback cannot extend the captured monotonic deadline.
        self.assert_authentication_required(
            lambda: actor.check(wall_clock=lambda: wall_now - 100, monotonic=lambda: actor.deadline))
        with self.assertRaises(FrozenInstanceError):
            actor.deadline = 900

    def test_nonfinite_unbounded_or_malformed_expiry_is_refused(self):
        for expiry in (None, True, '1300', float('inf'), -float('inf'), float('nan'), 10 ** 1000):
            with self.subTest(expiry=type(expiry).__name__):
                self.assert_authentication_required(
                    lambda: export_actor_from_verified(ISSUER, 'first-owner', expiry))
        valid_key = actor_digest(ISSUER, 'first-owner')
        for expiry, deadline in ((float('inf'), 500), (1300, float('nan')),
                                 (1300, True), (True, 500), (1300, '500')):
            with self.subTest(expiry=expiry, deadline=deadline):
                self.assert_authentication_required(
                    lambda: ExportActor(valid_key, expiry, deadline).check(
                        wall_clock=lambda: 1000, monotonic=lambda: 200))
        for key in ('', 'A' * 64, 'g' * 64, 'a' * 63, None):
            with self.subTest(key=key):
                self.assert_authentication_required(
                    lambda: ExportActor(key, 1300, 500).check(
                        wall_clock=lambda: 1000, monotonic=lambda: 200))

    def test_no_read_actor_does_not_adopt_existing_write_actor(self):
        verified_file_actor.set(actor_digest(ISSUER, 'write-only-owner'))
        self.assert_authentication_required(current_export_actor)

    def test_sdk_uses_verified_owner_and_issuer_instead_of_client_id(self):
        async def run():
            seen = []

            async def app(scope, receive, send):
                actor = current_export_actor()
                seen.append(actor.key)
                self.assertGreater(actor.expires_at, time.time())
                await JSONResponse({'ok': True})(scope, receive, send)

            wrapped = AuthContextMiddleware(app)
            for user in (sdk_user('first-owner'), sdk_user('second-owner'),
                         sdk_user('first-owner', client_id='another-client'),
                         sdk_user('first-owner', issuer='https://another-issuer.example.test')):
                await request(wrapped, user=user)
                self.assertIsNone(auth_context_var.get())
                self.assert_authentication_required(current_export_actor)
            self.assertNotEqual(seen[0], seen[1])
            self.assertEqual(seen[0], seen[2])
            self.assertNotEqual(seen[0], seen[3])

        asyncio.run(run())

    def test_sdk_missing_owner_issuer_or_expiry_never_falls_back_to_client(self):
        for subject, issuer, expiry in ((None, ISSUER, int(time.time()) + 300),
                                       ('', ISSUER, int(time.time()) + 300),
                                       ('first-owner', None, int(time.time()) + 300),
                                       ('first-owner', '', int(time.time()) + 300),
                                       ('first-owner', ISSUER, int(time.time()) - 1),
                                       ('first-owner', ISSUER, None)):
            with self.subTest(subject=subject, issuer=issuer, expiry=expiry):
                token = AccessToken(token='synthetic', client_id='shared-client', scopes=[],
                                    subject=subject, claims={'iss': issuer}, expires_at=expiry)
                context = auth_context_var.set(AuthenticatedUser(token))
                try:
                    self.assert_authentication_required(current_export_actor)
                finally:
                    auth_context_var.reset(context)

    def test_explicit_verified_read_context_overrides_sdk_and_refuses_fallback(self):
        sdk_context = auth_context_var.set(sdk_user('sdk-owner'))
        self.addCleanup(auth_context_var.reset, sdk_context)
        actor = export_actor_from_verified(ISSUER, 'cloudflare-owner', time.time() + 300)
        verified_export_actor.set(actor)
        self.assertIs(current_export_actor(), actor)
        for invalid in (object(), ExportActor(actor.key, 0, 0), ExportActor('', 0, 0)):
            verified_export_actor.set(invalid)
            with patch('mcp.server.auth.middleware.auth_context.get_access_token') as fallback:
                self.assert_authentication_required(current_export_actor)
            fallback.assert_not_called()

    def test_sdk_context_restores_outer_user_on_error_and_cancellation(self):
        outer = sdk_user('outer-owner')
        auth_context_var.set(outer)

        async def run(failure):
            async def app(scope, receive, send):
                self.assertEqual(current_export_actor().key, actor_digest(ISSUER, 'inner-owner'))
                raise failure()

            with self.assertRaises(failure):
                await request(AuthContextMiddleware(app), user=sdk_user('inner-owner'))
            self.assertIs(auth_context_var.get(), outer)

        for failure in (RuntimeError, asyncio.CancelledError):
            with self.subTest(failure=failure.__name__):
                asyncio.run(run(failure))

    def test_cloudflare_capture_uses_verified_claims_and_restores_outer_context(self):
        outer = export_actor_from_verified(ISSUER, 'outer-owner', time.time() + 300)
        verified_export_actor.set(outer)
        verified_file_actor.set('existing-write-context')
        seen = []

        class Verifier:
            def verify(self, token):
                return {'iss': ISSUER, 'sub': token, 'exp': time.time() + 300,
                        'client_id': 'shared-client'}

        async def run(subject, failure=None):
            async def app(scope, receive, send):
                actor = current_export_actor()
                seen.append(actor.key)
                self.assertEqual(current_file_actor(), actor.key)
                self.assertGreater(actor.expires_at, time.time())
                if failure:
                    raise failure()
                await JSONResponse({'ok': True})(scope, receive, send)

            wrapped = AccessMiddleware(app, Verifier())
            if failure:
                with self.assertRaises(failure):
                    await request(wrapped, subject=subject)
            else:
                messages = await request(wrapped, subject=subject)
                self.assertEqual(messages[0]['status'], 200)
            self.assertIs(verified_export_actor.get(), outer)
            self.assertEqual(verified_file_actor.get(), 'existing-write-context')

        asyncio.run(run('first-owner'))
        asyncio.run(run('second-owner'))
        self.assertNotEqual(seen[0], seen[1])
        self.assertEqual(seen[:2], [actor_digest(ISSUER, owner)
                                   for owner in ('first-owner', 'second-owner')])
        for failure in (RuntimeError, asyncio.CancelledError):
            asyncio.run(run('failing-owner', failure))

    def test_cloudflare_unusable_expiry_denies_read_without_changing_write_contract(self):
        async def run(expiry):
            class Verifier:
                def verify(self, token):
                    return {'iss': ISSUER, 'sub': 'cloudflare-owner', 'exp': expiry}

            async def app(scope, receive, send):
                self.assertEqual(current_file_actor(), actor_digest(ISSUER, 'cloudflare-owner'))
                with patch('mcp.server.auth.middleware.auth_context.get_access_token') as fallback:
                    self.assert_authentication_required(current_export_actor)
                fallback.assert_not_called()
                await JSONResponse({'ok': True})(scope, receive, send)

            wrapped = AuthContextMiddleware(AccessMiddleware(app, Verifier()))
            await request(wrapped, user=sdk_user('sdk-owner'))
            self.assertIsNone(verified_export_actor.get())
            self.assertIsNone(verified_file_actor.get())
            self.assertIsNone(auth_context_var.get())

        for expiry in (None, False, 'unbounded', float('inf'), float('nan'), time.time() - 1):
            with self.subTest(expiry=expiry):
                asyncio.run(run(expiry))

    def test_cloudflare_parallel_requests_do_not_exchange_actors(self):
        async def run():
            arrived = 0
            both_arrived = asyncio.Event()
            seen = {}

            class Verifier:
                def verify(self, token):
                    return {'iss': ISSUER, 'sub': token, 'exp': time.time() + 300}

            async def app(scope, receive, send):
                nonlocal arrived
                first = current_export_actor()
                arrived += 1
                if arrived == 2:
                    both_arrived.set()
                await asyncio.wait_for(both_arrived.wait(), timeout=2)
                self.assertIs(current_export_actor(), first)
                seen[first.key] = current_file_actor()

            wrapped = AccessMiddleware(app, Verifier())
            await asyncio.gather(request(wrapped, subject='first-owner'),
                                 request(wrapped, subject='second-owner'))
            keys = {actor_digest(ISSUER, owner) for owner in ('first-owner', 'second-owner')}
            self.assertEqual(set(seen), keys)
            self.assertEqual(set(seen.values()), keys)
            self.assertIsNone(verified_export_actor.get())
            self.assertIsNone(verified_file_actor.get())

        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
