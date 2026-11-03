"""Verified request identity for original-file tools; never supplied as an argument."""
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import time

from .catalog import AccessError

verified_file_actor = ContextVar('verified_file_actor', default=None)
verified_export_actor = ContextVar('verified_export_actor', default=None)


@dataclass(frozen=True)
class ExportActor:
    """Verified identity and fixed expiry; no token travels to worker threads."""
    key: str
    expires_at: float
    deadline: float

    def check(self, *, wall_clock=time.time, monotonic=time.monotonic):
        try:
            valid = (isinstance(self.key, str) and len(self.key) == 64 and
                     all(c in '0123456789abcdef' for c in self.key) and
                     type(self.expires_at) in (int, float) and type(self.deadline) in (int, float) and
                     math.isfinite(self.expires_at) and math.isfinite(self.deadline) and
                     wall_clock() < self.expires_at and monotonic() < self.deadline)
        except (TypeError, ValueError, OverflowError):
            valid = False
        if not valid:
            raise AccessError('Current verified read authorization is required.', code='authentication_required')


def export_actor_from_verified(issuer, subject, expires_at):
    try:
        valid_expiry = type(expires_at) in (int, float) and math.isfinite(expires_at)
    except (TypeError, ValueError, OverflowError):
        valid_expiry = False
    if not valid_expiry:
        raise AccessError('A bounded verified identity is required.', code='authentication_required')
    now = time.time()
    actor = ExportActor(actor_digest(issuer, subject), float(expires_at),
                        time.monotonic() + max(0.0, expires_at - now))
    actor.check()
    return actor


def current_export_actor():
    actor = verified_export_actor.get()
    if actor is not None:
        if not isinstance(actor, ExportActor):
            raise AccessError('Current verified read authorization is required.', code='authentication_required')
        actor.check()
        return actor
    # The SDK verifies its token before entering a handler. Used by isolated
    # authenticated deployments; an unauthenticated local transport has no actor.
    from mcp.server.auth.middleware.auth_context import get_access_token
    token = get_access_token()
    if token is not None:
        return export_actor_from_verified((token.claims or {}).get('iss'), token.subject, token.expires_at)
    raise AccessError('Current verified read authorization is required.', code='authentication_required')


def actor_digest(issuer, subject):
    if not isinstance(issuer, str) or not issuer or not isinstance(subject, str) or not subject:
        raise AccessError('An authenticated file-save principal is required.', code='authentication_required')
    return sha256(json.dumps([issuer, subject], separators=(',', ':')).encode()).hexdigest()


def current_file_actor():
    principal = verified_file_actor.get()
    if principal:
        return principal
    # The independent authenticated test deployment uses the SDK's OAuth verifier.
    from mcp.server.auth.middleware.auth_context import get_access_token
    token = get_access_token()
    if token is not None:
        return actor_digest((token.claims or {}).get('iss'), token.subject)
    raise AccessError('An authenticated file-save principal is required.', code='authentication_required')
