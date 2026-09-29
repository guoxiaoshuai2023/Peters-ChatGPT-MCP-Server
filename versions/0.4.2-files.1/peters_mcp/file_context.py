"""Verified request identity for original-file tools; never supplied as an argument."""
from contextvars import ContextVar
from hashlib import sha256
import json

from .catalog import AccessError

verified_file_actor = ContextVar('verified_file_actor', default=None)


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
