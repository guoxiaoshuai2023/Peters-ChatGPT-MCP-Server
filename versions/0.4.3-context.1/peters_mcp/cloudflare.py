"""Authenticated origin for Cloudflare Access Managed OAuth.

This is a separate entry point so the existing local-only server is unchanged.
Cloudflare owns OAuth discovery, login and grants. The origin validates its JWT.
"""

import argparse
from dataclasses import dataclass
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re

import anyio
import jwt
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
import uvicorn

from .catalog import AccessError, Catalog
from .history import HistoryAccess
from .server import create_server
from .file_context import (ExportActor, actor_digest, verified_file_actor,
                           verified_export_actor, export_actor_from_verified)


@dataclass(frozen=True)
class AccessSettings:
    team_domain: str
    audience: str
    public_hostname: str
    allowed_emails: tuple[str, ...]

    def __post_init__(self):
        if not re.fullmatch(r"https://[a-z0-9-]+\.cloudflareaccess\.com", self.team_domain):
            raise ValueError("team_domain must be your HTTPS Cloudflare Access team origin.")
        if not re.fullmatch(r"[0-9a-f]{64}", self.audience):
            raise ValueError("audience must be the 64-character Application Audience tag.")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
                            self.public_hostname):
            raise ValueError("public_hostname must be a DNS hostname without a path or port.")
        if not self.allowed_emails or any(
            not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
            for email in self.allowed_emails
        ):
            raise ValueError("Set at least one exact allowed email address.")

    @classmethod
    def from_file(cls, path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if set(data) != {"team_domain", "audience", "public_hostname", "allowed_emails"}:
            raise ValueError("Unexpected Access configuration fields.")
        if not isinstance(data["allowed_emails"], list):
            raise ValueError("allowed_emails must be an array.")
        return cls(data["team_domain"], data["audience"], data["public_hostname"],
                   tuple(email.casefold() for email in data["allowed_emails"]))


class AccessVerifier:
    def __init__(self, settings):
        self.settings = settings
        self.keys = jwt.PyJWKClient(
            settings.team_domain + "/cdn-cgi/access/certs",
            cache_keys=False, cache_jwk_set=True, lifespan=300, timeout=5,
        )

    def verify(self, token):
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise jwt.InvalidTokenError("Invalid assertion.")
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise jwt.InvalidTokenError("Unsupported signing header.")
        key = self.keys.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=self.settings.team_domain,
            audience=self.settings.audience,
            options={"require": ["iss", "aud", "exp", "iat", "sub", "email"]},
        )
        email = claims.get("email")
        if not isinstance(email, str) or email.casefold() not in self.settings.allowed_emails:
            raise jwt.InvalidTokenError("Identity not permitted.")
        return claims


class AccessMiddleware:
    def __init__(self, app, verifier, audit=None):
        self.app, self.verifier, self.audit = app, verifier, audit

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        tokens = [value for name, value in scope.get("headers", [])
                  if name.lower() == b"cf-access-jwt-assertion"]
        try:
            if len(tokens) != 1:
                raise jwt.InvalidTokenError("Missing or duplicate assertion.")
            token = tokens[0].decode("ascii")
            claims = await anyio.to_thread.run_sync(self.verifier.verify, token)
        except (jwt.PyJWTError, UnicodeDecodeError, ValueError, OSError):
            if self.audit:
                self.audit.info(json.dumps({"event": "access_denied"}))
            await JSONResponse(
                {"error": "Cloudflare Access authentication required."}, status_code=401,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)
            return
        principal = None
        export_principal = ExportActor('', 0, 0)
        if isinstance(claims, dict) and isinstance(claims.get('iss'), str) and isinstance(claims.get('sub'), str):
            principal = actor_digest(claims['iss'], claims['sub'])
            try:
                export_principal = export_actor_from_verified(claims['iss'], claims['sub'], claims.get('exp'))
            except AccessError:
                # Existing non-export callers retain their prior contract; a
                # malformed verified context cannot fall back to another actor.
                pass
        identity_context = verified_file_actor.set(principal)
        export_context = verified_export_actor.set(export_principal)
        try:
            await self.app(scope, receive, send)
        finally:
            verified_export_actor.reset(export_context)
            verified_file_actor.reset(identity_context)


def build_app(catalog, settings, audit=None, history=None, *, files=None, file_inspection_only=False, exports=None):
    server = create_server(catalog, audit, history, files=files, file_inspection_only=file_inspection_only, exports=exports)
    app = server.streamable_http_app(
        host="127.0.0.1", stateless_http=True, json_response=True,
        max_request_body_size=262144,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[settings.public_hostname, "127.0.0.1:*", "localhost:*"],
            allowed_origins=[f"https://{settings.public_hostname}"],
        ),
    )
    if exports is not None:
        app = exports.protocol.wrap(app)
    return AccessMiddleware(app, AccessVerifier(settings), audit)


def main():
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Loopback-only MCP origin protected by Cloudflare Access JWTs.")
    parser.add_argument("--access-config", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path,
                        help="Explicit project allowlist; use the synthetic test project first.")
    parser.add_argument("--history-config", type=Path,
                        help="History policy file; absent default history-access.json disables history.")
    parser.add_argument("--file-config", type=Path,
                        help="Explicit original-file policy; never auto-loads package delivery or local grants.")
    parser.add_argument("--file-export-config", type=Path,
                        help="Independent default-off original export policy; requires initialized private infrastructure.")
    parser.add_argument("--file-inspection-only", action="store_true",
                        help="Compatible rollback: retain private protection and read-only job inspection, with no new file jobs.")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port.")
    files = exports = None
    try:
        settings = AccessSettings.from_file(args.access_config)
        catalog = Catalog.from_config(args.config)
        default_history = base / "history-access.json"
        history_path = args.history_config
        if history_path is None and (default_history.exists() or default_history.is_symlink()):
            history_path = default_history
        history = HistoryAccess(history_path, catalog.projects, catalog=catalog)
        history._configuration()
        from .file_config import load_file_service
        _, files = load_file_service(args.file_config, catalog, history,
                                     inspection_only=args.file_inspection_only or args.check)
        from .file_export import load_export_service
        exports = load_export_service(args.file_export_config, catalog, history, files=files,
            protected_paths=(args.access_config, args.config, base / 'work'),
            inspection_only=args.file_inspection_only)
    except (ValueError, TypeError, AttributeError, OSError):
        if exports is not None:
            exports.close()
        if files is not None:
            files.close()
        parser.error("Invalid configuration; check Access settings and project roots.")
    if args.check:
        if exports is not None:
            exports.close()
        if files is not None:
            files.close()
        print("Access configuration valid. No server or tunnel started.")
        return
    audit_dir = base / "work"
    audit_dir.mkdir(exist_ok=True)
    audit = logging.getLogger("peters.remote.audit")
    audit.propagate = False
    audit.setLevel(logging.INFO)
    handler = RotatingFileHandler(audit_dir / "remote-audit.jsonl", maxBytes=1048576,
                                  backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit.addHandler(handler)
    try:
        uvicorn.run(build_app(catalog, settings, audit, history, files=files,
                             file_inspection_only=args.file_inspection_only or
                             bool(getattr(files, 'inspection_only', False)), exports=exports), host="127.0.0.1", port=args.port,
                    proxy_headers=False, access_log=False, log_level="warning",
                    limit_concurrency=16, timeout_keep_alive=10)
    finally:
        export_stop = exports.close() if exports is not None else None
        if files is not None:
            files.close()
        handler.close()
        audit.removeHandler(handler)
        if export_stop is not None and export_stop['state'] != 'stopped':
            raise SystemExit('Original export shutdown_pending; wait for actual process exit before restart.')


if __name__ == "__main__":
    main()
