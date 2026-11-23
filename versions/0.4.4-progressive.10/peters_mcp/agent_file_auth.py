"""Validate Cloudflare Service Auth assertions on the Agent-only ingress."""

from dataclasses import dataclass
import json
import re
import time

import httpx2
import jwt


_ISSUER = re.compile(r"https://[a-z0-9-]+\.cloudflareaccess\.com")
_AUDIENCE = re.compile(r"[0-9a-f]{64}")
_SERVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.access")
_KEY_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_CERT_LIMIT = 256 * 1024


@dataclass(frozen=True)
class MachineIdentity:
    key: tuple[str, str, str]
    expires_at: int


class _IssuerKeys(jwt.PyJWKClient):
    """Keep PyJWT's key cache and select keys from only the pinned issuer."""

    def fetch_data(self):
        try:
            with httpx2.Client(timeout=self.timeout, trust_env=False, follow_redirects=False) as client:
                with client.stream("GET", self.uri, headers={"Accept-Encoding": "identity"}) as response:
                    if (response.status_code != 200
                            or response.headers.get("content-encoding", "identity").lower() != "identity"):
                        raise ValueError()
                    data = bytearray()
                    deadline = time.monotonic() + self.timeout
                    for chunk in response.iter_raw():
                        if time.monotonic() >= deadline or len(data) + len(chunk) > _CERT_LIMIT:
                            raise ValueError()
                        data.extend(chunk)
                decoded = json.loads(data)
            entries = decoded.get("keys") if isinstance(decoded, dict) else None
            if not isinstance(entries, list) or not entries or len(entries) > 16:
                raise ValueError()
            key_ids = set()
            for entry in entries:
                key_id = entry.get("kid") if isinstance(entry, dict) else None
                if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id) or key_id in key_ids:
                    raise ValueError()
                key_ids.add(key_id)
        except (httpx2.HTTPError, OSError, ValueError, RecursionError):
            raise jwt.PyJWKClientConnectionError("Access signing keys could not be verified.") from None
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(decoded)
        return decoded


class MachineAccessVerifier:
    def __init__(self, issuer, audience):
        if (not isinstance(issuer, str) or not _ISSUER.fullmatch(issuer)
                or not isinstance(audience, str) or not _AUDIENCE.fullmatch(audience)):
            raise ValueError("An exact Cloudflare Access team URL and audience are required.")
        self.issuer = issuer
        self.audience = audience
        self.keys = _IssuerKeys(
            issuer + "/cdn-cgi/access/certs", cache_keys=False,
            cache_jwk_set=True, lifespan=300, timeout=5,
        )

    def verify(self, token):
        try:
            if not isinstance(token, str) or not 0 < len(token) <= 16384:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or not isinstance(kid, str) or not _KEY_ID.fullmatch(kid)
                    or any(field in header for field in ("crit", "jku", "jwk", "x5u", "x5c"))):
                raise ValueError()
            key = self.keys.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token, key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience,
                options={"require": ["iss", "aud", "exp", "iat", "type", "sub", "common_name"]},
            )
            client_id = claims["common_name"]
            if (claims["type"] != "app" or claims["sub"] != "" or "email" in claims
                    or claims["aud"] not in (self.audience, [self.audience])
                    or type(claims["iat"]) is not int or type(claims["exp"]) is not int
                    or claims["iat"] >= claims["exp"]
                    or ("nbf" in claims and type(claims["nbf"]) is not int)
                    or not isinstance(client_id, str) or not _SERVICE_ID.fullmatch(client_id)):
                raise ValueError()
            return MachineIdentity((self.issuer, self.audience, client_id), claims["exp"])
        except (jwt.PyJWTError, TypeError, ValueError, OSError, OverflowError, RecursionError):
            raise jwt.InvalidTokenError("Machine Access assertion could not be verified.") from None
