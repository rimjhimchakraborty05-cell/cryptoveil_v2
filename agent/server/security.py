"""Loopback dashboard sessions and one-use browser-extension pairing."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse

from ..forensics.storage import atomic_write, canonical

EXTENSION_ORIGIN = re.compile(r"chrome-extension://[a-p]{32}\Z")


class PairingManager:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "paired_browsers.json"
        self.clients = json.loads(self.path.read_bytes()) if self.path.exists() else {}
        self.session_token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self._code = None
        self._code_expires = 0.0
        self._attempts = 0

    def _save(self) -> None:
        atomic_write(self.path, canonical(self.clients))

    def new_code(self) -> dict:
        self._code = f"{secrets.randbelow(100_000_000):08d}"
        self._code_expires = time.time() + 300
        self._attempts = 0
        return {"code": self._code, "expires_at": self._code_expires}

    def complete(self, code: str, name: str, origin: str | None) -> dict:
        self._attempts += 1
        if (
            self._attempts > 5
            or time.time() >= self._code_expires
            or not self._code
            or not hmac.compare_digest(self._code, code)
        ):
            raise ValueError("Pairing code is invalid or expired. Generate a new code in the app.")
        self._code = None
        token = secrets.token_urlsafe(32)
        client_id = str(uuid.uuid4())
        self.clients[client_id] = {
            "id": client_id,
            "name": name.strip() or "Browser",
            "origin": origin,
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "paired_at": time.time(),
            "last_seen": time.time(),
            "queued_events": 0,
            "dropped_events": 0,
        }
        self._save()
        return {"client_id": client_id, "token": token, "name": self.clients[client_id]["name"]}

    def authenticate(self, token: str, origin: str | None) -> dict | None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        for client in self.clients.values():
            if hmac.compare_digest(token_hash, client["token_hash"]):
                if origin and client.get("origin") and origin != client["origin"]:
                    return None
                return client
        return None

    def heartbeat(self, client_id: str, queued: int, dropped: int) -> None:
        self.clients[client_id].update(
            last_seen=time.time(), queued_events=queued, dropped_events=dropped
        )

    def public_clients(self) -> list[dict]:
        return [
            {k: v for k, v in c.items() if k not in ("token_hash", "origin")}
            | {"connected": time.time() - c.get("last_seen", 0) < 90}
            for c in self.clients.values()
        ]

    def revoke(self, client_id: str) -> bool:
        if client_id not in self.clients:
            return False
        del self.clients[client_id]
        self._save()
        return True


def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


async def access_guard(request: Request, call_next):
    path = request.url.path
    origin = request.headers.get("origin")
    same_origin = origin == f"{request.url.scheme}://{request.url.netloc}"
    extension_route = path in (
        "/api/pairing/complete",
        "/api/browser/telemetry",
        "/api/browser/heartbeat",
    )
    allowed_extension = bool(origin and EXTENSION_ORIGIN.fullmatch(origin) and extension_route)
    if path.startswith("/api/"):
        if (origin and not same_origin and not allowed_extension) or (
            request.headers.get("sec-fetch-site") == "cross-site" and not allowed_extension
        ):
            return security_headers(
                JSONResponse({"detail": "Cross-origin access is not allowed"}, status_code=403)
            )
        if path == "/api/pairing/complete" and not allowed_extension:
            return security_headers(
                JSONResponse(
                    {"detail": "Pairing is available only to the CryptoVeil extension"},
                    status_code=403,
                )
            )
        # Let the CORS middleware answer extension preflight requests without
        # demanding a bearer token. The actual POST still passes every auth
        # and origin check below.
        if request.method == "OPTIONS" and allowed_extension:
            return security_headers(await call_next(request))
        public = path in ("/api/health", "/api/session", "/api/pairing/complete")
        pairing = request.app.state.pairing
        if not public:
            if extension_route:
                authorization = request.headers.get("authorization", "")
                token = (
                    authorization.removeprefix("Bearer ")
                    if authorization.startswith("Bearer ")
                    else ""
                )
                client = pairing.authenticate(token, origin) if token else None
                if not client:
                    return security_headers(
                        JSONResponse(
                            {"detail": "Pair this extension with CryptoVeil first"}, status_code=401
                        )
                    )
                request.state.browser_client = client
            else:
                session = request.cookies.get("cv_session", "")
                if not hmac.compare_digest(session, pairing.session_token):
                    return security_headers(
                        JSONResponse(
                            {"detail": "Open the CryptoVeil dashboard to start a session"},
                            status_code=401,
                        )
                    )
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    csrf = request.headers.get("x-cryptoveil-csrf", "")
                    if not hmac.compare_digest(csrf, pairing.csrf_token):
                        return security_headers(
                            JSONResponse(
                                {"detail": "Invalid dashboard request token"}, status_code=403
                            )
                        )
        if request.method in ("POST", "PUT", "PATCH"):
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return security_headers(
                    JSONResponse({"detail": "JSON content type required"}, status_code=415)
                )
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 65536:
                    return security_headers(
                        JSONResponse({"detail": "Request exceeds 64 KiB"}, status_code=413)
                    )
            request._body = bytes(data)
    return security_headers(await call_next(request))
