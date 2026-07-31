"""Shared Tribe v1 HTTP, ACK, fallback, and durable inbox client logic."""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

import tribe_protocol_v1 as protocol
from tribe_broker_v1 import SQLiteBroker, ack_preimage
from tribe_crypto_v1 import KeyBundle, b64url, decrypt_envelope
from tribe_directory_v1 import Directory
from tribe_transport_v1 import wrap_request


MAX_HTTP_RESPONSE = 4 * 1024 * 1024


class ClientError(RuntimeError):
    pass


class EndpointUnavailable(ClientError):
    pass


class EndpointRejected(ClientError):
    pass


def normalize_endpoint(value: str) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(candidate)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"invalid Tribe endpoint: {value}")
    return candidate


def post_signed(
    endpoint: str,
    path: str,
    body: Any,
    *,
    keys: KeyBundle,
    now_ms: int | None = None,
    timeout: float = 10,
) -> dict[str, Any]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    wrapper = wrap_request(
        body,
        keys=keys,
        method="POST",
        path=path,
        now_ms=now,
    )
    encoded = protocol.canonical_json(wrapper)
    request = urllib.request.Request(
        normalize_endpoint(endpoint) + path,
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_HTTP_RESPONSE + 1)
            if len(raw) > MAX_HTTP_RESPONSE:
                raise EndpointRejected("endpoint response exceeds limit")
            value = json.loads(raw)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        if exc.code >= 500:
            raise EndpointUnavailable(
                f"{endpoint} unavailable: HTTP {exc.code}"
            ) from exc
        raise EndpointRejected(
            f"{endpoint} rejected request: HTTP {exc.code} {detail}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise EndpointUnavailable(f"{endpoint} unavailable") from exc
    except json.JSONDecodeError as exc:
        raise EndpointRejected(f"{endpoint} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise EndpointRejected(f"{endpoint} returned invalid response")
    return value


def send_with_fallback(
    envelope: dict[str, Any],
    endpoints: list[str],
    *,
    keys: KeyBundle,
    outbox: SQLiteBroker,
    now_ms: int | None = None,
    timeout: float = 10,
) -> dict[str, Any]:
    if not endpoints:
        raise ValueError("at least one endpoint is required")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    staged = outbox.stage_outbox(envelope, now_ms=now)
    claims = outbox.claim_outbox(
        limit=1,
        lease_ms=60_000,
        now_ms=now,
        outbox_id=staged["outbox_id"],
    )
    claim = next(
        (
            item
            for item in claims
            if item["outbox_id"] == staged["outbox_id"]
        ),
        None,
    )
    if claim is None:
        raise ClientError("message is already leased by another sender worker")
    failures = []
    for endpoint in endpoints:
        try:
            receipt = post_signed(
                endpoint,
                "/v1/messages",
                envelope,
                keys=keys,
                now_ms=now,
                timeout=timeout,
            )
            outbox.complete_outbox(
                claim["outbox_id"],
                claim["lease_id"],
                receipt=receipt,
                now_ms=now,
            )
            return {
                "receipt": receipt,
                "endpoint": normalize_endpoint(endpoint),
                "fallbacks": failures,
            }
        except EndpointUnavailable as exc:
            failures.append(str(exc))
            continue
        except EndpointRejected as exc:
            outbox.complete_outbox(
                claim["outbox_id"],
                claim["lease_id"],
                error=str(exc),
                terminal_error=True,
                now_ms=now,
            )
            raise
    outbox.complete_outbox(
        claim["outbox_id"],
        claim["lease_id"],
        error="; ".join(failures) or "all endpoints unavailable",
        now_ms=now,
    )
    raise EndpointUnavailable("; ".join(failures))


def route_endpoints(
    routes: dict[str, Any], audience_id: str
) -> list[str]:
    entry = routes.get(audience_id)
    if isinstance(entry, str):
        return [entry]
    if isinstance(entry, dict):
        return [
            entry[name]
            for name in ("direct", "hub")
            if isinstance(entry.get(name), str)
        ]
    return []


def flush_outbox(
    outbox: SQLiteBroker,
    routes: dict[str, Any],
    *,
    keys: KeyBundle,
    now_ms: int | None = None,
    limit: int = 20,
    timeout: float = 10,
) -> dict[str, Any]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    claims = outbox.claim_outbox(
        limit=limit, lease_ms=60_000, now_ms=now
    )
    sent = []
    pending = []
    dead = []
    for claim in claims:
        audience_id = claim["envelope"]["audience"]["id"]
        endpoints = route_endpoints(routes, audience_id)
        if not endpoints:
            outbox.complete_outbox(
                claim["outbox_id"],
                claim["lease_id"],
                error=f"no route for {audience_id}",
                terminal_error=True,
                now_ms=now,
            )
            dead.append(claim["outbox_id"])
            continue
        failures = []
        delivered = False
        for endpoint in endpoints:
            try:
                receipt = post_signed(
                    endpoint,
                    "/v1/messages",
                    claim["envelope"],
                    keys=keys,
                    now_ms=now,
                    timeout=timeout,
                )
                outbox.complete_outbox(
                    claim["outbox_id"],
                    claim["lease_id"],
                    receipt=receipt,
                    now_ms=now,
                )
                sent.append(claim["outbox_id"])
                delivered = True
                break
            except EndpointUnavailable as exc:
                failures.append(str(exc))
            except EndpointRejected as exc:
                outbox.complete_outbox(
                    claim["outbox_id"],
                    claim["lease_id"],
                    error=str(exc),
                    terminal_error=True,
                    now_ms=now,
                )
                dead.append(claim["outbox_id"])
                delivered = True
                break
        if not delivered:
            outbox.complete_outbox(
                claim["outbox_id"],
                claim["lease_id"],
                error="; ".join(failures),
                now_ms=now,
            )
            pending.append(claim["outbox_id"])
    return {"sent": sent, "pending": pending, "dead_letter": dead}


def make_ack(
    claim: dict[str, Any],
    *,
    keys: KeyBundle,
    outcome: str,
    now_ms: int,
) -> dict[str, Any]:
    ack = {
        "schema": "tribe-ack/v1",
        "receiver_id": keys.agent_id,
        "message_id": claim["message_id"],
        "lease_id": claim["lease_id"],
        "issued_at_ms": now_ms,
        "envelope_sha256": claim["envelope_sha256"],
        "outcome": outcome,
        "receiver_signing_kid": keys.signing_kid,
        "signature": {
            "alg": "Ed25519",
            "kid": keys.signing_kid,
            "value": "",
        },
    }
    ack["signature"]["value"] = b64url(
        keys.signing_private.sign(ack_preimage(ack))
    )
    return ack


class InboxStore:
    """Durable endpoint replay/effect state shared across direct and hub routes."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS inbox_effects(
                    sender_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    envelope_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(
                        state IN ('processing', 'processed', 'terminal_failed')
                    ),
                    payload_json BLOB,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(sender_id, message_id)
                ) STRICT
                """
            )
            connection.commit()
        self.path.chmod(0o600)

    def begin(
        self,
        sender_id: str,
        message_id: str,
        envelope_sha256: str,
        *,
        now_ms: int,
        processing_timeout_ms: int = 5 * 60 * 1000,
    ) -> str:
        try:
            valid_message_id = uuid.UUID(message_id).version == 7
        except (ValueError, TypeError, AttributeError):
            valid_message_id = False
        if (
            not isinstance(sender_id, str)
            or not protocol.IDENTIFIER.fullmatch(sender_id)
            or not valid_message_id
            or not isinstance(envelope_sha256, str)
            or len(envelope_sha256) != 64
            or any(c not in "0123456789abcdef" for c in envelope_sha256)
        ):
            raise protocol.ProtocolError("malformed_delivery")
        with closing(
            sqlite3.connect(self.path, isolation_level=None)
        ) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT envelope_sha256, state, updated_at_ms
                    FROM inbox_effects
                    WHERE sender_id=? AND message_id=?
                    """,
                    (sender_id, message_id),
                ).fetchone()
                if row:
                    if row["envelope_sha256"] != envelope_sha256:
                        raise protocol.ProtocolError("message_id_conflict")
                    if (
                        row["state"] == "processing"
                        and row["updated_at_ms"]
                        <= now_ms - processing_timeout_ms
                    ):
                        connection.execute(
                            """
                            UPDATE inbox_effects SET updated_at_ms=?
                            WHERE sender_id=? AND message_id=?
                            """,
                            (now_ms, sender_id, message_id),
                        )
                        connection.execute("COMMIT")
                        return "new"
                    connection.execute("COMMIT")
                    return row["state"]
                connection.execute(
                    """
                    INSERT INTO inbox_effects(
                        sender_id, message_id, envelope_sha256,
                        state, updated_at_ms
                    ) VALUES(?, ?, ?, 'processing', ?)
                    """,
                    (sender_id, message_id, envelope_sha256, now_ms),
                )
                connection.execute("COMMIT")
                return "new"
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def finish(
        self,
        sender_id: str,
        message_id: str,
        state: str,
        *,
        payload: dict[str, Any] | None,
        now_ms: int,
    ) -> None:
        if state not in {"processed", "terminal_failed"}:
            raise ValueError("invalid terminal inbox state")
        encoded = (
            None if payload is None else protocol.canonical_json(payload)
        )
        with closing(sqlite3.connect(self.path)) as connection:
            updated = connection.execute(
                """
                UPDATE inbox_effects
                SET state=?, payload_json=?, updated_at_ms=?
                WHERE sender_id=? AND message_id=?
                """,
                (state, encoded, now_ms, sender_id, message_id),
            )
            if updated.rowcount != 1:
                raise ClientError("inbox effect row disappeared")
            connection.commit()

    def release(self, sender_id: str, message_id: str) -> None:
        """Release only an in-progress effect after a retryable failure."""
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                DELETE FROM inbox_effects
                WHERE sender_id=? AND message_id=? AND state='processing'
                """,
                (sender_id, message_id),
            )
            connection.commit()


def claim_and_process(
    endpoint: str,
    *,
    directory: Directory,
    keys: KeyBundle,
    store: InboxStore,
    limit: int = 3,
    lease_ms: int = 60_000,
    now_ms: int | None = None,
    timeout: float = 10,
) -> list[dict[str, Any]]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    response = post_signed(
        endpoint,
        "/v1/claims",
        {
            "recipient_id": keys.agent_id,
            "limit": limit,
            "lease_ms": lease_ms,
        },
        keys=keys,
        now_ms=now,
        timeout=timeout,
    )
    claims = response.get("claims")
    if not isinstance(claims, list):
        raise EndpointRejected("claim response has no claims list")
    fresh = []
    for claim in claims:
        sender = claim.get("sender_id")
        message_id = claim.get("message_id")
        digest = claim.get("envelope_sha256")
        prior = store.begin(sender, message_id, digest, now_ms=now)
        if prior == "new":
            try:
                payload = decrypt_envelope(
                    claim["envelope"],
                    directory=directory,
                    keys=keys,
                    now_ms=now,
                )
                store.finish(
                    sender,
                    message_id,
                    "processed",
                    payload=payload,
                    now_ms=now,
                )
                fresh.append(
                    {
                        "sender_id": sender,
                        "message_id": message_id,
                        "payload": payload,
                    }
                )
                outcome = "processed"
            except Exception:
                store.finish(
                    sender,
                    message_id,
                    "terminal_failed",
                    payload=None,
                    now_ms=now,
                )
                outcome = "terminal_failed"
        elif prior == "processing":
            # Another worker may still own the external effect. Let the
            # broker lease expire; the local processing timeout recovers a
            # crashed owner without claiming exactly-once effects.
            continue
        elif prior == "terminal_failed":
            outcome = "terminal_failed"
        else:
            outcome = "processed"
        ack = make_ack(
            claim, keys=keys, outcome=outcome, now_ms=now
        )
        post_signed(
            endpoint,
            "/v1/acks",
            ack,
            keys=keys,
            now_ms=now,
            timeout=timeout,
        )
    return fresh
