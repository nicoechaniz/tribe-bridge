"""Crash-safe SQLite delivery backend for Tribe Protocol v1."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import time
import uuid
from contextlib import closing, contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import tribe_protocol_v1 as protocol


SCHEMA_VERSION = 1
ACK_DOMAIN = b"tribe/v1/ack\x00"
ACK_FIELDS = {
    "schema",
    "receiver_id",
    "message_id",
    "lease_id",
    "issued_at_ms",
    "envelope_sha256",
    "outcome",
    "receiver_signing_kid",
    "signature",
}
ACK_SIGNATURE_FIELDS = {"alg", "kid", "value"}
TERMINAL_STATES = {"acknowledged", "dead_letter"}


class BrokerError(RuntimeError):
    code = "broker_error"


class MessageConflict(BrokerError):
    code = "message_id_conflict"


class LeaseConflict(BrokerError):
    code = "lease_conflict"


class CursorConflict(BrokerError):
    code = "cursor_conflict"


class StorageError(BrokerError):
    code = "storage_error"


class StorageCorruption(StorageError):
    code = "storage_corruption"


class BrokerBackend(Protocol):
    """Backend-neutral contract implemented by SQLite and future JetStream."""

    def enqueue(
        self,
        envelope: dict[str, Any],
        context: dict[str, Any],
        *,
        received_at_ms: int | None = None,
    ) -> dict[str, Any]: ...

    def claim(
        self,
        recipient_id: str,
        *,
        limit: int = 20,
        lease_ms: int = 60_000,
        now_ms: int | None = None,
    ) -> list[dict[str, Any]]: ...

    def acknowledge(
        self,
        ack: dict[str, Any],
        context: dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> dict[str, Any]: ...


def sqlite_wal_is_safe(version: tuple[int, int, int]) -> bool:
    """Return whether SQLite contains the 2026 WAL-reset corruption fix."""
    if version >= (3, 51, 3):
        return True
    if version[:2] == (3, 50) and version[2] >= 7:
        return True
    if version[:2] == (3, 44) and version[2] >= 6:
        return True
    return False


def _b64url_decode(value: Any, size: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise protocol.ProtocolError("malformed_ack")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise protocol.ProtocolError("malformed_ack") from exc
    if len(decoded) != size:
        raise protocol.ProtocolError("malformed_ack")
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise protocol.ProtocolError("malformed_ack")
    return decoded


def ack_unsigned(ack: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in ack.items() if key != "signature"}


def ack_preimage(ack: dict[str, Any]) -> bytes:
    return ACK_DOMAIN + protocol.canonical_json(ack_unsigned(ack))


def validate_ack(
    ack: Any,
    context: dict[str, Any],
    *,
    now_ms: int,
) -> dict[str, Any]:
    if not isinstance(ack, dict) or set(ack) != ACK_FIELDS:
        raise protocol.ProtocolError("malformed_ack")
    if ack["schema"] != "tribe-ack/v1":
        raise protocol.ProtocolError("unsupported_version")
    for field in (
        "receiver_id",
        "receiver_signing_kid",
        "message_id",
        "lease_id",
        "envelope_sha256",
        "outcome",
    ):
        if not isinstance(ack[field], str):
            raise protocol.ProtocolError("malformed_ack")
    if (
        not protocol.IDENTIFIER.fullmatch(ack["receiver_id"])
        or not protocol.IDENTIFIER.fullmatch(ack["receiver_signing_kid"])
    ):
        raise protocol.ProtocolError("malformed_ack")
    if ack["outcome"] not in {
        "processed",
        "retryable_failed",
        "terminal_failed",
    }:
        raise protocol.ProtocolError("malformed_ack")
    try:
        message_id = uuid.UUID(ack["message_id"])
        lease_id = uuid.UUID(ack["lease_id"])
    except ValueError as exc:
        raise protocol.ProtocolError("malformed_ack") from exc
    if message_id.version != 7 or lease_id.version != 4:
        raise protocol.ProtocolError("malformed_ack")
    if (
        not isinstance(ack["issued_at_ms"], int)
        or isinstance(ack["issued_at_ms"], bool)
        or abs(ack["issued_at_ms"] - now_ms) > protocol.MAX_CLOCK_SKEW_MS
    ):
        raise protocol.ProtocolError("invalid_ack_time")
    if (
        len(ack["envelope_sha256"]) != 64
        or any(c not in "0123456789abcdef" for c in ack["envelope_sha256"])
    ):
        raise protocol.ProtocolError("malformed_ack")

    signature = ack["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != ACK_SIGNATURE_FIELDS
        or signature["alg"] != "Ed25519"
        or signature["kid"] != ack["receiver_signing_kid"]
    ):
        raise protocol.ProtocolError("malformed_ack")
    keys = context.get("signing_keys", {})
    record = keys.get(ack["receiver_signing_kid"])
    if (
        not isinstance(record, dict)
        or record.get("owner") != ack["receiver_id"]
        or record.get("status") != "active"
    ):
        raise protocol.ProtocolError("unauthorized_receiver")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(record.get("public_key"), 32)
        )
        public_key.verify(
            _b64url_decode(signature["value"], 64),
            ack_preimage(ack),
        )
    except InvalidSignature as exc:
        raise protocol.ProtocolError("invalid_signature") from exc
    except (TypeError, ValueError) as exc:
        raise protocol.ProtocolError("unknown_key") from exc
    return ack


class SQLiteBroker:
    """One SQLite implementation of the backend-neutral delivery contract."""

    def __init__(
        self,
        path: Path | str,
        *,
        journal_mode: str = "auto",
        busy_timeout_ms: int = 5_000,
        max_attempts: int = 5,
        retry_base_ms: int = 1_000,
        retry_max_ms: int = 60 * 60 * 1000,
        clock_ms: Callable[[], int] | None = None,
        lease_id_factory: Callable[[], str] | None = None,
    ):
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self.max_attempts = max_attempts
        self.retry_base_ms = retry_base_ms
        self.retry_max_ms = retry_max_ms
        self.clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        self.lease_id_factory = lease_id_factory or (lambda: str(uuid.uuid4()))
        if journal_mode not in {"auto", "delete", "wal"}:
            raise ValueError("journal_mode must be auto, delete, or wal")
        wal_safe = sqlite_wal_is_safe(sqlite3.sqlite_version_info)
        if journal_mode == "wal" and not wal_safe:
            raise StorageError(
                "WAL refused: SQLite "
                f"{sqlite3.sqlite_version} lacks the WAL-reset corruption fix"
            )
        self.journal_mode = (
            "wal"
            if journal_mode == "wal" or (journal_mode == "auto" and wal_safe)
            else "delete"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except Exception:
            connection.close()
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass
            if isinstance(exc, sqlite3.DatabaseError) and (
                "malformed" in str(exc).lower()
                or "not a database" in str(exc).lower()
            ):
                raise StorageCorruption("SQLite database is corrupt") from exc
            raise StorageError("SQLite transaction failed") from exc
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection:
                mode = connection.execute(
                    f"PRAGMA journal_mode={self.journal_mode.upper()}"
                ).fetchone()[0]
                if mode.lower() != self.journal_mode:
                    raise StorageError(
                        f"SQLite refused journal mode {self.journal_mode}"
                    )
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS broker_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    ) STRICT;

                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY,
                        sender_id TEXT NOT NULL,
                        message_id TEXT NOT NULL,
                        envelope_json BLOB NOT NULL,
                        envelope_sha256 TEXT NOT NULL,
                        audience_type TEXT NOT NULL,
                        audience_id TEXT NOT NULL,
                        audience_epoch INTEGER NOT NULL,
                        issued_at_ms INTEGER NOT NULL,
                        expires_at_ms INTEGER NOT NULL,
                        received_at_ms INTEGER NOT NULL,
                        UNIQUE(sender_id, message_id)
                    ) STRICT;

                    CREATE TABLE IF NOT EXISTS deliveries (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        message_pk INTEGER NOT NULL
                            REFERENCES messages(id) ON DELETE CASCADE,
                        recipient_id TEXT NOT NULL,
                        encryption_kid TEXT NOT NULL,
                        state TEXT NOT NULL
                            CHECK(state IN (
                                'queued', 'claimed', 'acknowledged',
                                'dead_letter'
                            )),
                        available_at_ms INTEGER NOT NULL,
                        lease_id TEXT,
                        lease_until_ms INTEGER,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT,
                        terminal_ack_hash TEXT,
                        terminal_ack_json BLOB,
                        updated_at_ms INTEGER NOT NULL,
                        UNIQUE(message_pk, recipient_id),
                        CHECK(
                            (state = 'claimed'
                                AND lease_id IS NOT NULL
                                AND lease_until_ms IS NOT NULL)
                            OR
                            (state != 'claimed'
                                AND lease_id IS NULL
                                AND lease_until_ms IS NULL)
                        )
                    ) STRICT;

                    CREATE TABLE IF NOT EXISTS ack_events (
                        id INTEGER PRIMARY KEY,
                        delivery_seq INTEGER NOT NULL
                            REFERENCES deliveries(seq) ON DELETE CASCADE,
                        ack_hash TEXT NOT NULL UNIQUE,
                        ack_json BLOB NOT NULL,
                        outcome TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL
                    ) STRICT;

                    CREATE TABLE IF NOT EXISTS consumer_cursors (
                        recipient_id TEXT NOT NULL,
                        consumer_id TEXT NOT NULL,
                        cursor INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        PRIMARY KEY(recipient_id, consumer_id)
                    ) STRICT;

                    CREATE TABLE IF NOT EXISTS outbox (
                        id INTEGER PRIMARY KEY,
                        sender_id TEXT NOT NULL,
                        message_id TEXT NOT NULL,
                        envelope_json BLOB NOT NULL,
                        envelope_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL
                            CHECK(state IN (
                                'pending', 'sending', 'sent', 'dead_letter'
                            )),
                        available_at_ms INTEGER NOT NULL,
                        lease_id TEXT,
                        lease_until_ms INTEGER,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        receipt_json BLOB,
                        last_error TEXT,
                        updated_at_ms INTEGER NOT NULL,
                        UNIQUE(sender_id, message_id),
                        CHECK(
                            (state = 'sending'
                                AND lease_id IS NOT NULL
                                AND lease_until_ms IS NOT NULL)
                            OR
                            (state != 'sending'
                                AND lease_id IS NULL
                                AND lease_until_ms IS NULL)
                        )
                    ) STRICT;

                    CREATE INDEX IF NOT EXISTS deliveries_ready
                    ON deliveries(recipient_id, state, available_at_ms, seq);

                    CREATE INDEX IF NOT EXISTS messages_expiry
                    ON messages(expires_at_ms);

                    CREATE INDEX IF NOT EXISTS outbox_ready
                    ON outbox(state, available_at_ms, id);
                    """
                )
                connection.execute(
                    """
                    INSERT INTO broker_meta(key, value)
                    VALUES('schema_version', ?)
                    ON CONFLICT(key) DO NOTHING
                    """,
                    (str(SCHEMA_VERSION),),
                )
                stored = connection.execute(
                    "SELECT value FROM broker_meta WHERE key='schema_version'"
                ).fetchone()[0]
                if stored != str(SCHEMA_VERSION):
                    raise StorageError(
                        f"unsupported broker schema version {stored}"
                    )
                result = connection.execute("PRAGMA quick_check").fetchone()[0]
                if result != "ok":
                    raise StorageCorruption(f"SQLite quick_check failed: {result}")
            os.chmod(self.path, 0o600)
        except StorageError:
            raise
        except sqlite3.DatabaseError as exc:
            raise StorageCorruption("cannot initialize broker database") from exc

    def runtime_info(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "sqlite_version": sqlite3.sqlite_version,
            "sqlite_wal_safe": sqlite_wal_is_safe(
                sqlite3.sqlite_version_info
            ),
            "journal_mode": self.journal_mode,
            "synchronous": "FULL",
            "path": str(self.path),
        }

    def enqueue(
        self,
        envelope: dict[str, Any],
        context: dict[str, Any],
        *,
        received_at_ms: int | None = None,
    ) -> dict[str, Any]:
        now = self.clock_ms() if received_at_ms is None else received_at_ms
        validation_context = dict(context)
        validation_context["now_ms"] = now
        protocol.validate_broker_admission(envelope, validation_context)
        encoded = protocol.canonical_json(envelope)
        digest = sha256(encoded).hexdigest()
        sender_id = envelope["sender"]["id"]
        message_id = envelope["message_id"]

        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT id, envelope_sha256
                FROM messages
                WHERE sender_id=? AND message_id=?
                """,
                (sender_id, message_id),
            ).fetchone()
            if existing:
                if existing["envelope_sha256"] != digest:
                    raise MessageConflict(
                        "same sender/message_id has different envelope bytes"
                    )
                return {
                    "message_pk": existing["id"],
                    "message_id": message_id,
                    "envelope_sha256": digest,
                    "duplicate": True,
                }
            cursor = connection.execute(
                """
                INSERT INTO messages(
                    sender_id, message_id, envelope_json, envelope_sha256,
                    audience_type, audience_id, audience_epoch,
                    issued_at_ms, expires_at_ms, received_at_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sender_id,
                    message_id,
                    encoded,
                    digest,
                    envelope["audience"]["type"],
                    envelope["audience"]["id"],
                    envelope["audience"]["epoch"],
                    envelope["issued_at_ms"],
                    envelope["expires_at_ms"],
                    now,
                ),
            )
            message_pk = cursor.lastrowid
            for recipient in envelope["recipients"]:
                connection.execute(
                    """
                    INSERT INTO deliveries(
                        message_pk, recipient_id, encryption_kid, state,
                        available_at_ms, updated_at_ms
                    ) VALUES(?, ?, ?, 'queued', ?, ?)
                    """,
                    (
                        message_pk,
                        recipient["id"],
                        recipient["encryption_kid"],
                        now,
                        now,
                    ),
                )
            return {
                "message_pk": message_pk,
                "message_id": message_id,
                "envelope_sha256": digest,
                "duplicate": False,
            }

    def _expire_leases_and_messages(
        self, connection: sqlite3.Connection, now: int
    ) -> None:
        connection.execute(
            """
            UPDATE deliveries
            SET state = CASE
                    WHEN attempts >= ? THEN 'dead_letter'
                    ELSE 'queued'
                END,
                available_at_ms = ?,
                lease_id = NULL,
                lease_until_ms = NULL,
                last_error = CASE
                    WHEN attempts >= ? THEN 'max_attempts_after_lease_expiry'
                    ELSE 'lease_expired'
                END,
                updated_at_ms = ?
            WHERE state='claimed' AND lease_until_ms <= ?
            """,
            (self.max_attempts, now, self.max_attempts, now, now),
        )
        connection.execute(
            """
            UPDATE deliveries
            SET state='dead_letter',
                lease_id=NULL,
                lease_until_ms=NULL,
                last_error='message_expired',
                updated_at_ms=?
            WHERE state IN ('queued', 'claimed')
              AND message_pk IN (
                  SELECT id FROM messages WHERE expires_at_ms <= ?
              )
            """,
            (now, now),
        )

    def claim(
        self,
        recipient_id: str,
        *,
        limit: int = 20,
        lease_ms: int = 60_000,
        now_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        if not protocol.IDENTIFIER.fullmatch(recipient_id):
            raise ValueError("invalid recipient_id")
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if not 1_000 <= lease_ms <= 15 * 60 * 1000:
            raise ValueError("lease_ms must be between 1s and 15m")
        now = self.clock_ms() if now_ms is None else now_ms
        claimed: list[dict[str, Any]] = []
        with self._transaction() as connection:
            self._expire_leases_and_messages(connection, now)
            rows = connection.execute(
                """
                SELECT d.seq, d.attempts, m.message_id, m.sender_id,
                       m.envelope_json, m.envelope_sha256
                FROM deliveries d
                JOIN messages m ON m.id=d.message_pk
                WHERE d.recipient_id=?
                  AND d.state='queued'
                  AND d.available_at_ms <= ?
                  AND m.expires_at_ms > ?
                ORDER BY d.seq
                LIMIT ?
                """,
                (recipient_id, now, now, limit),
            ).fetchall()
            for row in rows:
                lease_id = self.lease_id_factory()
                parsed_lease = uuid.UUID(lease_id)
                if parsed_lease.version != 4:
                    raise ValueError("lease_id_factory must return UUIDv4")
                lease_until = now + lease_ms
                updated = connection.execute(
                    """
                    UPDATE deliveries
                    SET state='claimed', lease_id=?, lease_until_ms=?,
                        attempts=attempts+1, updated_at_ms=?
                    WHERE seq=? AND state='queued'
                    """,
                    (lease_id, lease_until, now, row["seq"]),
                )
                if updated.rowcount != 1:
                    continue
                claimed.append(
                    {
                        "cursor": row["seq"],
                        "sender_id": row["sender_id"],
                        "message_id": row["message_id"],
                        "envelope": json.loads(row["envelope_json"]),
                        "envelope_sha256": row["envelope_sha256"],
                        "lease_id": lease_id,
                        "lease_until_ms": lease_until,
                        "attempt": row["attempts"] + 1,
                    }
                )
        return claimed

    def acknowledge(
        self,
        ack: dict[str, Any],
        context: dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        now = self.clock_ms() if now_ms is None else now_ms
        validate_ack(ack, context, now_ms=now)
        encoded = protocol.canonical_json(ack)
        ack_hash = sha256(encoded).hexdigest()
        receiver = ack["receiver_id"]

        with self._transaction() as connection:
            duplicate = connection.execute(
                "SELECT delivery_seq, outcome FROM ack_events WHERE ack_hash=?",
                (ack_hash,),
            ).fetchone()
            if duplicate:
                return {
                    "cursor": duplicate["delivery_seq"],
                    "outcome": duplicate["outcome"],
                    "duplicate": True,
                }
            row = connection.execute(
                """
                SELECT d.seq, d.state, d.lease_id, d.lease_until_ms,
                       d.attempts, m.envelope_sha256
                FROM deliveries d
                JOIN messages m ON m.id=d.message_pk
                WHERE d.recipient_id=? AND m.message_id=?
                  AND d.lease_id=? AND m.envelope_sha256=?
                """,
                (
                    receiver,
                    ack["message_id"],
                    ack["lease_id"],
                    ack["envelope_sha256"],
                ),
            ).fetchone()
            if not row:
                raise LeaseConflict("message is not deliverable to receiver")
            if (
                row["state"] != "claimed"
                or row["lease_id"] != ack["lease_id"]
                or row["lease_until_ms"] <= now
                or row["envelope_sha256"] != ack["envelope_sha256"]
            ):
                raise LeaseConflict("ack does not match the active lease")

            outcome = ack["outcome"]
            if outcome == "processed":
                state = "acknowledged"
                available_at = now
                error = None
            elif outcome == "terminal_failed" or row["attempts"] >= self.max_attempts:
                state = "dead_letter"
                available_at = now
                error = (
                    "terminal_failed"
                    if outcome == "terminal_failed"
                    else "max_attempts"
                )
            else:
                state = "queued"
                delay = min(
                    self.retry_max_ms,
                    self.retry_base_ms * (2 ** max(0, row["attempts"] - 1)),
                )
                available_at = now + delay
                error = "retryable_failed"

            connection.execute(
                """
                INSERT INTO ack_events(
                    delivery_seq, ack_hash, ack_json, outcome, created_at_ms
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (row["seq"], ack_hash, encoded, outcome, now),
            )
            connection.execute(
                """
                UPDATE deliveries
                SET state=?, available_at_ms=?, lease_id=NULL,
                    lease_until_ms=NULL, last_error=?, terminal_ack_hash=?,
                    terminal_ack_json=?, updated_at_ms=?
                WHERE seq=?
                """,
                (
                    state,
                    available_at,
                    error,
                    ack_hash if state in TERMINAL_STATES else None,
                    encoded if state in TERMINAL_STATES else None,
                    now,
                    row["seq"],
                ),
            )
            return {
                "cursor": row["seq"],
                "outcome": outcome,
                "state": state,
                "available_at_ms": available_at,
                "duplicate": False,
            }

    def advance_cursor(
        self,
        recipient_id: str,
        consumer_id: str,
        cursor: int,
        *,
        now_ms: int | None = None,
    ) -> int:
        if not protocol.IDENTIFIER.fullmatch(recipient_id):
            raise ValueError("invalid recipient_id")
        if not protocol.IDENTIFIER.fullmatch(consumer_id):
            raise ValueError("invalid consumer_id")
        if not isinstance(cursor, int) or cursor < 0:
            raise ValueError("cursor must be a non-negative integer")
        now = self.clock_ms() if now_ms is None else now_ms
        with self._transaction() as connection:
            if cursor:
                owned = connection.execute(
                    """
                    SELECT 1 FROM deliveries
                    WHERE seq=? AND recipient_id=?
                      AND state IN ('acknowledged', 'dead_letter')
                    """,
                    (cursor, recipient_id),
                ).fetchone()
                if not owned:
                    raise CursorConflict(
                        "cursor is not a terminal delivery owned by recipient"
                    )
            existing = connection.execute(
                """
                SELECT cursor FROM consumer_cursors
                WHERE recipient_id=? AND consumer_id=?
                """,
                (recipient_id, consumer_id),
            ).fetchone()
            if existing and cursor < existing["cursor"]:
                raise CursorConflict("cursor cannot move backwards")
            connection.execute(
                """
                INSERT INTO consumer_cursors(
                    recipient_id, consumer_id, cursor, updated_at_ms
                ) VALUES(?, ?, ?, ?)
                ON CONFLICT(recipient_id, consumer_id) DO UPDATE SET
                    cursor=excluded.cursor,
                    updated_at_ms=excluded.updated_at_ms
                """,
                (recipient_id, consumer_id, cursor, now),
            )
        return cursor

    def get_cursor(self, recipient_id: str, consumer_id: str) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT cursor FROM consumer_cursors
                WHERE recipient_id=? AND consumer_id=?
                """,
                (recipient_id, consumer_id),
            ).fetchone()
            return 0 if row is None else row["cursor"]

    def stage_outbox(
        self,
        envelope: dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        protocol.validate_structure(envelope)
        now = self.clock_ms() if now_ms is None else now_ms
        encoded = protocol.canonical_json(envelope)
        digest = sha256(encoded).hexdigest()
        sender = envelope["sender"]["id"]
        message_id = envelope["message_id"]
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT id, envelope_sha256 FROM outbox
                WHERE sender_id=? AND message_id=?
                """,
                (sender, message_id),
            ).fetchone()
            if existing:
                if existing["envelope_sha256"] != digest:
                    raise MessageConflict("outbox message ID conflict")
                return {"outbox_id": existing["id"], "duplicate": True}
            cursor = connection.execute(
                """
                INSERT INTO outbox(
                    sender_id, message_id, envelope_json, envelope_sha256,
                    state, available_at_ms, updated_at_ms
                ) VALUES(?, ?, ?, ?, 'pending', ?, ?)
                """,
                (sender, message_id, encoded, digest, now, now),
            )
            return {"outbox_id": cursor.lastrowid, "duplicate": False}

    def claim_outbox(
        self,
        *,
        limit: int = 20,
        lease_ms: int = 60_000,
        now_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if not 1_000 <= lease_ms <= 15 * 60 * 1000:
            raise ValueError("lease_ms must be between 1s and 15m")
        now = self.clock_ms() if now_ms is None else now_ms
        claimed = []
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE outbox
                SET state=CASE
                        WHEN attempts >= ? THEN 'dead_letter'
                        ELSE 'pending'
                    END,
                    available_at_ms=?,
                    lease_id=NULL,
                    lease_until_ms=NULL,
                    last_error=CASE
                        WHEN attempts >= ? THEN 'max_attempts'
                        ELSE 'lease_expired'
                    END,
                    updated_at_ms=?
                WHERE state='sending' AND lease_until_ms <= ?
                """,
                (self.max_attempts, now, self.max_attempts, now, now),
            )
            rows = connection.execute(
                """
                SELECT id, envelope_json, envelope_sha256, attempts
                FROM outbox
                WHERE state='pending' AND available_at_ms <= ?
                ORDER BY id LIMIT ?
                """,
                (now, limit),
            ).fetchall()
            for row in rows:
                lease_id = self.lease_id_factory()
                parsed_lease = uuid.UUID(lease_id)
                if parsed_lease.version != 4:
                    raise ValueError("lease_id_factory must return UUIDv4")
                lease_until = now + lease_ms
                connection.execute(
                    """
                    UPDATE outbox SET state='sending', lease_id=?,
                        lease_until_ms=?, attempts=attempts+1, updated_at_ms=?
                    WHERE id=? AND state='pending'
                    """,
                    (lease_id, lease_until, now, row["id"]),
                )
                claimed.append(
                    {
                        "outbox_id": row["id"],
                        "envelope": json.loads(row["envelope_json"]),
                        "envelope_sha256": row["envelope_sha256"],
                        "lease_id": lease_id,
                        "lease_until_ms": lease_until,
                        "attempt": row["attempts"] + 1,
                    }
                )
        return claimed

    def complete_outbox(
        self,
        outbox_id: int,
        lease_id: str,
        *,
        receipt: dict[str, Any] | None = None,
        error: str | None = None,
        now_ms: int | None = None,
    ) -> str:
        if (receipt is None) == (error is None):
            raise ValueError("provide exactly one of receipt or error")
        now = self.clock_ms() if now_ms is None else now_ms
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT state, lease_id, lease_until_ms, attempts
                FROM outbox WHERE id=?
                """,
                (outbox_id,),
            ).fetchone()
            if (
                not row
                or row["state"] != "sending"
                or row["lease_id"] != lease_id
                or row["lease_until_ms"] <= now
            ):
                raise LeaseConflict("outbox completion has no active lease")
            if receipt is not None:
                state = "sent"
                available_at = now
                receipt_json = protocol.canonical_json(receipt)
                last_error = None
            elif row["attempts"] >= self.max_attempts:
                state = "dead_letter"
                available_at = now
                receipt_json = None
                last_error = "max_attempts"
            else:
                state = "pending"
                available_at = now + min(
                    self.retry_max_ms,
                    self.retry_base_ms * (2 ** max(0, row["attempts"] - 1)),
                )
                receipt_json = None
                last_error = str(error)[:256]
            connection.execute(
                """
                UPDATE outbox SET state=?, available_at_ms=?, lease_id=NULL,
                    lease_until_ms=NULL, receipt_json=?, last_error=?,
                    updated_at_ms=? WHERE id=?
                """,
                (
                    state,
                    available_at,
                    receipt_json,
                    last_error,
                    now,
                    outbox_id,
                ),
            )
            return state

    def maintenance(
        self,
        *,
        terminal_before_ms: int | None = None,
        now_ms: int | None = None,
    ) -> dict[str, int]:
        now = self.clock_ms() if now_ms is None else now_ms
        with self._transaction() as connection:
            self._expire_leases_and_messages(connection, now)
            purged = 0
            if terminal_before_ms is not None:
                cursor = connection.execute(
                    """
                    DELETE FROM messages
                    WHERE NOT EXISTS (
                          SELECT 1 FROM deliveries
                          WHERE deliveries.message_pk=messages.id
                            AND deliveries.state NOT IN (
                                'acknowledged', 'dead_letter'
                            )
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM deliveries
                          WHERE deliveries.message_pk=messages.id
                            AND deliveries.updated_at_ms >= ?
                      )
                    """,
                    (terminal_before_ms,),
                )
                purged = cursor.rowcount
            return {"purged_messages": purged}

    def metrics(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            deliveries = {
                row["state"]: row["count"]
                for row in connection.execute(
                    "SELECT state, count(*) AS count FROM deliveries GROUP BY state"
                )
            }
            outbox = {
                row["state"]: row["count"]
                for row in connection.execute(
                    "SELECT state, count(*) AS count FROM outbox GROUP BY state"
                )
            }
            messages = connection.execute(
                "SELECT count(*) FROM messages"
            ).fetchone()[0]
            return {
                "messages": messages,
                "deliveries": deliveries,
                "outbox": outbox,
                "runtime": self.runtime_info(),
            }

    def integrity_check(self) -> list[str]:
        try:
            with closing(self._connect()) as connection:
                return [
                    row[0]
                    for row in connection.execute("PRAGMA integrity_check")
                ]
        except sqlite3.DatabaseError as exc:
            raise StorageCorruption("SQLite integrity check failed") from exc

    def backup_to(self, destination: Path | str) -> dict[str, Any]:
        destination = Path(destination)
        if destination.exists():
            raise FileExistsError(destination)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            source = self._connect()
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                result = target.execute("PRAGMA integrity_check").fetchone()[0]
                if result != "ok":
                    raise StorageCorruption(
                        f"backup integrity check failed: {result}"
                    )
            finally:
                target.close()
                source.close()
            os.chmod(temporary, 0o600)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return {
                "path": str(destination),
                "bytes": destination.stat().st_size,
                "sha256": sha256(destination.read_bytes()).hexdigest(),
            }
        finally:
            temporary.unlink(missing_ok=True)
