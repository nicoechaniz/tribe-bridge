"""Fail-closed Telegram rendering policy for an explicit Tribe v1 recipient."""

from __future__ import annotations

import hashlib
import html
import json
import sqlite3
import urllib.error
import urllib.request
from bisect import bisect_right
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tribe_protocol_v1 as protocol


class MirrorPolicyError(ValueError):
    pass


_ALLOWED_AUDIENCE_TYPES = frozenset({"group", "direct"})
_ALLOWED_CLASSIFICATIONS = frozenset({"tribe-public", "private"})

# Telegram's Bot API rejects sendMessage texts over 4096 characters
# (https://core.telegram.org/bots/api#sendmessage). Each mirrored part must
# stay under this limit, so long payloads are chunked (issue #44).
TELEGRAM_MESSAGE_LIMIT = 4096
# Conservative escaped-body budget per part: leaves ample headroom for the
# provenance header and the "part i/n" suffix while keeping every rendered
# part comfortably below TELEGRAM_MESSAGE_LIMIT.
_ESCAPED_BODY_BUDGET = 3500
# Human-readable messages may still span a few Telegram posts.  Beyond this
# bound the mirror emits one content-addressed notice instead of turning a
# machine artifact into a wall of opaque fragments.
MAX_MIRROR_PARTS = 8
_OPAQUE_ARTIFACT_MIN_CHARS = 7000


class MirrorDeliveryError(RuntimeError):
    """A retryable Telegram part failed without exposing its contents."""

    def __init__(self, part_index: int, total_parts: int):
        super().__init__("Telegram delivery unavailable")
        self.part_index = part_index
        self.total_parts = total_parts

    def failure_record(self, *, endpoint: str, message_id: str) -> dict[str, Any]:
        return {
            "endpoint": endpoint,
            "message_id": message_id,
            "failed_part_index": self.part_index,
            "total_parts": self.total_parts,
            "error": "telegram_delivery_retryable",
        }


class MirrorProgressStore:
    """Durable cursor for one deterministic Telegram rendering.

    The cursor is advanced only after Telegram confirms a part.  Retrying an
    interrupted claim therefore resumes at the first unconfirmed part instead
    of replaying the already confirmed prefix.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mirror_part_progress(
                    sender_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    envelope_sha256 TEXT NOT NULL,
                    rendered_sha256 TEXT NOT NULL,
                    total_parts INTEGER NOT NULL CHECK(total_parts > 0),
                    next_part_index INTEGER NOT NULL CHECK(
                        next_part_index >= 0 AND next_part_index <= total_parts
                    ),
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(sender_id, message_id)
                ) STRICT
                """
            )
            connection.commit()
        self.path.chmod(0o600)

    @staticmethod
    def _rendered_sha256(parts: list[str]) -> str:
        if not parts or any(not isinstance(part, str) for part in parts):
            raise MirrorPolicyError("invalid rendered Telegram parts")
        encoded = json.dumps(
            parts, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def resume(
        self,
        sender_id: str,
        message_id: str,
        envelope_sha256: str,
        parts: list[str],
        *,
        now_ms: int,
    ) -> int:
        rendered_sha256 = self._rendered_sha256(parts)
        with closing(
            sqlite3.connect(self.path, isolation_level=None)
        ) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT envelope_sha256, rendered_sha256,
                           total_parts, next_part_index
                    FROM mirror_part_progress
                    WHERE sender_id=? AND message_id=?
                    """,
                    (sender_id, message_id),
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO mirror_part_progress(
                            sender_id, message_id, envelope_sha256,
                            rendered_sha256, total_parts, next_part_index,
                            updated_at_ms
                        ) VALUES(?, ?, ?, ?, ?, 0, ?)
                        """,
                        (
                            sender_id,
                            message_id,
                            envelope_sha256,
                            rendered_sha256,
                            len(parts),
                            now_ms,
                        ),
                    )
                    connection.execute("COMMIT")
                    return 0
                if (
                    row["envelope_sha256"] != envelope_sha256
                    or row["rendered_sha256"] != rendered_sha256
                    or row["total_parts"] != len(parts)
                ):
                    raise MirrorPolicyError(
                        "retry rendering differs from persisted progress"
                    )
                next_part_index = int(row["next_part_index"])
                connection.execute("COMMIT")
                return next_part_index
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def advance(
        self,
        sender_id: str,
        message_id: str,
        envelope_sha256: str,
        parts: list[str],
        *,
        delivered_index: int,
        now_ms: int,
    ) -> None:
        rendered_sha256 = self._rendered_sha256(parts)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            updated = connection.execute(
                """
                UPDATE mirror_part_progress
                SET next_part_index=?, updated_at_ms=?
                WHERE sender_id=? AND message_id=?
                  AND envelope_sha256=? AND rendered_sha256=?
                  AND total_parts=? AND next_part_index=?
                """,
                (
                    delivered_index + 1,
                    now_ms,
                    sender_id,
                    message_id,
                    envelope_sha256,
                    rendered_sha256,
                    len(parts),
                    delivered_index,
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("mirror part cursor changed concurrently")
            connection.commit()

    def clear(self, sender_id: str, message_id: str) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                DELETE FROM mirror_part_progress
                WHERE sender_id=? AND message_id=?
                """,
                (sender_id, message_id),
            )
            connection.commit()


def deliver_rendered_parts(
    progress: MirrorProgressStore,
    *,
    sender_id: str,
    message_id: str,
    envelope_sha256: str,
    parts: list[str],
    send: Callable[[str], Any],
    now_ms: int,
) -> None:
    """Resume one deterministic rendering at its first unconfirmed part."""
    next_part_index = progress.resume(
        sender_id,
        message_id,
        envelope_sha256,
        parts,
        now_ms=now_ms,
    )
    for index in range(next_part_index, len(parts)):
        try:
            send(parts[index])
        except RuntimeError as exc:
            raise MirrorDeliveryError(index + 1, len(parts)) from exc
        progress.advance(
            sender_id,
            message_id,
            envelope_sha256,
            parts,
            delivered_index=index,
            now_ms=now_ms,
        )


@dataclass(frozen=True)
class TelegramPolicy:
    allowed_chat_ids: frozenset[int]
    allowed_user_ids: frozenset[int]
    allowed_audiences: frozenset[str]
    allowed_audience_types: frozenset[str]
    allowed_classifications: frozenset[str]

    @classmethod
    def from_values(
        cls,
        *,
        chat_ids: list[int],
        user_ids: list[int],
        audiences: list[str],
        audience_types: list[str] | None = None,
        classifications: list[str] | None = None,
    ) -> "TelegramPolicy":
        if audience_types is None:
            audience_types = ["group"]
        if classifications is None:
            classifications = ["tribe-public"]
        if (
            not chat_ids
            or not user_ids
            or not audiences
            or not audience_types
            or not classifications
        ):
            raise MirrorPolicyError(
                "mirror allowlists must be non-empty"
            )
        if any(not isinstance(value, int) for value in chat_ids + user_ids):
            raise MirrorPolicyError("Telegram IDs must be integers")
        for audience in audiences:
            if not protocol.IDENTIFIER.fullmatch(audience):
                raise MirrorPolicyError("invalid allowed audience")
        if (
            not isinstance(audience_types, list)
            or any(not isinstance(value, str) for value in audience_types)
            or not set(audience_types) <= _ALLOWED_AUDIENCE_TYPES
        ):
            raise MirrorPolicyError("invalid allowed audience types")
        if (
            not isinstance(classifications, list)
            or any(not isinstance(value, str) for value in classifications)
            or not set(classifications) <= _ALLOWED_CLASSIFICATIONS
        ):
            raise MirrorPolicyError("invalid allowed classifications")
        return cls(
            frozenset(chat_ids),
            frozenset(user_ids),
            frozenset(audiences),
            frozenset(audience_types),
            frozenset(classifications),
        )

    def _validate_render(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> None:
        audience = envelope["audience"]
        if (
            audience["type"] not in self.allowed_audience_types
            or audience["id"] not in self.allowed_audiences
            or payload.get("classification") not in self.allowed_classifications
            or payload.get("schema") != "tribe-message/v1"
            or payload.get("from") != envelope["sender"]["id"]
            or payload.get("to") != audience["id"]
            or not isinstance(payload.get("text"), str)
        ):
            raise MirrorPolicyError(
                "mirror only emits explicitly allowed tribe messages"
            )

    @staticmethod
    def _provenance(envelope: dict[str, Any]) -> str:
        audience = envelope["audience"]
        return (
            f'Tribe v1 · {envelope["sender"]["id"]} → {audience["id"]} · '
            f'{envelope["message_id"]}'
        )

    @staticmethod
    def _chunk_text(text: str) -> list[str]:
        """Split raw text so every chunk's escaped form fits the budget.

        Chunking happens on the raw text with a running escaped-length
        prefix, so an HTML entity is never split across parts.
        """
        if not text:
            return [""]
        prefix = [0]
        for char in text:
            prefix.append(prefix[-1] + len(html.escape(char)))
        chunks = []
        start = 0
        while start < len(text):
            end = (
                bisect_right(prefix, prefix[start] + _ESCAPED_BODY_BUDGET)
                - 1
            )
            end = max(end, start + 1)  # always make progress
            chunks.append(text[start:end])
            start = end
        return chunks

    @staticmethod
    def _looks_like_opaque_artifact(text: str) -> bool:
        if len(text) < _OPAQUE_ARTIFACT_MIN_CHARS:
            return False
        compact = "".join(text.split())
        if not compact:
            return False
        base64_chars = frozenset(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "0123456789+/=_-"
        )
        opaque_fraction = sum(char in base64_chars for char in compact) / len(
            compact
        )
        return opaque_fraction >= 0.98

    @classmethod
    def _suppressed_artifact_notice(
        cls, text: str, envelope: dict[str, Any]
    ) -> str:
        provenance = cls._provenance(envelope)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return (
            f"<b>{html.escape(provenance)}</b>\n"
            "Large or opaque payload omitted from Telegram; use an approved "
            f"artifact channel · characters {len(text)} · sha256 {digest}"
        )

    def render(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> str:
        parts = self.render_parts(payload, envelope)
        if len(parts) != 1:
            raise MirrorPolicyError(
                "payload too large for a single Telegram message; "
                "use render_parts"
            )
        return parts[0]

    def render_parts(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> list[str]:
        """Render as one or more Telegram-safe messages (issue #44)."""
        self._validate_render(payload, envelope)
        provenance = self._provenance(envelope)
        text = payload["text"]
        chunks = self._chunk_text(text)
        if len(chunks) > MAX_MIRROR_PARTS or self._looks_like_opaque_artifact(
            text
        ):
            return [self._suppressed_artifact_notice(text, envelope)]
        if len(chunks) == 1:
            header = f"<b>{html.escape(provenance)}</b>\n"
            return [f"{header}{html.escape(chunks[0])}"]
        total = len(chunks)
        return [
            f"<b>{html.escape(provenance)} · part {index}/{total}</b>\n"
            f"{html.escape(chunk)}"
            for index, chunk in enumerate(chunks, 1)
        ]

    def validate_inbound_update(
        self, update: dict[str, Any]
    ) -> dict[str, Any]:
        message = update.get("message")
        if not isinstance(message, dict):
            raise MirrorPolicyError("update has no message")
        chat_id = message.get("chat", {}).get("id")
        user_id = message.get("from", {}).get("id")
        text = message.get("text")
        if (
            chat_id not in self.allowed_chat_ids
            or user_id not in self.allowed_user_ids
            or not isinstance(text, str)
            or not text.strip()
        ):
            raise MirrorPolicyError("Telegram source is not allowed")
        return {
            "chat_id": chat_id,
            "user_id": user_id,
            "text": text.strip(),
            "provenance": {
                "telegram_update_id": update.get("update_id"),
                "telegram_message_id": message.get("message_id"),
            },
        }


class TelegramClient:
    def __init__(
        self,
        token: str,
        chat_id: int,
        policy: TelegramPolicy,
        *,
        timeout: float = 10,
    ):
        if not token or chat_id not in policy.allowed_chat_ids:
            raise MirrorPolicyError("Telegram destination is not allowed")
        self._url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.policy = policy
        self.timeout = timeout

    def send_rendered(self, rendered_html: str) -> dict[str, Any]:
        body = json.dumps(
            {
                "chat_id": self.chat_id,
                "text": rendered_html,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout
            ) as response:
                value = json.loads(response.read(1024 * 1024))
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            raise RuntimeError("Telegram delivery unavailable") from exc
        if not isinstance(value, dict) or value.get("ok") is not True:
            raise RuntimeError("Telegram rejected mirrored message")
        return value
