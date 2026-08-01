"""Fail-closed Telegram rendering policy for an explicit Tribe v1 recipient."""

from __future__ import annotations

import html
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import tribe_protocol_v1 as protocol


class MirrorPolicyError(ValueError):
    pass


_ALLOWED_AUDIENCE_TYPES = frozenset({"group", "direct"})
_ALLOWED_CLASSIFICATIONS = frozenset({"tribe-public", "private"})


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

    def render(
        self,
        payload: dict[str, Any],
        envelope: dict[str, Any],
    ) -> str:
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
        provenance = (
            f'Tribe v1 · {envelope["sender"]["id"]} → {audience["id"]} · '
            f'{envelope["message_id"]}'
        )
        return (
            f"<b>{html.escape(provenance)}</b>\n"
            f"{html.escape(payload['text'])}"
        )

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
