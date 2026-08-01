"""Fail-closed embodiment-locality policy shared by Tribe v1 components."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import tribe_protocol_v1 as protocol


LOCALHOST_SUFFIX = "@localhost"


class LocalityPolicyError(ValueError):
    pass


def parse_local_agent_ids(raw: str) -> frozenset[str]:
    """Parse the broker/harness-owned set of principals on this machine."""
    try:
        value: Any = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise LocalityPolicyError(
            "TRIBE_V1_LOCAL_AGENT_IDS must be a JSON array"
        ) from exc
    if not isinstance(value, list) or not value:
        raise LocalityPolicyError(
            "TRIBE_V1_LOCAL_AGENT_IDS must be a non-empty JSON array"
        )
    if any(
        not isinstance(item, str)
        or not protocol.IDENTIFIER.fullmatch(item)
        for item in value
    ):
        raise LocalityPolicyError("invalid local agent ID")
    if len(set(value)) != len(value):
        raise LocalityPolicyError("duplicate local agent ID")
    return frozenset(value)


def enforce_localhost_boundary(
    sender_id: str,
    recipient_ids: Iterable[str],
    local_agent_ids: frozenset[str],
) -> None:
    """Keep ``*@localhost`` senders and every HPKE wrap on one machine."""
    if not sender_id.endswith(LOCALHOST_SUFFIX):
        return
    recipients = frozenset(recipient_ids)
    if (
        sender_id not in local_agent_ids
        or not recipients
        or not recipients <= local_agent_ids
    ):
        raise LocalityPolicyError(
            "localhost principal cannot address a remote or mixed audience"
        )
