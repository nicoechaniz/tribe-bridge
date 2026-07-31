#!/usr/bin/env python3
"""Drain and merge local and hub Tribe Bridge inboxes.

Usage:
  TRIBE_AGENT_NAME=compaii python3 scripts/check_inbox.py
  TRIBE_AGENT_NAME=compaii python3 scripts/check_inbox.py --hub 144.217.95.152:8586
  TRIBE_AGENT_NAME=compaii python3 scripts/check_inbox.py --json

Messages delivered directly are re-posted to the hub with their original
encrypted envelope and signature. A local state file provides drain semantics
without requiring server-side deletion.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from client_common import (
    BridgeRequestError,
    endpoint_key,
    endpoint_url,
    envelope_from_record,
    load_roster,
    logical_message_id,
    post_envelope,
    roster_address,
)


DEFAULT_LOCAL = "127.0.0.1:8585"
DEFAULT_STATE_FILE = "~/.tribe-bridge/check-inbox-state.json"
SERVER_FETCH_LIMIT = 100


def sign_get(
    path: str,
    key_path: Optional[str] = None,
    signer: Optional[str] = None,
) -> Tuple[str, str]:
    """Sign a GET request path (query parameters are intentionally excluded)."""
    key = os.path.expanduser(
        key_path
        or os.environ.get("TRIBE_SSH_KEY", "~/.ssh/id_ed25519")
    )
    base_path = path.split("?")[0]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as file:
        file.write(f"GET {base_path}")
        temporary_path = file.name
    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                key,
                "-n",
                "tribe-bridge",
                temporary_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ssh-keygen failed: {result.stderr.strip()}")
        armored = Path(temporary_path + ".sig").read_text().strip()
        encoded = base64.b64encode(armored.encode()).decode()
        return encoded, signer or os.environ.get("TRIBE_AGENT_NAME", "unknown")
    finally:
        Path(temporary_path).unlink(missing_ok=True)
        Path(temporary_path + ".sig").unlink(missing_ok=True)


def fetch_inbox(
    address: str,
    since: int,
    limit: int,
    key_path: Optional[str] = None,
    signer: Optional[str] = None,
    timeout: float = 10.0,
) -> List[Dict[str, Any]]:
    """Fetch and decrypt messages from one LCM endpoint."""
    path = f"/inbox?decrypt=true&since={since}&limit={limit}"
    signature, signer_name = sign_get(path, key_path, signer)
    request = urllib.request.Request(
        endpoint_url(address, path),
        headers={
            "X-Tribe-Signature": signature,
            "X-Tribe-Signer": signer_name,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BridgeRequestError(
            f"{address} rejected the inbox read: HTTP {exc.code} - {detail}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BridgeRequestError(f"{address} is unavailable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BridgeRequestError(
            f"{address} returned an invalid inbox response"
        ) from exc

    if not isinstance(data, dict):
        raise BridgeRequestError(f"{address} returned an invalid inbox response")
    messages = data.get("messages", [])
    if not isinstance(messages, list):
        raise BridgeRequestError(f"{address} returned an invalid inbox response")
    return messages


def resolve_endpoints(
    agent: str,
    local_override: Optional[str] = None,
    hub_override: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """Resolve the agent's local and hub inbox endpoints."""
    roster = load_roster("TRIBE_ROSTER")
    hub_roster = load_roster("TRIBE_HUB_ROSTER")
    local = local_override or os.environ.get("TRIBE_LOCAL") or DEFAULT_LOCAL
    hub = (
        hub_override
        or roster_address(hub_roster, agent, "hub")
        or roster_address(hub_roster, agent)
        or roster_address(roster, agent, "hub")
        or os.environ.get("TRIBE_HUB")
    )
    endpoint_key(local)
    if hub:
        endpoint_key(hub)
    return local, hub


def load_state(path: Path) -> Dict[str, Set[str]]:
    """Load persistent drain and mirror state."""
    if not path.exists():
        return {"seen_ids": set(), "mirrored_ids": set()}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read state file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuntimeError(f"state file {path} must contain a JSON object")
    seen_ids = raw.get("seen_ids", [])
    mirrored_ids = raw.get("mirrored_ids", [])
    if not isinstance(seen_ids, list) or not isinstance(mirrored_ids, list):
        raise RuntimeError(f"state file {path} contains invalid ID lists")
    return {
        "seen_ids": set(seen_ids),
        "mirrored_ids": set(mirrored_ids),
    }


def save_state(path: Path, state: Dict[str, Set[str]]) -> None:
    """Atomically persist drain and mirror state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "seen_ids": sorted(state["seen_ids"]),
        "mirrored_ids": sorted(state["mirrored_ids"]),
    }
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    ) as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        temporary_path = Path(file.name)
    temporary_path.replace(path)


def merge_messages(
    local_messages: Iterable[Dict[str, Any]],
    hub_messages: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge inbox records by stable logical message ID."""
    merged: Dict[str, Dict[str, Any]] = {}
    for message in list(local_messages) + list(hub_messages):
        merged.setdefault(logical_message_id(message), message)
    return sorted(
        merged.values(),
        key=lambda message: (
            message.get("received_at", 0),
            logical_message_id(message),
        ),
    )


def mirror_direct_messages(
    local_messages: Iterable[Dict[str, Any]],
    hub_messages: Iterable[Dict[str, Any]],
    hub_address: Optional[str],
    mirrored_ids: Set[str],
    timeout: float,
) -> List[str]:
    """Re-post unseen direct envelopes to the hub and return warning strings."""
    warnings: List[str] = []
    hub_ids = {logical_message_id(message) for message in hub_messages}

    for message in local_messages:
        decrypted = message.get("decrypted")
        if not isinstance(decrypted, dict) or decrypted.get("via") != "direct":
            continue

        message_key = logical_message_id(message)
        if message_key in hub_ids:
            mirrored_ids.add(message_key)
            continue
        if message_key in mirrored_ids:
            continue
        if not hub_address:
            warnings.append(
                f"cannot mirror {message_key}: no hub endpoint is configured"
            )
            continue

        try:
            envelope = envelope_from_record(message)
            post_envelope(hub_address, envelope, timeout)
        except (BridgeRequestError, ValueError) as exc:
            warnings.append(f"could not mirror {message_key}: {exc}")
            continue

        mirrored_ids.add(message_key)
        hub_ids.add(message_key)

    return warnings


def drain_messages(
    local_messages: List[Dict[str, Any]],
    hub_messages: List[Dict[str, Any]],
    state: Dict[str, Set[str]],
    limit: int,
) -> List[Dict[str, Any]]:
    """Return unseen merged records and mark the selected records as drained."""
    merged = merge_messages(local_messages, hub_messages)
    unseen = [
        message
        for message in merged
        if logical_message_id(message) not in state["seen_ids"]
    ]
    selected = unseen[-limit:]
    state["seen_ids"].update(logical_message_id(message) for message in selected)
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drain local and hub Tribe Bridge inboxes"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON"
    )
    parser.add_argument(
        "--since", type=int, default=0, help="Only messages after this timestamp"
    )
    parser.add_argument(
        "--limit", type=int, default=10, help="Maximum merged messages to return"
    )
    parser.add_argument(
        "--local",
        help="Local LCM address (default: $TRIBE_LOCAL or 127.0.0.1:8585)",
    )
    parser.add_argument(
        "--hub",
        help="Hub address (default: $TRIBE_HUB_ROSTER or $TRIBE_HUB)",
    )
    parser.add_argument("--key", help="SSH key path (default: $TRIBE_SSH_KEY)")
    parser.add_argument(
        "--state-file",
        default=os.environ.get("TRIBE_STATE_FILE", DEFAULT_STATE_FILE),
        help="Persistent drain state file",
    )
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="Disable persistent drain and mirror state",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds"
    )
    args = parser.parse_args()

    if args.limit < 1 or args.limit > 100:
        parser.error("--limit must be between 1 and 100")

    agent = os.environ.get("TRIBE_AGENT_NAME", "")
    if not agent:
        parser.error("TRIBE_AGENT_NAME is required")

    try:
        local_address, hub_address = resolve_endpoints(
            agent, args.local, args.hub
        )
        state_path = Path(os.path.expanduser(args.state_file))
        state = (
            {"seen_ids": set(), "mirrored_ids": set()}
            if args.no_state
            else load_state(state_path)
        )
    except (RuntimeError, ValueError) as exc:
        sys.exit(f"Inbox check failed: {exc}")

    local_messages: List[Dict[str, Any]] = []
    hub_messages: List[Dict[str, Any]] = []
    warnings: List[str] = []
    successful_reads = 0

    try:
        local_messages = fetch_inbox(
            local_address,
            args.since,
            SERVER_FETCH_LIMIT,
            args.key,
            agent,
            args.timeout,
        )
        successful_reads += 1
    except (BridgeRequestError, RuntimeError) as exc:
        warnings.append(f"local inbox: {exc}")

    same_endpoint = bool(
        hub_address and endpoint_key(local_address) == endpoint_key(hub_address)
    )
    if same_endpoint:
        hub_messages = local_messages
    elif hub_address:
        try:
            hub_messages = fetch_inbox(
                hub_address,
                args.since,
                SERVER_FETCH_LIMIT,
                args.key,
                agent,
                args.timeout,
            )
            successful_reads += 1
        except (BridgeRequestError, RuntimeError) as exc:
            warnings.append(f"hub inbox: {exc}")

    if successful_reads == 0:
        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)
        sys.exit("Inbox check failed: no configured inbox could be read")

    if not same_endpoint:
        warnings.extend(
            mirror_direct_messages(
                local_messages,
                hub_messages,
                hub_address,
                state["mirrored_ids"],
                args.timeout,
            )
        )

    messages = drain_messages(local_messages, hub_messages, state, args.limit)

    if not args.no_state:
        try:
            save_state(state_path, state)
        except OSError as exc:
            sys.exit(f"Inbox check failed: could not save state: {exc}")

    for warning in warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    if args.json:
        output: Dict[str, Any] = {
            "messages": messages,
            "count": len(messages),
        }
        if warnings:
            output["warnings"] = warnings
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    print(f"{len(messages)} messages:")
    for message in messages:
        payload = message.get("decrypted", message)
        print(
            f"  [{payload.get('from', '?')} → {payload.get('to', '?')}] "
            f"{payload.get('text', '')}"
        )


if __name__ == "__main__":
    main()
