#!/usr/bin/env python3
"""Send an encrypted, signed message to a tribe agent.

Usage:
  TRIBE_AGENT_NAME=compaii python3 scripts/send.py --to oliva --text "hola"
  python3 scripts/send.py --to oliva --text "hola" --sender compaii \
    --direct 10.8.0.5:8585 --hub 144.217.95.152:8587

Requires TRIBE_AGENT_NAME or --sender to be set.
"""
import argparse
import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from client_common import (
    BridgeRequestError,
    load_roster,
    post_envelope,
    roster_address,
)


DEFAULT_HUB = "144.217.95.152:8585"


def sign_data(data: str, key_path: Optional[str] = None) -> tuple:
    key = (
        key_path
        or os.environ.get("TRIBE_SSH_KEY")
        or str(Path.home() / ".ssh" / "id_ed25519")
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        result = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", key, "-n", "tribe-bridge", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ssh-keygen failed: {result.stderr.strip()}")
        sig = Path(path + ".sig").read_text().strip()
        return base64.b64encode(sig.encode()).decode(), "sender"
    finally:
        Path(path).unlink(missing_ok=True)
        Path(path + ".sig").unlink(missing_ok=True)


def load_lcm_module():
    """Import lcm-server.py from this checkout."""
    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("lcm", repo / "src" / "lcm-server.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load src/lcm-server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve_endpoints(
    recipient: str,
    direct_override: Optional[str] = None,
    hub_override: Optional[str] = None,
) -> Tuple[Optional[str], str]:
    """Resolve direct and hub endpoints while preserving flat roster support."""
    roster = load_roster("TRIBE_ROSTER")
    hub_roster = load_roster("TRIBE_HUB_ROSTER")

    direct = (
        direct_override
        or roster_address(roster, recipient, "direct")
        or roster_address(roster, recipient)
    )
    hub = (
        hub_override
        or roster_address(hub_roster, recipient, "hub")
        or roster_address(hub_roster, recipient)
        or roster_address(roster, recipient, "hub")
        or os.environ.get("TRIBE_HUB")
        or DEFAULT_HUB
    )
    return direct, hub


def build_envelope(
    lcm_module,
    payload: Dict[str, Any],
    signer: str,
    key_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Encrypt and sign a plaintext payload."""
    encrypted = lcm_module.encrypt_payload(json.dumps(payload))
    ciphertext_wrapper = json.dumps(
        {
            "ciphertext": encrypted["ciphertext"],
            "nonce": encrypted["nonce"],
            "tag": encrypted["tag"],
        },
        separators=(",", ":"),
    )
    signature_b64, _ = sign_data(ciphertext_wrapper, key_path)
    return {
        "ciphertext": encrypted["ciphertext"],
        "nonce": encrypted["nonce"],
        "tag": encrypted["tag"],
        "signature": base64.b64decode(signature_b64).decode(),
        "signer": signer,
    }


def deliver_message(
    recipient: str,
    text: str,
    sender: str,
    direct: Optional[str],
    hub: str,
    key_path: Optional[str] = None,
    direct_timeout: float = 4.0,
    hub_timeout: float = 10.0,
    lcm_module=None,
) -> Tuple[str, Dict[str, Any], str]:
    """Try direct delivery and fall back to the recipient's hub inbox."""
    lcm_module = lcm_module or load_lcm_module()
    message_id = str(uuid.uuid4())
    base_payload = {
        "from": sender,
        "to": recipient,
        "text": text,
        "ts": int(time.time()),
        "message_id": message_id,
        # v0 has no confidentiality: every message is in the tribe-public
        # trust domain, including messages copied to Telegram.
        "classification": "tribe-public",
    }

    if direct:
        direct_payload = {**base_payload, "via": "direct"}
        direct_envelope = build_envelope(
            lcm_module, direct_payload, sender, key_path
        )
        try:
            result = post_envelope(direct, direct_envelope, direct_timeout)
            return "direct", result, message_id
        except BridgeRequestError as exc:
            print(
                f"Direct delivery failed ({exc}); falling back to hub.",
                file=sys.stderr,
            )

    hub_payload = {**base_payload, "via": "hub"}
    hub_envelope = build_envelope(lcm_module, hub_payload, sender, key_path)
    result = post_envelope(hub, hub_envelope, hub_timeout)
    return "hub", result, message_id


def main():
    p = argparse.ArgumentParser(
        description="Send an encrypted message through Tribe Bridge"
    )
    p.add_argument("--to", required=True, help="Recipient agent name")
    p.add_argument("--text", required=True, help="Message body")
    p.add_argument(
        "--sender",
        "--from",
        dest="sender",
        help="Sender name (default: $TRIBE_AGENT_NAME)",
    )
    p.add_argument(
        "--direct",
        help="Recipient's direct anyVPN address (default: $TRIBE_ROSTER)",
    )
    p.add_argument(
        "--hub",
        help="Recipient's hub address (default: $TRIBE_HUB_ROSTER or $TRIBE_HUB)",
    )
    p.add_argument("--key", help="SSH key path (default: ~/.ssh/id_ed25519)")
    p.add_argument(
        "--direct-timeout",
        type=float,
        default=4.0,
        help="Direct delivery timeout in seconds (default: 4)",
    )
    p.add_argument(
        "--hub-timeout",
        type=float,
        default=10.0,
        help="Hub delivery timeout in seconds (default: 10)",
    )
    args = p.parse_args()

    agent_name = args.sender or os.environ.get("TRIBE_AGENT_NAME")
    if not agent_name:
        p.error("--sender or TRIBE_AGENT_NAME is required")

    try:
        direct, hub = resolve_endpoints(args.to, args.direct, args.hub)
        route, result, message_id = deliver_message(
            recipient=args.to,
            text=args.text,
            sender=agent_name,
            direct=direct,
            hub=hub,
            key_path=args.key,
            direct_timeout=args.direct_timeout,
            hub_timeout=args.hub_timeout,
        )
    except (BridgeRequestError, RuntimeError, ValueError) as exc:
        sys.exit(f"Delivery failed: {exc}")

    print(
        f"Sent: {result.get('id', result)} via {route} "
        f"(message_id={message_id})"
    )

if __name__ == "__main__":
    main()
