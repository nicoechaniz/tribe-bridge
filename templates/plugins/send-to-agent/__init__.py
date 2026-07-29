"""send-to-agent — Tribe Bridge messaging plugin for Hermes Agent.

Sends SSH-signed messages to other tribe agents through the LCM network.
Messages are cryptographically signed with the agent's SSH private key
and verified by the receiver against the allowed_signers roster.

Environment:
  TRIBE_AGENT_NAME     — this agent's name (e.g. "compaii")
  TRIBE_ROSTER         — JSON: agent → {"ip": "10.10.20.x", "pubkey": "ssh-ed25519 AAAAC3..."}
  TRIBE_SSH_KEY        — path to SSH private key for signing (default ~/.ssh/id_ed25519)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import urllib.request
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

SEND_TO_AGENT_SCHEMA = {
    "name": "send_to_agent",
    "description": (
        "Send a message to another tribe agent via the Tribe Bridge LCM "
        "network. Messages are cryptographically signed with SSH. "
        "This tool never fires autonomously — only when the human asks.\n\n"
        "Usage: send_to_agent(to='oliva', text='¿cómo va el render?')\n"
        "       send_to_agent(to='ani', text='...', reply_to='msg-123')"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {"type": "string", "description": "Target agent name"},
            "text": {"type": "string", "description": "Message text to send"},
            "reply_to": {"type": "string", "description": "Optional message ID to reply to"},
        },
        "required": ["to", "text"],
    },
}

CHECK_INBOX_SCHEMA = {
    "name": "check_inbox",
    "description": (
        "Check the Tribe Bridge inbox for messages from other agents. "
        "Use when the human asks 'did anyone respond?' or 'check my inbox'."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "agent": {"type": "string", "description": "Filter by sender agent (optional)"},
            "since": {"type": "integer", "description": "Unix timestamp — only messages after this"},
        },
    },
}


def _load_roster() -> Dict[str, dict]:
    raw = os.environ.get("TRIBE_ROSTER", "{}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("TRIBE_ROSTER is not valid JSON")
        return {}


def _sign_payload(payload: dict) -> tuple[str, str]:
    """Sign a JSON payload with SSH. Returns (signature_armored, signer_name).

    Uses ssh-keygen -Y sign with the tribe-bridge namespace.
    """
    key_path = os.path.expanduser(
        os.environ.get("TRIBE_SSH_KEY", "~/.ssh/id_ed25519")
    )
    agent_name = os.environ.get("TRIBE_AGENT_NAME", "")
    namespace = "tribe-bridge"

    payload_json = json.dumps(payload, separators=(",", ":"))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        pf.write(payload_json)
        payload_path = pf.name

    try:
        result = subprocess.run(
            [
                "ssh-keygen", "-Y", "sign",
                "-f", key_path,
                "-n", namespace,
                payload_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ssh-keygen sign failed: {result.stderr}")

        # ssh-keygen outputs the signature to stdout, armored format
        signature = result.stdout.strip()
        return signature, agent_name
    finally:
        import os as _os
        _os.unlink(payload_path)


def _send_lcm(target_ip: str, port: int, payload: dict,
              signature: str, signer: str) -> dict:
    """POST a signed message to a tribe agent's LCM server."""
    envelope = {
        "payload": payload,
        "signature": signature,
        "signer": signer,
    }
    url = f"http://{target_ip}:{port}/send"
    data = json.dumps(envelope).encode("utf-8")

    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        raise ConnectionError(f"{target_ip}:{port} returned {exc.code}: {body}")
    except urllib.error.URLError as exc:
        raise ConnectionError(f"cannot reach {target_ip}:{port}: {exc}")


def _check_inbox(agent_filter: str = None, since: int = None) -> List[dict]:
    """GET /inbox from this agent's own LCM server."""
    port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
    url = f"http://127.0.0.1:{port}/inbox"
    params = []
    if agent_filter:
        params.append(f"agent={agent_filter}")
    if since:
        params.append(f"since={since}")
    if params:
        url += "?" + "&".join(params)
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("messages", [])
    except Exception as exc:
        logger.warning(f"check_inbox failed: {exc}")
        return []


class SendToAgentProvider:

    @property
    def name(self) -> str:
        return "send-to-agent"

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [SEND_TO_AGENT_SCHEMA, CHECK_INBOX_SCHEMA]

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any],
                         **kwargs) -> str:
        agent_name = os.environ.get("TRIBE_AGENT_NAME", "")
        if not agent_name:
            return json.dumps(
                {"success": False, "error": "TRIBE_AGENT_NAME not set"},
                ensure_ascii=False)

        if tool_name == "send_to_agent":
            target = args.get("to", "").strip()
            text = args.get("text", "").strip()
            reply_to = args.get("reply_to")

            if not target or not text:
                return json.dumps(
                    {"success": False, "error": "to and text are required"},
                    ensure_ascii=False)

            roster = _load_roster()
            entry = roster.get(target)
            if not entry:
                return json.dumps(
                    {"success": False,
                     "error": f"unknown agent '{target}'. Known: {list(roster)}"},
                    ensure_ascii=False)

            target_ip = entry.get("ip") if isinstance(entry, dict) else entry
            port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))

            payload = {"from": agent_name, "to": target, "text": text,
                       "ts": int(__import__("time").time())}
            if reply_to:
                payload["reply_to"] = reply_to

            try:
                signature, signer = _sign_payload(payload)
                result = _send_lcm(target_ip, port, payload, signature, signer)
                return json.dumps(
                    {"success": True, "message_id": result.get("id"),
                     "to": target, "from": agent_name},
                    ensure_ascii=False)
            except (ConnectionError, RuntimeError) as exc:
                return json.dumps(
                    {"success": False, "error": str(exc)},
                    ensure_ascii=False)

        if tool_name == "check_inbox":
            agent_filter = args.get("agent")
            since = args.get("since")
            messages = _check_inbox(agent_filter, since)
            return json.dumps(
                {"success": True, "messages": messages, "count": len(messages)},
                ensure_ascii=False)

        return json.dumps(
            {"success": False, "error": f"unknown tool: {tool_name}"},
            ensure_ascii=False)


def register(ctx):
    ctx.register_tool_provider(SendToAgentProvider())
