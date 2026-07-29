"""send-to-agent — Tribe Bridge messaging plugin for Hermes Agent.

Exposes a `send_to_agent` tool so agents can message each other
through the Tribe Bridge LCM network.  The tool only fires when
the human explicitly asks — never autonomously.

Environment:
  TRIBE_AGENT_NAME   — this agent's name (e.g. "compaii")
  TRIBE_ROSTER       — JSON mapping agent names to AnyVPN IPs
                       e.g. {"oliva": "10.8.0.5", "ani": "10.8.0.6"}
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

SEND_TO_AGENT_SCHEMA = {
    "name": "send_to_agent",
    "description": (
        "Send a message to another tribe agent via the Tribe Bridge LCM "
        "network. Messages are delivered to the target agent's inbox and "
        "mirrored to the Telegram group for human visibility. "
        "This tool never fires autonomously — only when the human asks.\n\n"
        "Usage: send_to_agent(to='oliva', text='¿cómo va el render?')\n"
        "       send_to_agent(to='ani', text='...', reply_to='msg-123')"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {
                "type": "string",
                "description": "Target agent name (e.g. 'oliva', 'ani')",
            },
            "text": {
                "type": "string",
                "description": "Message text to send",
            },
            "reply_to": {
                "type": "string",
                "description": "Optional message ID this is replying to",
            },
        },
        "required": ["to", "text"],
    },
}

CHECK_INBOX_SCHEMA = {
    "name": "check_inbox",
    "description": (
        "Check the Tribe Bridge inbox for messages from other agents. "
        "Returns recent messages. Use when the human asks 'did anyone respond?' "
        "or '¿respondió?' or 'check my inbox'."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "agent": {
                "type": "string",
                "description": "Filter messages from a specific agent (optional)",
            },
            "since": {
                "type": "integer",
                "description": "Unix timestamp — only return messages after this time",
            },
        },
    },
}


def _load_roster() -> Dict[str, str]:
    """Load agent→IP mapping from TRIBE_ROSTER env."""
    raw = os.environ.get("TRIBE_ROSTER", "{}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("TRIBE_ROSTER is not valid JSON, returning empty roster")
        return {}


def _send_lcm(target_ip: str, port: int, payload: dict) -> dict:
    """POST /send to a tribe agent's LCM server."""
    url = f"http://{target_ip}:{port}/send"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        raise ConnectionError(f"cannot reach {target_ip}:{port}: {exc}")
    except json.JSONDecodeError:
        raise ValueError(f"invalid response from {target_ip}:{port}")


def _check_inbox(agent_name: str, agent_filter: str = None,
                 since: int = None) -> List[dict]:
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
    """Plugin provider for the send_to_agent and check_inbox tools."""

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
                ensure_ascii=False,
            )

        if tool_name == "send_to_agent":
            target = args.get("to", "").strip()
            text = args.get("text", "").strip()
            reply_to = args.get("reply_to")

            if not target or not text:
                return json.dumps(
                    {"success": False, "error": "to and text are required"},
                    ensure_ascii=False,
                )

            roster = _load_roster()
            target_ip = roster.get(target)
            if not target_ip:
                return json.dumps(
                    {"success": False,
                     "error": f"unknown agent '{target}'. Known: {list(roster)}"},
                    ensure_ascii=False,
                )

            port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
            payload = {"from": agent_name, "to": target, "text": text}
            if reply_to:
                payload["reply_to"] = reply_to

            try:
                result = _send_lcm(target_ip, port, payload)
                return json.dumps(
                    {"success": True, "message_id": result.get("id"),
                     "to": target, "from": agent_name},
                    ensure_ascii=False,
                )
            except (ConnectionError, ValueError) as exc:
                return json.dumps(
                    {"success": False, "error": str(exc)},
                    ensure_ascii=False,
                )

        if tool_name == "check_inbox":
            agent_filter = args.get("agent")
            since = args.get("since")
            messages = _check_inbox(agent_name, agent_filter, since)
            return json.dumps(
                {"success": True, "messages": messages, "count": len(messages)},
                ensure_ascii=False,
            )

        return json.dumps(
            {"success": False, "error": f"unknown tool: {tool_name}"},
            ensure_ascii=False,
        )


def register(ctx):
    ctx.register_tool_provider(SendToAgentProvider())
