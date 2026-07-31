"""Hermes tool provider delegating all wire crypto to Tribe v1 scripts."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


SEND_SCHEMA = {
    "name": "send_to_agent",
    "description": (
        "Send a private Tribe v1 message to one agent. For explicit public "
        "group visibility use send_to_tribe_group."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "to": {"type": "string"},
            "text": {"type": "string"},
            "reply_to": {"type": "string"},
        },
        "required": ["to", "text"],
    },
}
GROUP_SCHEMA = {
    "name": "send_to_tribe_group",
    "description": (
        "Send a tribe-public Tribe v1 message to an explicitly configured "
        "group. Public messages may be rendered by an authorized mirror."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "group": {"type": "string"},
            "text": {"type": "string"},
            "reply_to": {"type": "string"},
        },
        "required": ["group", "text"],
    },
}
INBOX_SCHEMA = {
    "name": "check_inbox",
    "description": "Claim, decrypt, deduplicate, and ACK the Tribe v1 inbox.",
    "parameters": {"type": "object", "additionalProperties": False},
}


def _repo() -> Path:
    value = os.environ.get("TRIBE_V1_REPO")
    if not value:
        raise RuntimeError("TRIBE_V1_REPO is required")
    root = Path(value).resolve()
    if not (root / "scripts" / "send_v1.py").is_file():
        raise RuntimeError("TRIBE_V1_REPO has no v1 client")
    return root


def _run(arguments, *, stdin_text=None):
    result = subprocess.run(
        [os.environ.get("TRIBE_V1_PYTHON", "python3"), *arguments],
        cwd=_repo(),
        capture_output=True,
        text=True,
        timeout=60,
        env=os.environ.copy(),
        input=stdin_text,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Tribe v1 client command failed"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("Tribe v1 client returned invalid output")
    return value


class TribeV1Provider:
    @property
    def name(self):
        return "send-to-agent-v1"

    def get_tool_schemas(self):
        return [SEND_SCHEMA, GROUP_SCHEMA, INBOX_SCHEMA]

    def handle_tool_call(self, tool_name, args, **kwargs):
        try:
            if tool_name == "send_to_agent":
                command = [
                    "scripts/send_v1.py",
                    "--to",
                    args["to"],
                    "--text-stdin",
                ]
                if args.get("reply_to"):
                    command.extend(["--reply-to", args["reply_to"]])
                return json.dumps(
                    _run(command, stdin_text=args["text"]),
                    ensure_ascii=False,
                )
            if tool_name == "send_to_tribe_group":
                command = [
                    "scripts/send_v1.py",
                    "--group",
                    args["group"],
                    "--classification",
                    "tribe-public",
                    "--text-stdin",
                ]
                if args.get("reply_to"):
                    command.extend(["--reply-to", args["reply_to"]])
                return json.dumps(
                    _run(command, stdin_text=args["text"]),
                    ensure_ascii=False,
                )
            if tool_name == "check_inbox":
                return json.dumps(
                    _run(["scripts/check_inbox_v1.py"]),
                    ensure_ascii=False,
                )
            raise RuntimeError(f"unknown tool: {tool_name}")
        except Exception as exc:
            return json.dumps(
                {"ok": False, "error": str(exc)}, ensure_ascii=False
            )


def register(ctx):
    ctx.register_tool_provider(TribeV1Provider())
