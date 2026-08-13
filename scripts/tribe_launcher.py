#!/usr/bin/env python3
"""Load one inert, owner-only Tribe identity file and exec the reviewed client."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


MAX_CLIENT_ENV_BYTES = 256 * 1024
IDENTITY_KEYS = frozenset(
    {
        "TRIBE_CLIENT_ID",
        "TRIBE_V1_BUILD_COMMIT",
        "TRIBE_V1_CLIENT_DB",
        "TRIBE_V1_CLIENT_INBOX_DB",
        "TRIBE_V1_DIRECTORY",
        "TRIBE_V1_DIRECTORY_STATE",
        "TRIBE_V1_GOVERNANCE_ROOTS",
        "TRIBE_V1_INBOX_ENDPOINTS",
        "TRIBE_V1_KEYS",
        "TRIBE_V1_LOCAL_AGENT_IDS",
        "TRIBE_V1_ROUTES",
    }
)
COMMANDS = {
    "send": "send_v1.py",
    "inbox": "check_inbox_v1.py",
    "flush-outbox": "flush_outbox_v1.py",
}


class ClientEnvironmentError(ValueError):
    pass


def _read_owner_file(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise ClientEnvironmentError("client environment cannot be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        current = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ClientEnvironmentError("client environment changed while opening")
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) & 0o077
            or current.st_nlink != 1
            or current.st_size > MAX_CLIENT_ENV_BYTES
        ):
            raise ClientEnvironmentError(
                "client environment must be one owner-only regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 16 * 1024):
            size += len(chunk)
            if size > MAX_CLIENT_ENV_BYTES:
                raise ClientEnvironmentError("client environment is too large")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exception:
        raise ClientEnvironmentError("client environment is unavailable") from exception
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _decode_value(raw: str, line_number: int) -> str:
    if raw.startswith('"') or raw.endswith('"'):
        if not (raw.startswith('"') and raw.endswith('"')):
            raise ClientEnvironmentError(f"invalid quoted value on line {line_number}")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exception:
            raise ClientEnvironmentError(
                f"invalid quoted value on line {line_number}"
            ) from exception
        if not isinstance(value, str):
            raise ClientEnvironmentError(f"invalid quoted value on line {line_number}")
        return value
    if raw.startswith("'") or raw.endswith("'"):
        if not (raw.startswith("'") and raw.endswith("'")) or "'" in raw[1:-1]:
            raise ClientEnvironmentError(f"invalid quoted value on line {line_number}")
        return raw[1:-1]
    return raw


def load_client_environment(path: Path) -> dict[str, str]:
    try:
        text = _read_owner_file(path).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ClientEnvironmentError("client environment is not UTF-8") from exception
    values: dict[str, str] = {}
    for line_number, source_line in enumerate(text.splitlines(), start=1):
        line = source_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ClientEnvironmentError(
                f"client environment is data, not shell, on line {line_number}"
            )
        key, raw_value = line.split("=", 1)
        if key not in IDENTITY_KEYS:
            raise ClientEnvironmentError(
                f"client environment key is not allowed on line {line_number}"
            )
        if key in values:
            raise ClientEnvironmentError(
                f"duplicate client environment key on line {line_number}"
            )
        value = _decode_value(raw_value, line_number)
        if (
            "\x00" in value
            or "\n" in value
            or "\r" in value
            or "$(" in value
            or "${" in value
            or "`" in value
        ):
            raise ClientEnvironmentError(
                f"invalid client environment value on line {line_number}"
            )
        values[key] = value
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--client-env", required=True)
    parser.add_argument("--command", choices=sorted(COMMANDS), required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    trailing = arguments.arguments
    if trailing[:1] == ["--"]:
        trailing = trailing[1:]
    try:
        identity = load_client_environment(Path(arguments.client_env))
    except ClientEnvironmentError as exception:
        print(f"tribe: {exception}", file=sys.stderr)
        return 2

    environment = dict(os.environ)
    for key in IDENTITY_KEYS:
        environment.pop(key, None)
    environment.update(identity)
    environment["TRIBE_V1_REPO"] = arguments.repo
    environment["TRIBE_V1_PYTHON"] = arguments.python
    script = str(Path(arguments.repo) / "scripts" / COMMANDS[arguments.command])
    os.execve(
        arguments.python,
        [arguments.python, script, *trailing],
        environment,
    )
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
