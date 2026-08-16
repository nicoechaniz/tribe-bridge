#!/usr/bin/env python3
"""Build/apply/diagnose a signed zero-SSH Tribe v1 client package."""

import argparse
import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_directory_v1 import strict_json  # noqa: E402
from tribe_provisioning_v1 import (  # noqa: E402
    ProvisioningError,
    apply_package,
    build_package,
    create_provisioning_authority,
    doctor,
)


def write_exclusive(path: Path, value, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    authority = commands.add_parser("authority-create")
    authority.add_argument("--kid", required=True)
    authority.add_argument("--private-output", type=Path, required=True)
    authority.add_argument("--public-output", type=Path, required=True)

    build = commands.add_parser("build")
    build.add_argument("--directory", type=Path, required=True)
    build.add_argument("--roots", type=Path, required=True)
    build.add_argument("--private-authority", type=Path, required=True)
    build.add_argument("--config", type=Path, required=True)
    build.add_argument("--package", type=Path, required=True)
    build.add_argument("--provisioning-id", required=True)
    build.add_argument("--agent-id", required=True)
    build.add_argument("--build-commit", required=True)
    build.add_argument("--expires-at-ms", type=int, required=True)

    apply = commands.add_parser("apply")
    apply.add_argument("--package", type=Path, required=True)
    apply.add_argument("--authority", type=Path, required=True)
    apply.add_argument("--keys", type=Path, required=True)
    apply.add_argument("--destination", type=Path, required=True)
    apply.add_argument("--local-agent-id", action="append", default=[])

    inspect = commands.add_parser("doctor")
    inspect.add_argument("--destination", type=Path, required=True)
    inspect.add_argument("--keys", type=Path, required=True)
    inspect.add_argument("--agent-id", required=True)
    arguments = parser.parse_args()
    now_ms = int(time.time() * 1000)

    try:
        if arguments.command == "authority-create":
            private, public = create_provisioning_authority(kid=arguments.kid)
            write_exclusive(arguments.private_output, private, 0o600)
            write_exclusive(arguments.public_output, public, 0o644)
            result = {"ok": True, "kid": arguments.kid}
        elif arguments.command == "build":
            config = strict_json(arguments.config.read_bytes())
            if not isinstance(config, dict) or set(config) != {
                "required_audiences",
                "routes",
                "inbox_endpoints",
                "local_agent_ids",
            }:
                raise ProvisioningError("invalid closed provisioning config")
            manifest = build_package(
                arguments.package,
                arguments.directory,
                arguments.roots,
                arguments.private_authority,
                provisioning_id=arguments.provisioning_id,
                agent_id=arguments.agent_id,
                required_audiences=config["required_audiences"],
                routes=config["routes"],
                inbox_endpoints=config["inbox_endpoints"],
                local_agent_ids=config["local_agent_ids"],
                build_commit=arguments.build_commit,
                now_ms=now_ms,
                expires_at_ms=arguments.expires_at_ms,
            )
            result = {
                "ok": True,
                "package": str(arguments.package),
                "directory_epoch": manifest["directory_epoch"],
                "directory_sha256": manifest["directory_sha256"],
                "contains_private_material": False,
            }
        elif arguments.command == "apply":
            result = {
                "ok": True,
                **apply_package(
                    arguments.package,
                    arguments.authority,
                    arguments.keys,
                    arguments.destination,
                    authorized_local_agent_ids=frozenset(arguments.local_agent_id),
                    now_ms=now_ms,
                ),
            }
        else:
            result = {
                "ok": True,
                **doctor(
                    arguments.destination,
                    arguments.keys,
                    agent_id=arguments.agent_id,
                    now_ms=now_ms,
                ),
            }
    except (OSError, ValueError, ProvisioningError) as exception:
        print(json.dumps({"ok": False, "error": str(exception)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
