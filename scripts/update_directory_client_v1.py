#!/usr/bin/env python3
"""Update a remote client's installed Tribe v1 directory from a canonical URL.

Fetches the signed directory, verifies schema/signature/chain/expiry against
the local roots and state (fail closed — no mutation on any error), and
installs it atomically. Idempotent: exits 0 silently when already current.
"""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_directory_admin_v1 import RenewalError, update_client_directory  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get("TRIBE_V1_DIRECTORY_URL"),
        help="canonical signed-directory URL (or TRIBE_V1_DIRECTORY_URL)",
    )
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path.home() / ".tribe-bridge/v1/directory.json",
    )
    parser.add_argument(
        "--roots",
        type=Path,
        default=Path.home() / ".tribe-bridge/v1/governance-roots.json",
    )
    parser.add_argument(
        "--state",
        type=Path,
        required=True,
        help="this client's *-directory-state.json",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.url:
        parser.error("--url or TRIBE_V1_DIRECTORY_URL is required")
    try:
        result = update_client_directory(
            args.url,
            directory_path=args.directory,
            roots_path=args.roots,
            state_path=args.state,
            dry_run=args.dry_run,
        )
    except (RenewalError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)
    if not result.get("updated") and result.get("reason") == "already-current":
        sys.exit(0)  # silent no-op for cron
    print(json.dumps({"ok": True, **result}, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
