#!/usr/bin/env python3
"""Run the synthetic single-holder local validity-renewal fixture.

It signs and installs only local explicit paths and has no publish, service,
network, or remote-install capability.  It is not the release ceremony.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_directory_admin_v1 import (  # noqa: E402
    DEFAULT_RENEWAL_WINDOW_DAYS,
    DEFAULT_VALIDITY_DAYS,
    RenewalError,
    renew_synthetic_single_holder_directory,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-dir", type=Path, default=Path.home() / ".tribe-bridge/v1")
    parser.add_argument(
        "--governance-key",
        type=Path,
        default=Path.home() / ".tribe-bridge/v1-governance-offline/governance-root.json",
    )
    parser.add_argument("--validity-days", type=float, default=DEFAULT_VALIDITY_DAYS)
    parser.add_argument("--window-days", type=float, default=DEFAULT_RENEWAL_WINDOW_DAYS)
    parser.add_argument("--force", action="store_true", help="renew even inside the validity window")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        summary = renew_synthetic_single_holder_directory(
            args.v1_dir,
            args.governance_key,
            validity_days=args.validity_days,
            window_days=args.window_days,
            force=args.force,
            dry_run=args.dry_run,
        )
    except RenewalError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)
    print(json.dumps({"ok": True, **summary}, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
