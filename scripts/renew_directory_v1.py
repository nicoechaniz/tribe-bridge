#!/usr/bin/env python3
"""Renew the installed Tribe v1 directory (pure validity renewal, epoch N+1).

Signs with the governance root working copy, verifies the chain against every
local client state, installs atomically with backup, and optionally pushes the
signed artifact to a publishing clone (directory-live branch) and/or to the
hub over ssh. Fail closed: a failed verification installs nothing.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_directory_admin_v1 import (  # noqa: E402
    DEFAULT_RENEWAL_WINDOW_DAYS,
    DEFAULT_VALIDITY_DAYS,
    RenewalError,
    renew_installed_directory,
)


def publish(repo_dir: Path, v1_dir: Path, summary: dict) -> None:
    """Copy the signed artifact into a publishing clone and push."""
    directories = repo_dir / "governance" / "directories"
    directories.mkdir(parents=True, exist_ok=True)
    signed = (v1_dir / "directory.json").read_bytes()
    (directories / "directory-current-signed.json").write_bytes(signed)
    (directories / f"directory-epoch{summary['next_epoch']}-signed.json").write_bytes(signed)
    subprocess.run(["git", "add", "governance/directories"], cwd=repo_dir, check=True)
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            f"chore(governance): publish signed directory epoch {summary['next_epoch']}",
        ],
        cwd=repo_dir,
        check=True,
    )
    subprocess.run(["git", "push"], cwd=repo_dir, check=True)


def install_on_hub(hub: str, v1_dir: Path) -> None:
    """Install the new directory on the hub with a remote backup."""
    subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            hub,
            "cp -a ~/.tribe-bridge/v1/directory.json "
            "~/.tribe-bridge/v1/directory.json.bak-prenewal-$(date -u +%Y%m%dT%H%M%SZ) 2>/dev/null || true",
        ],
        check=True,
    )
    subprocess.run(
        [
            "scp",
            "-o",
            "BatchMode=yes",
            str(v1_dir / "directory.json"),
            f"{hub}:.tribe-bridge/v1/directory.json",
        ],
        check=True,
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
    parser.add_argument("--publish-repo", type=Path, help="publishing clone on the directory-live branch")
    parser.add_argument("--hub", help="ssh target for the hub broker (e.g. debian@10.10.20.69)")
    args = parser.parse_args()

    try:
        summary = renew_installed_directory(
            args.v1_dir,
            args.governance_key,
            validity_days=args.validity_days,
            window_days=args.window_days,
            force=args.force,
            dry_run=args.dry_run,
        )
        if summary["renewed"] and args.hub:
            install_on_hub(args.hub, args.v1_dir)
            summary["hub"] = args.hub
        if summary["renewed"] and args.publish_repo:
            publish(args.publish_repo, args.v1_dir, summary)
            summary["published"] = str(args.publish_repo)
    except (RenewalError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)
    print(json.dumps({"ok": True, **summary}, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
