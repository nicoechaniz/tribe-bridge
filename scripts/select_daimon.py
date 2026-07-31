#!/usr/bin/env python3
"""Validate a Daimon manifest and explain task/instance compatibility."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from daimon_manifest import (  # noqa: E402
    DaimonManifestError,
    canonical_json,
    select_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--task", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        task = json.loads(args.task.read_text(encoding="utf-8"))
        decision = select_manifest(manifest, task)
    except (OSError, json.JSONDecodeError, DaimonManifestError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json(decision))
    return 0 if decision["eligible_for_consideration"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
