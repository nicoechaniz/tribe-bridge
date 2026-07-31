#!/usr/bin/env python3
"""Bind a reviewed Daimon manifest to an immutable compaii-state generation.

The bound descriptor is external to the state generation whose artifact-index
hash it records. Keeping it external avoids an impossible recursive hash.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from daimon_manifest import (  # noqa: E402
    DaimonManifestError,
    canonical_json,
    manifest_sha256,
    validate_manifest,
)


class BindingError(RuntimeError):
    pass


def reviewed_state_manifest(
    repository: Path, commit: str, reviewed_ref: str
) -> dict:
    repo = repository.expanduser().resolve()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BindingError("state commit must be a full lowercase Git SHA")
    if not reviewed_ref.startswith("refs/remotes/"):
        raise BindingError(
            "reviewed ref must be a full remote-tracking ref "
            "(refs/remotes/<remote>/<branch>)"
        )
    checked_ref = subprocess.run(
        ["git", "check-ref-format", reviewed_ref],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if checked_ref.returncode:
        raise BindingError("reviewed ref is not a valid Git ref")
    resolved_ref = subprocess.run(
        ["git", "rev-parse", "--verify", f"{reviewed_ref}^{{commit}}"],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if resolved_ref.returncode:
        raise BindingError("reviewed remote-tracking ref does not exist")
    verified = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if verified.returncode:
        raise BindingError("state commit does not exist in the reviewed repository")
    contained = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, reviewed_ref],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if contained.returncode:
        raise BindingError(
            "state commit is not reachable from the reviewed remote-tracking ref"
        )
    result = subprocess.run(
        ["git", "show", f"{commit}:manifest.json"],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise BindingError("reviewed state commit has no manifest.json")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BindingError("reviewed state manifest is invalid JSON") from exc


def bind_generation(
    template: dict, state_manifest: dict, state_commit: str
) -> dict:
    if (
        state_manifest.get("schema_version") != "compaii-state-manifest/v2"
        or not isinstance(state_manifest.get("generation"), dict)
        or not isinstance(state_manifest.get("artifact_index"), dict)
    ):
        raise BindingError("unsupported compaii-state manifest")
    generation_id = state_manifest["generation"].get("id")
    artifact_hash = state_manifest["artifact_index"].get("sha256")
    bound = json.loads(json.dumps(template))
    if not isinstance(bound.get("portability"), dict):
        raise BindingError("Daimon template has no portability object")
    bound["portability"].update(
        {
            "generation_scheme": "compaii-state-manifest/v2",
            "generation_id": generation_id,
            "source_commit": state_commit,
            "artifact_index_sha256": artifact_hash,
        }
    )
    try:
        return validate_manifest(bound)
    except DaimonManifestError as exc:
        raise BindingError(f"bound Daimon manifest is invalid: {exc}") from exc


def write_atomic(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--state-repo", type=Path, required=True)
    parser.add_argument("--state-commit", required=True)
    parser.add_argument(
        "--reviewed-ref",
        required=True,
        help="full remote-tracking ref containing the reviewed commit",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        template = json.loads(args.template.read_text(encoding="utf-8"))
        state = reviewed_state_manifest(
            args.state_repo, args.state_commit, args.reviewed_ref
        )
        bound = bind_generation(template, state, args.state_commit)
    except (OSError, json.JSONDecodeError, BindingError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    digest = manifest_sha256(bound)
    if args.output:
        destination = args.output.expanduser().resolve()
        write_atomic(destination, canonical_json(bound))
        print(f"BOUND: {destination}; sha256={digest}")
    else:
        print(f"DRY RUN: bound manifest sha256={digest}")
        print("No descriptor or state file was changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
