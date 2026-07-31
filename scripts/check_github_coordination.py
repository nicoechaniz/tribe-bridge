#!/usr/bin/env python3
"""Audit Tribe claims in GitHub issue comments and enforce PR linkage."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from github_coordination import (  # noqa: E402
    CoordinationError,
    audit_authors,
    audit_events,
    event_to_json,
    parse_comments,
    parse_timestamp,
)

ROOT = Path(__file__).resolve().parents[1]
PRINCIPALS_FILE = ROOT / "coordination" / "principals.json"

_CLOSES = re.compile(
    r"(?im)^\s*(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+"
    r"(?:https://github\.com/([^/\s]+/[^/\s]+)/issues/)?#?(\d+)\b"
)
_CLAIM_ID = re.compile(
    r"(?im)^\s*Claim-ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\s*$"
)
_DEPLOYMENT = re.compile(r"(?im)^\s*Deployment:\s*(.+?)\s*$")
_TESTS = re.compile(r"(?ims)^##\s+Tests\s*$\s*(.+?)(?=^##\s+|\Z)")


def _run_gh(arguments: list[str]) -> Any:
    environment = dict(os.environ)
    token = environment.get("GH_TOKEN") or environment.get("GITHUB_TOKEN")
    if token:
        environment["GH_TOKEN"] = token
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CoordinationError(f"gh {' '.join(arguments)} failed: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CoordinationError("GitHub CLI returned invalid JSON") from exc


def _comments(repo: str, issue: int) -> list[dict[str, Any]]:
    result = _run_gh(
        [
            "api",
            "--paginate",
            f"repos/{repo}/issues/{issue}/comments",
            "--slurp",
        ]
    )
    return [comment for page in result for comment in page]


def _now(value: Optional[str]) -> dt.datetime:
    return parse_timestamp(value, "now") if value else dt.datetime.now(dt.timezone.utc)


def audit_issue(repo: str, issue: int, now: dt.datetime) -> dict[str, Any]:
    events = parse_comments(_comments(repo, issue))
    scoped = [
        event
        for event in events
        if event.issue.repository == repo and event.issue.number == issue
    ]
    audit = audit_events(scoped, now=now)
    findings = [
        {"code": finding.code, "message": finding.message}
        for finding in audit.findings
    ]
    findings.extend(
        {
            "code": "misplaced-event",
            "message": (
                f"comment {event.comment_id} describes "
                f"{event.issue.repository}#{event.issue.number}, not {repo}#{issue}"
            ),
        }
        for event in events
        if event not in scoped
    )
    try:
        registry = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoordinationError(f"cannot load {PRINCIPALS_FILE}: {exc}") from exc
    findings.extend(
        {"code": finding.code, "message": finding.message}
        for finding in audit_authors(scoped, registry)
    )
    if not scoped:
        findings.append(
            {
                "code": "missing-claim",
                "message": f"{repo}#{issue} has no {repo} coordination event",
            }
        )
    return {
        "ok": not findings,
        "repository": repo,
        "issue": issue,
        "checked_at": now.isoformat(),
        "effective": [event_to_json(event) for event in audit.effective],
        "findings": findings,
    }


def _linked_issue(body: str, repo: str) -> Optional[int]:
    for match in _CLOSES.finditer(body):
        linked_repo = match.group(1)
        if linked_repo is None or linked_repo.lower() == repo.lower():
            return int(match.group(2))
    return None


def audit_pr(repo: str, pr_number: int, now: dt.datetime) -> dict[str, Any]:
    pull = _run_gh(
        [
            "api",
            f"repos/{repo}/pulls/{pr_number}",
        ]
    )
    body = pull.get("body") or ""
    findings: list[dict[str, str]] = []
    issue_number = _linked_issue(body, repo)
    claim_match = _CLAIM_ID.search(body)
    deployment_match = _DEPLOYMENT.search(body)
    tests_match = _TESTS.search(body)
    head = pull.get("head", {}).get("ref")

    if issue_number is None:
        findings.append(
            {
                "code": "missing-linked-issue",
                "message": "PR body must contain Closes #<issue>",
            }
        )
    if claim_match is None:
        findings.append(
            {
                "code": "missing-claim-id",
                "message": "PR body must contain Claim-ID: <uuid>",
            }
        )
    if deployment_match is None:
        findings.append(
            {
                "code": "missing-deployment-status",
                "message": "PR body must contain Deployment: <status>",
            }
        )
    if tests_match is None or not tests_match.group(1).strip():
        findings.append(
            {
                "code": "missing-tests",
                "message": "PR body must contain a non-empty ## Tests section",
            }
        )

    issue_audit = None
    if issue_number is not None:
        issue_audit = audit_issue(repo, issue_number, now)
        findings.extend(issue_audit["findings"])
        if claim_match is not None:
            claim_id = claim_match.group(1)
            selected = [
                event
                for event in issue_audit["effective"]
                if event["claim_id"] == claim_id
            ]
            if not selected:
                findings.append(
                    {
                        "code": "unknown-claim-id",
                        "message": f"Claim-ID {claim_id} is not effective on issue",
                    }
                )
            else:
                claim = selected[0]
                if claim["state"] != "in_review":
                    findings.append(
                        {
                            "code": "claim-not-in-review",
                            "message": (
                                f"claim is in {claim['state']} state, not in_review"
                            ),
                        }
                    )
                if claim["branch"] != head:
                    findings.append(
                        {
                            "code": "branch-mismatch",
                            "message": (
                                f"claim branch {claim['branch']!r} does not match "
                                f"PR head {head!r}"
                            ),
                        }
                    )
                if claim["pull_request"] != pr_number:
                    findings.append(
                        {
                            "code": "pull-request-mismatch",
                            "message": (
                                f"claim pull_request {claim['pull_request']!r} does "
                                f"not match PR {pr_number}"
                            ),
                        }
                    )

    return {
        "ok": not findings,
        "repository": repo,
        "pull_request": pr_number,
        "head": head,
        "linked_issue": issue_number,
        "checked_at": now.isoformat(),
        "issue_audit": issue_audit,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--now", help="RFC 3339 UTC test override")
    subparsers = parser.add_subparsers(dest="command", required=True)
    issue_parser = subparsers.add_parser("issue")
    issue_parser.add_argument("--issue", type=int, required=True)
    pr_parser = subparsers.add_parser("pr")
    pr_parser.add_argument("--pr", type=int, required=True)
    args = parser.parse_args()
    if not args.repo or "/" not in args.repo:
        parser.error("--repo owner/name or GITHUB_REPOSITORY is required")

    try:
        if args.command == "issue":
            result = audit_issue(args.repo, args.issue, _now(args.now))
        else:
            result = audit_pr(args.repo, args.pr, _now(args.now))
    except CoordinationError as exc:
        result = {"ok": False, "findings": [{"code": "invalid-data", "message": str(exc)}]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
