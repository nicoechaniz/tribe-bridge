from __future__ import annotations

import datetime as dt
import json
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from github_coordination import (  # noqa: E402
    CoordinationError,
    audit_authors,
    audit_events,
    parse_comments,
    reduce_events,
    render_event,
    validate_event,
)


NOW = dt.datetime(2026, 7, 31, 12, tzinfo=dt.timezone.utc)
CLAIM_ID = "11111111-1111-4111-8111-111111111111"


def event(
    *,
    kind: str = "claim",
    event_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    claim_id: str = CLAIM_ID,
    principal: str = "codex@localhost",
    state: str = "in_progress",
    at: str = "2026-07-31T12:00:00Z",
    lease_until: str | None = "2026-08-01T11:59:59Z",
    resources: list[str] | None = None,
    branch: str = "coordination/github-leases-9",
    pull_request: int | None = None,
    supersedes: str | None = None,
) -> dict:
    return {
        "schema": "tribe-claim/v1",
        "event": kind,
        "event_id": event_id,
        "claim_id": claim_id,
        "issue": {"repository": "nicoechaniz/tribe-bridge", "number": 9},
        "principal": principal,
        "state": state,
        "at": at,
        "lease_until": lease_until,
        "resources": resources
        or [
            "issue:nicoechaniz/tribe-bridge#9",
            "path:coordination/**",
        ],
        "branch": branch,
        "pull_request": pull_request,
        "supersedes": supersedes,
        "note": None,
    }


def comment(raw: dict, comment_id: int = 1) -> dict:
    return {
        "id": comment_id,
        "html_url": f"https://example.test/comments/{comment_id}",
        "user": {"login": "nicoechaniz"},
        "body": f"human context\n{render_event(raw)}",
    }


class EventValidationTests(unittest.TestCase):
    def test_closed_valid_claim_round_trips_through_comment(self) -> None:
        parsed = parse_comments([comment(event())])
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].claim_id, CLAIM_ID)
        self.assertEqual(parsed[0].comment_author, "nicoechaniz")

    def test_unknown_fields_are_rejected(self) -> None:
        raw = event()
        raw["local_worktree"] = "/home/person/private"
        with self.assertRaisesRegex(CoordinationError, "unknown fields"):
            validate_event(raw)

    def test_issue_resource_is_mandatory(self) -> None:
        raw = event(resources=["path:coordination/**"])
        with self.assertRaisesRegex(CoordinationError, "must include issue:"):
            validate_event(raw)

    def test_active_lease_is_bounded_to_24_hours(self) -> None:
        raw = event(lease_until="2026-08-02T12:00:01Z")
        with self.assertRaisesRegex(CoordinationError, "24 hours"):
            validate_event(raw)

    def test_timestamps_must_be_explicit_utc(self) -> None:
        raw = event(at="2026-07-31T09:00:00-03:00")
        with self.assertRaisesRegex(CoordinationError, "ending in Z"):
            validate_event(raw)

    def test_release_cannot_retain_lease(self) -> None:
        raw = event(kind="release", state="released")
        with self.assertRaisesRegex(CoordinationError, "null lease"):
            validate_event(raw)

    def test_duplicate_event_ids_are_rejected(self) -> None:
        raw = event()
        with self.assertRaisesRegex(CoordinationError, "duplicate event_id"):
            parse_comments([comment(raw, 1), comment(raw, 2)])

    def test_invalid_json_marker_fails_closed(self) -> None:
        broken = {
            "id": 4,
            "body": "<!-- tribe-claim/v1\n{\"broken\":\n-->",
        }
        with self.assertRaisesRegex(CoordinationError, "invalid coordination JSON"):
            parse_comments([broken])

    def test_unterminated_marker_fails_closed(self) -> None:
        broken = {
            "id": 5,
            "body": "<!-- tribe-claim/v1\n{}",
        }
        with self.assertRaisesRegex(CoordinationError, "unterminated"):
            parse_comments([broken])

    def test_one_comment_cannot_bundle_multiple_events(self) -> None:
        first = render_event(event())
        second_raw = event(
            event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            claim_id="22222222-2222-4222-8222-222222222222",
            branch="coordination/other",
        )
        bundled = {"id": 6, "body": f"{first}\n{render_event(second_raw)}"}
        with self.assertRaisesRegex(CoordinationError, "multiple"):
            parse_comments([bundled])


class ReductionAndAuditTests(unittest.TestCase):
    def test_renewal_extends_same_claim(self) -> None:
        initial = validate_event(event())
        renewal = validate_event(
            event(
                kind="renew",
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                state="in_review",
                at="2026-08-01T10:00:00Z",
                lease_until="2026-08-02T09:59:59Z",
                pull_request=17,
            )
        )
        effective = reduce_events([renewal, initial])
        self.assertEqual(effective[0].state, "in_review")
        self.assertEqual(effective[0].pull_request, 17)

    def test_claim_cannot_change_owner_or_resources(self) -> None:
        initial = validate_event(event())
        changed = validate_event(
            event(
                kind="renew",
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                principal="compaii@localhost",
                at="2026-07-31T13:00:00Z",
                lease_until="2026-08-01T12:59:59Z",
            )
        )
        with self.assertRaisesRegex(CoordinationError, "changed principal"):
            reduce_events([initial, changed])

    def test_expired_claim_cannot_be_renewed_in_place(self) -> None:
        initial = validate_event(event(lease_until="2026-07-31T13:00:00Z"))
        late = validate_event(
            event(
                kind="renew",
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                at="2026-07-31T13:00:01Z",
                lease_until="2026-08-01T13:00:00Z",
            )
        )
        with self.assertRaisesRegex(CoordinationError, "after expiry"):
            reduce_events([initial, late])

    def test_release_is_terminal_and_not_stale(self) -> None:
        initial = validate_event(event())
        released = validate_event(
            event(
                kind="release",
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                state="released",
                at="2026-07-31T13:00:00Z",
                lease_until=None,
            )
        )
        audit = audit_events([initial, released], now=NOW + dt.timedelta(days=3))
        self.assertTrue(audit.ok)

    def test_expired_active_claim_is_a_finding(self) -> None:
        claim = validate_event(event(lease_until="2026-07-31T13:00:00Z"))
        audit = audit_events([claim], now=NOW + dt.timedelta(hours=2))
        self.assertEqual(audit.findings[0].code, "expired-lease")

    def test_overlapping_live_resources_fail(self) -> None:
        left = validate_event(event())
        right = validate_event(
            event(
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                claim_id="22222222-2222-4222-8222-222222222222",
                principal="compaii@localhost",
                branch="coordination/other",
            )
        )
        audit = audit_events([left, right], now=NOW)
        self.assertEqual(audit.findings[0].code, "overlapping-claims")

    def test_non_overlapping_claims_can_coexist(self) -> None:
        left = validate_event(event())
        right_raw = event(
            event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            claim_id="22222222-2222-4222-8222-222222222222",
            principal="compaii@localhost",
            branch="docs/other-10",
            resources=[
                "issue:nicoechaniz/tribe-bridge#10",
                "path:docs/memory/**",
            ],
        )
        right_raw["issue"]["number"] = 10
        right = validate_event(right_raw)
        self.assertTrue(audit_events([left, right], now=NOW).ok)

    def test_expired_claim_can_be_explicitly_reclaimed(self) -> None:
        old = validate_event(event(lease_until="2026-07-31T13:00:00Z"))
        replacement = validate_event(
            event(
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                claim_id="22222222-2222-4222-8222-222222222222",
                principal="compaii@localhost",
                at="2026-07-31T13:00:01Z",
                lease_until="2026-08-01T13:00:00Z",
                branch="coordination/reclaimed-9",
                supersedes=CLAIM_ID,
            )
        )
        audit = audit_events([old, replacement], now=NOW + dt.timedelta(hours=2))
        self.assertTrue(audit.ok)

    def test_live_claim_cannot_be_superseded(self) -> None:
        old = validate_event(event())
        replacement = validate_event(
            event(
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                claim_id="22222222-2222-4222-8222-222222222222",
                principal="compaii@localhost",
                at="2026-07-31T13:00:01Z",
                lease_until="2026-08-01T13:00:00Z",
                branch="coordination/reclaimed-9",
                supersedes=CLAIM_ID,
            )
        )
        audit = audit_events([old, replacement], now=NOW + dt.timedelta(hours=2))
        self.assertIn(
            "premature-supersede",
            {finding.code for finding in audit.findings},
        )

    def test_event_after_release_is_rejected(self) -> None:
        initial = validate_event(event())
        released = validate_event(
            event(
                kind="release",
                event_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                state="released",
                at="2026-07-31T13:00:00Z",
                lease_until=None,
            )
        )
        renewed = validate_event(
            event(
                kind="renew",
                event_id=str(uuid.uuid4()),
                at="2026-07-31T14:00:00Z",
                lease_until="2026-08-01T13:59:59Z",
            )
        )
        with self.assertRaisesRegex(CoordinationError, "after terminal"):
            reduce_events([initial, released, renewed])

    def test_comment_author_must_be_authorized_for_principal(self) -> None:
        parsed = parse_comments([comment(event())])
        registry = {
            "schema": "tribe-principals/v1",
            "principals": {
                "codex@localhost": {
                    "enabled": True,
                    "github_logins": ["somebody-else"],
                }
            },
        }
        findings = audit_authors(parsed, registry)
        self.assertEqual(findings[0].code, "unauthorized-comment-author")


if __name__ == "__main__":
    unittest.main()
