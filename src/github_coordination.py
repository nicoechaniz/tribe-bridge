"""Strict, append-only coordination events for GitHub issues.

GitHub comments are the audit log. This module parses the machine-readable
blocks, validates their closed shape, reduces them to effective claims, and
reports stale or overlapping work without depending on GitHub itself.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Optional


SCHEMA = "tribe-claim/v1"
MARKER = "tribe-claim/v1"
ACTIVE_STATES = frozenset({"in_progress", "in_review", "blocked"})
TERMINAL_STATES = frozenset({"done", "released"})
STATES = ACTIVE_STATES | TERMINAL_STATES | {"ready"}
EVENTS = frozenset({"claim", "renew", "status", "release"})
MAX_LEASE = dt.timedelta(hours=24)
_BLOCK = re.compile(
    r"<!--\s*tribe-claim/v1\s*\n(?P<payload>.*?)\s*\n-->",
    re.DOTALL,
)
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9_.:@/-]+$")
_RESOURCE = re.compile(r"^(issue|path|service|project|protocol):\S+$")
_BRANCH = re.compile(r"^[^\s~^:?*\[\\]+(?:/[^\s~^:?*\[\\]+)*$")
_ALLOWED_KEYS = frozenset(
    {
        "schema",
        "event",
        "event_id",
        "claim_id",
        "issue",
        "principal",
        "state",
        "at",
        "lease_until",
        "resources",
        "branch",
        "pull_request",
        "supersedes",
        "note",
    }
)


class CoordinationError(ValueError):
    """A coordination record is malformed or violates the state machine."""


@dataclasses.dataclass(frozen=True)
class IssueRef:
    repository: str
    number: int

    @property
    def resource(self) -> str:
        return f"issue:{self.repository}#{self.number}"


@dataclasses.dataclass(frozen=True)
class Event:
    event: str
    event_id: str
    claim_id: str
    issue: IssueRef
    principal: str
    state: str
    at: dt.datetime
    lease_until: Optional[dt.datetime]
    resources: tuple[str, ...]
    branch: Optional[str] = None
    pull_request: Optional[int] = None
    supersedes: Optional[str] = None
    note: Optional[str] = None
    comment_id: Optional[int] = None
    comment_url: Optional[str] = None
    comment_author: Optional[str] = None

    @property
    def is_active_state(self) -> bool:
        return self.state in ACTIVE_STATES

    def is_live(self, now: dt.datetime) -> bool:
        return (
            self.is_active_state
            and self.lease_until is not None
            and self.lease_until > now
        )


@dataclasses.dataclass(frozen=True)
class Finding:
    code: str
    message: str
    claim_ids: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Audit:
    effective: tuple[Event, ...]
    findings: tuple[Finding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CoordinationError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CoordinationError(f"{field} is not a valid timestamp") from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise CoordinationError(f"{field} must use UTC")
    return parsed


def format_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
        raise CoordinationError("timestamp must be timezone-aware UTC")
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise CoordinationError(f"{field} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise CoordinationError(f"{field} must be a UUID") from exc
    if str(parsed) != value.lower():
        raise CoordinationError(f"{field} must use canonical lowercase UUID form")
    return value


def _nullable_uuid(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    return _uuid(value, field)


def validate_event(
    raw: Mapping[str, Any],
    *,
    comment_id: Optional[int] = None,
    comment_url: Optional[str] = None,
    comment_author: Optional[str] = None,
) -> Event:
    if not isinstance(raw, Mapping):
        raise CoordinationError("event must be a JSON object")
    unknown = set(raw) - _ALLOWED_KEYS
    required = {
        "schema",
        "event",
        "event_id",
        "claim_id",
        "issue",
        "principal",
        "state",
        "at",
        "lease_until",
        "resources",
    }
    missing = required - set(raw)
    if unknown:
        raise CoordinationError(f"unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise CoordinationError(f"missing fields: {', '.join(sorted(missing))}")
    if raw["schema"] != SCHEMA:
        raise CoordinationError(f"schema must be {SCHEMA}")
    event_kind = raw["event"]
    if event_kind not in EVENTS:
        raise CoordinationError(f"event must be one of {sorted(EVENTS)}")
    state = raw["state"]
    if state not in STATES:
        raise CoordinationError(f"state must be one of {sorted(STATES)}")

    issue_raw = raw["issue"]
    if not isinstance(issue_raw, Mapping) or set(issue_raw) != {
        "repository",
        "number",
    }:
        raise CoordinationError("issue must contain exactly repository and number")
    repository = issue_raw["repository"]
    number = issue_raw["number"]
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
        raise CoordinationError("issue.repository must be owner/name")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise CoordinationError("issue.number must be a positive integer")
    issue = IssueRef(repository=repository, number=number)

    principal = raw["principal"]
    if (
        not isinstance(principal, str)
        or not 1 <= len(principal) <= 128
        or not _PRINCIPAL.fullmatch(principal)
    ):
        raise CoordinationError("principal contains unsupported characters")
    at = parse_timestamp(raw["at"], "at")
    lease_raw = raw["lease_until"]
    lease_until = (
        None
        if lease_raw is None
        else parse_timestamp(lease_raw, "lease_until")
    )

    resources_raw = raw["resources"]
    if (
        not isinstance(resources_raw, list)
        or not resources_raw
        or any(
            not isinstance(item, str)
            or len(item) > 256
            or not _RESOURCE.fullmatch(item)
            for item in resources_raw
        )
    ):
        raise CoordinationError("resources must be a non-empty list of typed resources")
    if len(set(resources_raw)) != len(resources_raw):
        raise CoordinationError("resources must not contain duplicates")
    resources = tuple(resources_raw)
    if issue.resource not in resources:
        raise CoordinationError(f"resources must include {issue.resource}")

    branch = raw.get("branch")
    if branch is not None and (
        not isinstance(branch, str)
        or len(branch) > 255
        or not _BRANCH.fullmatch(branch)
        or branch.startswith(("/", "."))
        or branch.endswith(("/", "."))
        or ".." in branch
        or "@{" in branch
        or "//" in branch
        or any(
            component.startswith(".") or component.endswith(".lock")
            for component in branch.split("/")
        )
    ):
        raise CoordinationError("branch is not a safe Git ref name")
    pull_request = raw.get("pull_request")
    if pull_request is not None and (
        isinstance(pull_request, bool)
        or not isinstance(pull_request, int)
        or pull_request < 1
    ):
        raise CoordinationError("pull_request must be a positive integer or null")
    note = raw.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 500):
        raise CoordinationError("note must be null or at most 500 characters")

    if event_kind == "claim":
        if state != "in_progress":
            raise CoordinationError("claim events must enter in_progress")
        if branch is None:
            raise CoordinationError("claim events require a branch")
    elif event_kind == "renew":
        if state not in ACTIVE_STATES:
            raise CoordinationError("renew events require an active state")
    elif event_kind == "release":
        if state != "released" or lease_until is not None:
            raise CoordinationError("release events require released state and null lease")
    elif event_kind == "status" and state == "released":
        raise CoordinationError("released state requires a release event")

    if state in ACTIVE_STATES:
        if lease_until is None:
            raise CoordinationError("active states require lease_until")
        if lease_until <= at:
            raise CoordinationError("lease_until must be after at")
        if lease_until - at > MAX_LEASE:
            raise CoordinationError("lease duration must not exceed 24 hours")
    elif lease_until is not None:
        raise CoordinationError("non-active states require null lease_until")

    return Event(
        event=event_kind,
        event_id=_uuid(raw["event_id"], "event_id"),
        claim_id=_uuid(raw["claim_id"], "claim_id"),
        issue=issue,
        principal=principal,
        state=state,
        at=at,
        lease_until=lease_until,
        resources=resources,
        branch=branch,
        pull_request=pull_request,
        supersedes=_nullable_uuid(raw.get("supersedes"), "supersedes"),
        note=note,
        comment_id=comment_id,
        comment_url=comment_url,
        comment_author=comment_author,
    )


def parse_comment(comment: Mapping[str, Any]) -> tuple[Event, ...]:
    body = comment.get("body", "")
    if not isinstance(body, str):
        raise CoordinationError("comment body must be text")
    blocks = tuple(_BLOCK.finditer(body))
    marker_count = len(re.findall(r"<!--\s*tribe-claim/v1\b", body))
    if marker_count != len(blocks):
        raise CoordinationError(
            f"comment {comment.get('id', '?')} has an unterminated coordination block"
        )
    if len(blocks) > 1:
        raise CoordinationError(
            f"comment {comment.get('id', '?')} contains multiple coordination blocks"
        )
    events = []
    for match in blocks:
        try:
            raw = json.loads(match.group("payload"))
        except json.JSONDecodeError as exc:
            raise CoordinationError(
                f"comment {comment.get('id', '?')} has invalid coordination JSON"
            ) from exc
        author_raw = comment.get("user")
        author = (
            author_raw.get("login")
            if isinstance(author_raw, Mapping)
            else comment.get("author")
        )
        events.append(
            validate_event(
                raw,
                comment_id=comment.get("id"),
                comment_url=comment.get("html_url") or comment.get("url"),
                comment_author=author,
            )
        )
    return tuple(events)


def parse_comments(comments: Iterable[Mapping[str, Any]]) -> tuple[Event, ...]:
    result = []
    seen_event_ids: set[str] = set()
    for comment in comments:
        for event in parse_comment(comment):
            if event.event_id in seen_event_ids:
                raise CoordinationError(f"duplicate event_id {event.event_id}")
            seen_event_ids.add(event.event_id)
            result.append(event)
    return tuple(sorted(result, key=lambda item: (item.at, item.event_id)))


def render_event(raw: Mapping[str, Any]) -> str:
    """Validate and render a canonical comment block."""
    validate_event(raw)
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"<!-- {MARKER}\n{payload}\n-->"


def _same_claim(previous: Event, current: Event) -> None:
    if current.issue != previous.issue:
        raise CoordinationError(f"claim {current.claim_id} changed issue")
    if current.principal != previous.principal:
        raise CoordinationError(f"claim {current.claim_id} changed principal")
    if current.resources != previous.resources:
        raise CoordinationError(f"claim {current.claim_id} changed resources")
    if current.branch != previous.branch:
        raise CoordinationError(f"claim {current.claim_id} changed branch")
    if current.supersedes != previous.supersedes:
        raise CoordinationError(f"claim {current.claim_id} changed supersedes")
    if current.at <= previous.at:
        raise CoordinationError(f"claim {current.claim_id} events are not monotonic")


def reduce_events(events: Iterable[Event]) -> tuple[Event, ...]:
    effective: dict[str, Event] = {}
    event_ids: set[str] = set()
    for event in sorted(events, key=lambda item: (item.at, item.event_id)):
        if event.event_id in event_ids:
            raise CoordinationError(f"duplicate event_id {event.event_id}")
        event_ids.add(event.event_id)
        previous = effective.get(event.claim_id)
        if previous is None:
            if event.event != "claim":
                raise CoordinationError(
                    f"claim {event.claim_id} starts with {event.event}, not claim"
                )
        else:
            if event.event == "claim":
                raise CoordinationError(f"claim {event.claim_id} has multiple claim events")
            if previous.state in TERMINAL_STATES:
                raise CoordinationError(
                    f"claim {event.claim_id} has an event after terminal state"
                )
            _same_claim(previous, event)
            if (
                event.event != "release"
                and previous.lease_until is not None
                and previous.lease_until <= event.at
            ):
                raise CoordinationError(
                    f"claim {event.claim_id} was renewed or changed after expiry"
                )
        effective[event.claim_id] = event
    return tuple(sorted(effective.values(), key=lambda item: item.claim_id))


def audit_events(events: Iterable[Event], *, now: Optional[dt.datetime] = None) -> Audit:
    checked_at = now or utc_now()
    if checked_at.tzinfo is None or checked_at.utcoffset() != dt.timedelta(0):
        raise CoordinationError("audit time must be timezone-aware UTC")
    effective = reduce_events(events)
    findings: list[Finding] = []
    by_id = {claim.claim_id: claim for claim in effective}
    superseded: set[str] = set()
    for claim in effective:
        if claim.supersedes is None:
            continue
        target = by_id.get(claim.supersedes)
        if target is None:
            findings.append(
                Finding(
                    code="unknown-supersedes",
                    message=(
                        f"{claim.claim_id} supersedes unknown claim "
                        f"{claim.supersedes}"
                    ),
                    claim_ids=(claim.claim_id, claim.supersedes),
                )
            )
        elif target.at >= claim.at or target.is_live(claim.at):
            findings.append(
                Finding(
                    code="premature-supersede",
                    message=(
                        f"{claim.claim_id} supersedes {target.claim_id} before "
                        "the previous lease expired or terminated"
                    ),
                    claim_ids=(claim.claim_id, target.claim_id),
                )
            )
        else:
            superseded.add(target.claim_id)
    live = []
    for claim in effective:
        if claim.is_active_state and (
            claim.lease_until is None or claim.lease_until <= checked_at
        ) and claim.claim_id not in superseded:
            expiry = (
                format_timestamp(claim.lease_until)
                if claim.lease_until is not None
                else "missing"
            )
            findings.append(
                Finding(
                    code="expired-lease",
                    message=(
                        f"{claim.claim_id} owned by {claim.principal} expired at "
                        f"{expiry}"
                    ),
                    claim_ids=(claim.claim_id,),
                )
            )
        if claim.is_live(checked_at):
            live.append(claim)
    for index, left in enumerate(live):
        left_resources = set(left.resources)
        for right in live[index + 1 :]:
            overlap = sorted(left_resources.intersection(right.resources))
            if overlap and left.claim_id != right.claim_id:
                findings.append(
                    Finding(
                        code="overlapping-claims",
                        message=(
                            f"{left.claim_id} and {right.claim_id} both claim "
                            f"{', '.join(overlap)}"
                        ),
                        claim_ids=(left.claim_id, right.claim_id),
                    )
                )
    return Audit(effective=effective, findings=tuple(findings))


def audit_authors(
    events: Iterable[Event], registry: Mapping[str, Any]
) -> tuple[Finding, ...]:
    if set(registry) != {"schema", "principals"}:
        raise CoordinationError(
            "principal registry must contain exactly schema and principals"
        )
    if registry["schema"] != "tribe-principals/v1":
        raise CoordinationError("principal registry schema must be tribe-principals/v1")
    principals = registry["principals"]
    if not isinstance(principals, Mapping):
        raise CoordinationError("principal registry principals must be an object")
    findings = []
    for event in events:
        entry = principals.get(event.principal)
        if not isinstance(entry, Mapping) or set(entry) != {
            "enabled",
            "github_logins",
        }:
            findings.append(
                Finding(
                    code="unknown-principal",
                    message=f"{event.principal} is absent or malformed in registry",
                    claim_ids=(event.claim_id,),
                )
            )
            continue
        logins = entry["github_logins"]
        if (
            entry["enabled"] is not True
            or not isinstance(logins, list)
            or not logins
            or any(not isinstance(login, str) or not login for login in logins)
        ):
            findings.append(
                Finding(
                    code="disabled-principal",
                    message=f"{event.principal} is not enabled with GitHub identities",
                    claim_ids=(event.claim_id,),
                )
            )
        elif event.comment_author not in logins:
            findings.append(
                Finding(
                    code="unauthorized-comment-author",
                    message=(
                        f"GitHub user {event.comment_author!r} cannot speak for "
                        f"{event.principal}"
                    ),
                    claim_ids=(event.claim_id,),
                )
            )
    return tuple(findings)


def event_to_json(event: Event) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "event": event.event,
        "event_id": event.event_id,
        "claim_id": event.claim_id,
        "issue": {
            "repository": event.issue.repository,
            "number": event.issue.number,
        },
        "principal": event.principal,
        "state": event.state,
        "at": format_timestamp(event.at),
        "lease_until": (
            format_timestamp(event.lease_until)
            if event.lease_until is not None
            else None
        ),
        "resources": list(event.resources),
        "branch": event.branch,
        "pull_request": event.pull_request,
        "supersedes": event.supersedes,
        "note": event.note,
        "comment_id": event.comment_id,
        "comment_url": event.comment_url,
        "comment_author": event.comment_author,
    }
