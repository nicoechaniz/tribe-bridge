"""Tests for the Tribe v1 sent-message duplicate gate (2026-08-02).

Nico's rule: before sending, review what was already sent to the same
audience; a materially identical message blocks with evidence.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tribe_sent_gate_v1 import (  # noqa: E402
    append_sent,
    find_duplicates,
    format_evidence,
    recent_for_audience,
    similarity,
    text_hash,
)


def test_exact_duplicate_detected(tmp_path):
    log = tmp_path / "sent.jsonl"
    text = "PUSH REQUEST #31 — daimon-cluster R3 landed. Please pull main."
    append_sent(log, audience="compaii", classification="private",
                text=text, message_id="m1", result="delivered")
    # renumbered repeat: #32 instead of #31 — still the same message
    hits = find_duplicates(log, audience="compaii",
                           text=text.replace("#31", "#32"))
    assert hits and hits[0]["exact"] is True


def test_materially_identical_detected(tmp_path):
    log = tmp_path / "sent.jsonl"
    base = ("PUSH REQUEST — daimon-cluster landed on main. "
            "Pull when you can. remote: ssh://x/y " + "detail " * 30)
    append_sent(log, audience="compaii", classification="private",
                text=base + "alpha", message_id="m1", result="delivered")
    hits = find_duplicates(log, audience="compaii",
                           text=base + "omega")
    assert len(hits) == 1
    assert hits[0]["exact"] is False
    assert hits[0]["similarity"] >= 0.6


def test_genuinely_new_message_passes(tmp_path):
    log = tmp_path / "sent.jsonl"
    append_sent(log, audience="compaii", classification="private",
                text="PUSH REQUEST — pull main please.",
                message_id="m1", result="delivered")
    hits = find_duplicates(log, audience="compaii",
                           text="The cross-host /we.sync demo is complete: "
                                "chains converged byte-identical on both "
                                "hosts, acceptance checklist green.")
    assert hits == []


def test_audience_isolation(tmp_path):
    log = tmp_path / "sent.jsonl"
    text = "same text to two different audiences"
    append_sent(log, audience="compaii", classification="private",
                text=text, message_id="m1", result="delivered")
    # the SAME text to a DIFFERENT audience is not a duplicate
    assert find_duplicates(log, audience="public-agents", text=text) == []
    # ...but it is to the same one
    assert find_duplicates(log, audience="compaii", text=text)


def test_window_limits_comparison(tmp_path):
    log = tmp_path / "sent.jsonl"
    old = "an old repeated message " + "x " * 40
    append_sent(log, audience="compaii", classification="private",
                text=old, message_id="m0", result="delivered")
    for i in range(25):
        append_sent(log, audience="compaii", classification="private",
                    text=f"distinct message number {i} with unique content",
                    message_id=f"m{i+1}", result="delivered")
    assert len(recent_for_audience(log, "compaii")) == 20
    assert find_duplicates(log, audience="compaii", text=old) == []


def test_corrupt_lines_are_skipped(tmp_path):
    log = tmp_path / "sent.jsonl"
    log.write_text("not json\n{broken\n")
    append_sent(log, audience="compaii", classification="private",
                text="hello", message_id="m1", result="delivered")
    rows = recent_for_audience(log, "compaii")
    assert len(rows) == 1 and rows[0]["message_id"] == "m1"


def test_normalization_ignores_hashes_and_counters():
    a = "landed on main (77483ba) — push request #30 ok"
    b = "landed on main (d25b07e) — push request #31 ok"
    assert text_hash(a) == text_hash(b)
    assert similarity(a, b) == 1.0


def test_format_evidence_shows_ids_and_snippet(tmp_path):
    log = tmp_path / "sent.jsonl"
    append_sent(log, audience="compaii", classification="private",
                text="the message that already went out",
                message_id="m-evidence", result="delivered")
    hits = find_duplicates(log, audience="compaii",
                           text="the message that already went out")
    ev = format_evidence(hits)
    assert "m-evidence" in ev and "--force" in ev
    assert "EXACT DUPLICATE" in ev


def test_shortened_resend_caught_by_opener(tmp_path):
    """The live failure (2026-08-02): a 600-char summary of a 2600-char
    brief slips the whole-text ratio (~0.37) but shares its opener."""
    log = tmp_path / "sent.jsonl"
    opener = ("CONVERGENCE BRIEF — merge the two daimon-cluster lines "
              "(Nico's call 2026-08-02: you do the merge, with context "
              "from daimon-matrix + daimon-cluster). SITUATION: while "
              "you implemented ontology-weave-v1 + weave-r6 on GitHub")
    long_brief = opener + " main. " + ("Detailed context. " * 150)
    short_resend = opener + " main. PORT: R5 and R6."
    append_sent(log, audience="compaii", classification="private",
                text=long_brief, message_id="m1", result="delivered")
    hits = find_duplicates(log, audience="compaii", text=short_resend)
    assert len(hits) == 1
    assert hits[0]["match"] == "opener"
    ev = format_evidence(hits)
    assert "same opener" in ev


def test_different_openers_pass(tmp_path):
    log = tmp_path / "sent.jsonl"
    append_sent(log, audience="compaii", classification="private",
                text="CONVERGENCE BRIEF — the merge plan is ready. "
                     "Long detailed body follows here.",
                message_id="m1", result="delivered")
    hits = find_duplicates(log, audience="compaii",
                           text="HEARTBEAT — nothing new to report. "
                                "All quiet on every front today.")
    assert hits == []

