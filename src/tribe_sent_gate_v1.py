#!/usr/bin/env python3
"""Sent-message log and duplicate gate for Tribe v1 (2026-08-02).

Origin: compaii@daimonmatrix kept re-sending materially identical
messages (the same "pull main" push request eight times) because
nothing forced a review of what had already been sent. Nico's rule:
before composing a send, check the already-sent messages for the same
audience; if the new text is materially the same, stop and show the
evidence.

Design:
- A local JSONL log (plaintext stays on this host — it is our own
  outbox record, it never travels) appended AFTER every accepted send
  (including outbox-queued fallback: the intent was expressed).
- The gate compares against the most recent messages to the SAME
  audience with two signals:
  * exact normalized hash — always blocks;
  * whole-text similarity (difflib ratio >= threshold) — blocks;
  * OPENER similarity (first ~120 normalized chars >= 0.85) — blocks:
    a shortened re-send of the same brief shares its opening lines
    even when the full-text ratio drops below threshold (proven live
    2026-08-02: a 600-char summary of a 2600-char brief slipped the
    whole-text check at ~0.37 and was caught by the opener check).
- `--force` overrides explicitly; on a TTY the operator is asked.
"""

import difflib
import hashlib
import json
import os
import re
import time
from pathlib import Path

DEFAULT_WINDOW = 20          # recent messages per audience to compare
DEFAULT_THRESHOLD = 0.6      # whole-text similarity that counts as same
OPENER_LEN = 120             # chars of normalized opener to compare
OPENER_THRESHOLD = 0.85      # same opener + same audience = same thread


def default_log_path() -> Path:
    return Path(os.environ.get(
        "TRIBE_V1_SENT_LOG",
        str(Path.home() / ".tribe-bridge/v1/sent-log.jsonl")))


def _normalize(text: str) -> str:
    """Whitespace/case-folded text for comparison. Message counters
    (e.g. 'PUSH REQUEST #31' vs '#32') and commit hashes are stripped
    so a re-numbered repeat still counts as the same message."""
    t = " ".join(text.lower().split())
    t = re.sub(r"#\d+", "#", t)
    t = re.sub(r"\b[0-9a-f]{7,40}\b", "<hash>", t)
    return t


def text_hash(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode()).hexdigest()


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()


def _opener(text: str) -> str:
    return _normalize(text)[:OPENER_LEN]


def opener_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _opener(a), _opener(b)).ratio()


def append_sent(path: Path, *, audience: str, classification: str,
                text: str, message_id: str, result: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ms": int(time.time() * 1000),
        "audience": audience,
        "classification": classification,
        "message_id": message_id,
        "result": result,
        "text_hash": text_hash(text),
        "text": text,
    }
    with path.open("a") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def recent_for_audience(path: Path, audience: str,
                        window: int = DEFAULT_WINDOW) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("audience") == audience:
                rows.append(rec)
    return rows[-window:]


def find_duplicates(path: Path, *, audience: str, text: str,
                    threshold: float = DEFAULT_THRESHOLD,
                    window: int = DEFAULT_WINDOW) -> list[dict]:
    """Return prior sends to the same audience that are materially the
    same message, each annotated with how it matched."""
    new_hash = text_hash(text)
    hits = []
    for rec in recent_for_audience(path, audience, window=window):
        prior = rec.get("text", "")
        if rec.get("text_hash") == new_hash:
            hits.append({**rec, "similarity": 1.0, "exact": True,
                         "match": "exact"})
            continue
        ratio = similarity(text, prior)
        if ratio >= threshold:
            hits.append({**rec, "similarity": round(ratio, 3),
                         "exact": False, "match": "similar"})
            continue
        op = opener_similarity(text, prior)
        if op >= OPENER_THRESHOLD and len(_normalize(text)) >= 40:
            hits.append({**rec, "similarity": round(ratio, 3),
                         "opener_similarity": round(op, 3),
                         "exact": False, "match": "opener"})
    return hits


def format_evidence(hits: list[dict]) -> str:
    lines = ["similar message(s) already sent to this audience:"]
    for h in hits:
        when = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.localtime(h["ms"] / 1000))
        snippet = " ".join(h.get("text", "").split())[:160]
        if h.get("exact"):
            kind = "EXACT DUPLICATE"
        elif h.get("match") == "opener":
            kind = f"same opener ({h.get('opener_similarity')})"
        else:
            kind = f"similarity {h['similarity']}"
        result = h.get("result", "?")
        lines.append(f"  - [{kind}] {when} id={h.get('message_id')} "
                     f"({result})")
        lines.append(f"    {snippet}")
    lines.append(
        "do NOT re-send this content: the earlier send is already in the "
        "recipient's inbox — re-sending adds noise, not signal, and the "
        "recipient will see the repetition as the problem, not the "
        "message. If you are waiting on them, wait; the ids above are "
        "your proof of delivery. --force exists ONLY for false positives "
        "(genuinely new information that merely looks similar) — using it "
        "to force the same content through defeats this gate.")
    return "\n".join(lines)
