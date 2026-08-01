import base64
import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tribe_broker_v1 as broker_module
import tribe_protocol_v1 as protocol


VECTORS = json.loads(
    (
        ROOT / "protocol" / "v1" / "test-vectors" / "vectors.json"
    ).read_text(encoding="utf-8")
)


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def valid_case(case_id="valid-direct"):
    vector = next(case for case in VECTORS["cases"] if case["id"] == case_id)
    return copy.deepcopy(vector["envelope"]), copy.deepcopy(vector["context"])


def resign(envelope):
    private_key = Ed25519PrivateKey.from_private_bytes(
        decode(VECTORS["test_signing_private_seed"])
    )
    envelope["signature"]["value"] = b64url(
        private_key.sign(protocol.signature_preimage(envelope))
    )
    return envelope


def add_receiver_key(context, receiver, private_key):
    kid = f"{receiver}/sig/99"
    context["signing_keys"][kid] = {
        "owner": receiver,
        "status": "active",
        "not_before_ms": 0,
        "not_after_ms": None,
        "public_key": b64url(private_key.public_key().public_bytes_raw()),
    }
    return kid


def make_ack(claim, receiver, kid, private_key, now, outcome="processed"):
    ack = {
        "schema": "tribe-ack/v1",
        "receiver_id": receiver,
        "message_id": claim["message_id"],
        "lease_id": claim["lease_id"],
        "issued_at_ms": now,
        "envelope_sha256": claim["envelope_sha256"],
        "outcome": outcome,
        "receiver_signing_kid": kid,
        "signature": {"alg": "Ed25519", "kid": kid, "value": ""},
    }
    ack["signature"]["value"] = b64url(
        private_key.sign(broker_module.ack_preimage(ack))
    )
    return ack


class MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class SQLiteBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        envelope, context = valid_case()
        self.envelope = envelope
        self.context = context
        self.now = context["now_ms"]
        self.clock = MutableClock(self.now)
        self.broker = broker_module.SQLiteBroker(
            self.root / "broker.sqlite",
            clock_ms=self.clock,
            retry_base_ms=100,
            retry_max_ms=1_000,
        )

    def enqueue(self, envelope=None, context=None):
        return self.broker.enqueue(
            envelope or self.envelope,
            context or self.context,
            received_at_ms=self.clock.value,
        )

    def test_wal_gate_refuses_unpatched_runtime_and_auto_uses_delete(self):
        self.assertFalse(
            broker_module.sqlite_wal_is_safe(sqlite3.sqlite_version_info)
        )
        self.assertEqual(self.broker.runtime_info()["journal_mode"], "delete")
        with self.assertRaisesRegex(broker_module.StorageError, "WAL refused"):
            broker_module.SQLiteBroker(
                self.root / "unsafe.sqlite",
                journal_mode="wal",
            )
        self.assertTrue(broker_module.sqlite_wal_is_safe((3, 51, 3)))
        self.assertTrue(broker_module.sqlite_wal_is_safe((3, 44, 6)))
        self.assertTrue(broker_module.sqlite_wal_is_safe((3, 50, 7)))
        self.assertFalse(broker_module.sqlite_wal_is_safe((3, 51, 2)))

    def test_enqueue_is_idempotent_and_conflicting_bytes_fail(self):
        first = self.enqueue()
        second = self.enqueue()
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["message_pk"], second["message_pk"])

        conflict = copy.deepcopy(self.envelope)
        conflict["content_type"] = "application/vnd.tribe.other+json"
        resign(conflict)
        with self.assertRaises(broker_module.MessageConflict):
            self.enqueue(conflict)
        self.assertEqual(self.broker.metrics()["messages"], 1)

    def test_two_concurrent_claimers_never_receive_same_delivery(self):
        self.enqueue()
        barrier = threading.Barrier(3)
        results = []
        failures = []

        def worker():
            try:
                barrier.wait()
                results.extend(
                    self.broker.claim(
                        "worker@localhost",
                        limit=1,
                        lease_ms=1_000,
                        now_ms=self.now,
                    )
                )
            except Exception as exc:
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(len({item["cursor"] for item in results}), 1)

    def test_signed_ack_is_durable_idempotent_and_cursor_is_monotonic(self):
        self.enqueue()
        claim = self.broker.claim(
            "worker@localhost", lease_ms=1_000, now_ms=self.now
        )[0]
        with self.assertRaises(broker_module.CursorConflict):
            self.broker.advance_cursor(
                "worker@localhost", "worker-1", claim["cursor"]
            )
        receiver_key = Ed25519PrivateKey.generate()
        kid = add_receiver_key(
            self.context, "worker@localhost", receiver_key
        )
        ack = make_ack(
            claim,
            "worker@localhost",
            kid,
            receiver_key,
            self.now,
        )
        result = self.broker.acknowledge(
            ack, self.context, now_ms=self.now
        )
        self.assertEqual(result["state"], "acknowledged")
        self.assertTrue(
            self.broker.acknowledge(
                ack, self.context, now_ms=self.now
            )["duplicate"]
        )
        self.assertEqual(
            self.broker.claim(
                "worker@localhost", now_ms=self.now
            ),
            [],
        )

        self.broker.advance_cursor(
            "worker@localhost", "worker-1", claim["cursor"]
        )
        reopened = broker_module.SQLiteBroker(
            self.root / "broker.sqlite", clock_ms=self.clock
        )
        self.assertEqual(
            reopened.get_cursor("worker@localhost", "worker-1"),
            claim["cursor"],
        )
        self.assertEqual(
            reopened.metrics()["deliveries"]["acknowledged"], 1
        )
        with self.assertRaises(broker_module.CursorConflict):
            reopened.advance_cursor(
                "worker@localhost", "worker-1", 0
            )

    def test_retry_backoff_and_max_attempts_end_in_dead_letter(self):
        broker = broker_module.SQLiteBroker(
            self.root / "retry.sqlite",
            clock_ms=self.clock,
            retry_base_ms=100,
            retry_max_ms=100,
            max_attempts=2,
        )
        broker.enqueue(
            self.envelope, self.context, received_at_ms=self.now
        )
        receiver_key = Ed25519PrivateKey.generate()
        kid = add_receiver_key(
            self.context, "worker@localhost", receiver_key
        )

        first = broker.claim(
            "worker@localhost", lease_ms=1_000, now_ms=self.now
        )[0]
        retry_ack = make_ack(
            first,
            "worker@localhost",
            kid,
            receiver_key,
            self.now,
            "retryable_failed",
        )
        result = broker.acknowledge(
            retry_ack, self.context, now_ms=self.now
        )
        self.assertEqual(result["state"], "queued")
        self.assertEqual(
            broker.claim(
                "worker@localhost", now_ms=self.now + 99
            ),
            [],
        )
        second = broker.claim(
            "worker@localhost",
            lease_ms=1_000,
            now_ms=self.now + 100,
        )[0]
        final_retry = make_ack(
            second,
            "worker@localhost",
            kid,
            receiver_key,
            self.now + 100,
            "retryable_failed",
        )
        final = broker.acknowledge(
            final_retry, self.context, now_ms=self.now + 100
        )
        self.assertEqual(final["state"], "dead_letter")

    def test_group_admission_creates_one_delivery_per_member(self):
        envelope, context = valid_case("valid-group")
        self.broker.enqueue(
            envelope, context, received_at_ms=self.now
        )
        worker = self.broker.claim(
            "worker@localhost", now_ms=self.now
        )
        peer = self.broker.claim("peer", now_ms=self.now)
        self.assertEqual(len(worker), 1)
        self.assertEqual(len(peer), 1)
        self.assertEqual(worker[0]["message_id"], peer[0]["message_id"])

    def test_outbox_survives_retry_and_restart(self):
        staged = self.broker.stage_outbox(
            self.envelope, now_ms=self.now
        )
        self.assertFalse(staged["duplicate"])
        claim = self.broker.claim_outbox(
            lease_ms=1_000, now_ms=self.now
        )[0]
        state = self.broker.complete_outbox(
            claim["outbox_id"],
            claim["lease_id"],
            error="ambiguous timeout",
            now_ms=self.now,
        )
        self.assertEqual(state, "pending")
        self.assertEqual(
            self.broker.claim_outbox(now_ms=self.now + 99),
            [],
        )
        retried = self.broker.claim_outbox(
            lease_ms=1_000, now_ms=self.now + 100
        )[0]
        self.assertEqual(retried["attempt"], 2)
        self.assertEqual(
            self.broker.complete_outbox(
                retried["outbox_id"],
                retried["lease_id"],
                receipt={"ok": True},
                now_ms=self.now + 100,
            ),
            "sent",
        )
        reopened = broker_module.SQLiteBroker(
            self.root / "broker.sqlite", clock_ms=self.clock
        )
        self.assertEqual(reopened.metrics()["outbox"]["sent"], 1)

    def test_backup_is_private_and_integrity_checked(self):
        self.enqueue()
        destination = self.root / "backups" / "broker.sqlite"
        result = self.broker.backup_to(destination)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(result["sha256"]), 64)
        backup = broker_module.SQLiteBroker(destination)
        self.assertEqual(backup.integrity_check(), ["ok"])
        self.assertEqual(backup.metrics()["messages"], 1)
        with self.assertRaises(FileExistsError):
            self.broker.backup_to(destination)

    def test_retention_starts_when_delivery_becomes_terminal(self):
        self.enqueue()
        claim = self.broker.claim(
            "worker@localhost", lease_ms=1_000, now_ms=self.now
        )[0]
        receiver_key = Ed25519PrivateKey.generate()
        kid = add_receiver_key(
            self.context, "worker@localhost", receiver_key
        )
        ack = make_ack(
            claim,
            "worker@localhost",
            kid,
            receiver_key,
            self.now,
        )
        self.broker.acknowledge(ack, self.context, now_ms=self.now)
        self.assertEqual(
            self.broker.maintenance(
                terminal_before_ms=self.now,
                now_ms=self.now,
            )["purged_messages"],
            0,
        )
        self.assertEqual(
            self.broker.maintenance(
                terminal_before_ms=self.now + 1,
                now_ms=self.now + 1,
            )["purged_messages"],
            1,
        )

    def test_corruption_and_simulated_disk_full_fail_closed(self):
        corrupt = self.root / "corrupt.sqlite"
        corrupt.write_bytes(b"not-a-sqlite-database")
        with self.assertRaises(broker_module.StorageCorruption):
            broker_module.SQLiteBroker(corrupt)

        with closing(sqlite3.connect(self.broker.path)) as connection:
            connection.execute(
                """
                CREATE TRIGGER simulate_disk_full
                BEFORE INSERT ON messages
                BEGIN
                    SELECT RAISE(ABORT, 'database or disk is full');
                END
                """
            )
            connection.commit()
        with self.assertRaises(broker_module.StorageError):
            self.enqueue()
        self.assertEqual(self.broker.metrics()["messages"], 0)

    def test_uncommitted_process_crash_is_recovered_without_partial_row(self):
        script = """
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute("PRAGMA foreign_keys=ON")
db.execute("BEGIN IMMEDIATE")
db.execute(
    "INSERT INTO messages(sender_id,message_id,envelope_json,"
    "envelope_sha256,audience_type,audience_id,audience_epoch,"
    "issued_at_ms,expires_at_ms,received_at_ms)"
    " VALUES(?,?,?,?,?,?,?,?,?,?)",
    (
        "crash",
        "00000000-0000-7000-8000-000000000000",
        b"{}",
        "0" * 64,
        "direct",
        "nobody",
        1,
        1,
        2,
        1,
    ),
)
os._exit(17)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(self.broker.path)]
        )
        self.assertEqual(result.returncode, 17)
        reopened = broker_module.SQLiteBroker(self.broker.path)
        self.assertEqual(reopened.metrics()["messages"], 0)
        self.assertEqual(reopened.integrity_check(), ["ok"])


if __name__ == "__main__":
    unittest.main()
