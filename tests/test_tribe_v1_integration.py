import copy
import json
import subprocess
import sys
import tempfile
import threading
import urllib.request
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import tribe_protocol_v1 as protocol
from tribe_broker_v1 import RequestReplay, SQLiteBroker
from tribe_client_v1 import (
    InboxStore,
    claim_and_process,
    flush_outbox,
    make_ack,
    post_signed,
    send_with_fallback,
)
from tribe_crypto_v1 import (
    KeyBundle,
    b64url,
    decrypt_envelope,
    encrypt_envelope,
    message_payload,
)
from tribe_directory_v1 import (
    Directory,
    DirectoryError,
    directory_sha256,
)
from tribe_mirror_v1 import MirrorPolicyError, TelegramPolicy
from tribe_locality_v1 import LocalityPolicyError
from tribe_service_v1 import (
    BoundedThreadingHTTPServer,
    TribeV1Handler,
    TribeV1Service,
)
from tribe_transport_v1 import wrap_request
from v1_fixtures import NOW, make_material, resign_directory, signing_key


class MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class TribeV1IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.material = make_material(self.root / "identity")
        self.directory = Directory.load(
            self.material["directory_path"],
            self.material["roots_path"],
            self.material["state_path"],
            now_ms=NOW,
        )
        self.local_agent_ids = frozenset(self.directory.agents)
        self.alice = KeyBundle.load(self.material["bundles"]["alice"])
        self.worker = KeyBundle.load(
            self.material["bundles"]["worker@localhost"]
        )
        self.mirror = KeyBundle.load(
            self.material["bundles"]["mirror"]
        )
        self.clock = MutableClock(NOW)

    def service(self, name, *, local_agent_ids=None):
        broker = SQLiteBroker(
            self.root / f"{name}.sqlite", clock_ms=self.clock
        )
        return TribeV1Service(
            broker,
            self.directory,
            build_commit="a" * 40,
            local_agent_ids=(
                self.local_agent_ids
                if local_agent_ids is None
                else frozenset(local_agent_ids)
            ),
            clock_ms=self.clock,
        )

    def serve(self, name):
        service = self.service(name)
        server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), TribeV1Handler, max_workers=4
        )
        server.service = service
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_address[1]}"

        def stop_server():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "test HTTP server did not stop")

        self.addCleanup(stop_server)
        with urllib.request.urlopen(
            f"{endpoint}/v1/health", timeout=5
        ) as response:
            self.assertEqual(response.status, 200)
        return service, endpoint

    def direct_envelope(self, ttl_ms=60_000):
        payload = message_payload(
            sender="alice",
            to="worker@localhost",
            text="hola <worker>",
        )
        return encrypt_envelope(
            payload,
            directory=self.directory,
            keys=self.alice,
            audience_type="direct",
            audience_id="worker@localhost",
            local_agent_ids=self.local_agent_ids,
            now_ms=NOW,
            ttl_ms=ttl_ms,
        )

    def worker_envelope(
        self, audience_type, audience_id, *, local_agent_ids
    ):
        payload = message_payload(
            sender="worker@localhost",
            to=audience_id,
            text="locality gate",
            classification=(
                "tribe-public" if audience_type == "group" else "private"
            ),
        )
        return encrypt_envelope(
            payload,
            directory=self.directory,
            keys=self.worker,
            audience_type=audience_type,
            audience_id=audience_id,
            local_agent_ids=frozenset(local_agent_ids),
            now_ms=NOW,
        )

    def directory_from_snapshot(self, snapshot, name):
        signed = resign_directory(snapshot, signing_key(1))
        path = self.root / f"{name}-directory.json"
        path.write_text(json.dumps(signed))
        return Directory.load(
            path,
            self.material["roots_path"],
            self.root / f"{name}-state.json",
            now_ms=NOW,
        )

    def test_directory_signature_key_bundle_and_rollback_are_fail_closed(self):
        self.alice.verify_against(self.directory, NOW)
        state = json.loads(self.material["state_path"].read_text())
        self.assertEqual(state["directory_epoch"], 1)
        self.assertEqual(state["directory_sha256"], self.directory.hash)
        self.assertEqual(len(state["roots_sha256"]), 64)

        concurrent_state = self.root / "concurrent-state.json"
        results = []
        failures = []

        def loader():
            try:
                results.append(
                    Directory.load(
                        self.material["directory_path"],
                        self.material["roots_path"],
                        concurrent_state,
                        now_ms=NOW,
                    ).hash
                )
            except Exception as exc:
                failures.append(exc)

        threads = [threading.Thread(target=loader) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(results, [self.directory.hash] * 2)

        split = copy.deepcopy(self.material["snapshot"])
        split["expires_at_ms"] += 1
        split = resign_directory(split, signing_key(1))
        self.material["directory_path"].write_text(json.dumps(split))
        with self.assertRaisesRegex(DirectoryError, "split view"):
            Directory.load(
                self.material["directory_path"],
                self.material["roots_path"],
                self.material["state_path"],
                now_ms=NOW,
            )

    def test_real_crypto_direct_policy(self):
        direct = self.direct_envelope()
        plaintext = decrypt_envelope(
            direct,
            directory=self.directory,
            keys=self.worker,
            now_ms=NOW,
        )
        self.assertEqual(plaintext["text"], "hola <worker>")
        with self.assertRaises(protocol.ProtocolError):
            decrypt_envelope(
                direct,
                directory=self.directory,
                keys=self.mirror,
                now_ms=NOW,
            )

    def test_direct_observer_receives_wrap_delivery_without_sender_authority(self):
        snapshot = copy.deepcopy(self.material["snapshot"])
        snapshot["audiences"][0]["observers"] = ["mirror"]
        observed = self.directory_from_snapshot(snapshot, "observed")

        envelope = encrypt_envelope(
            message_payload(
                sender="alice",
                to="worker@localhost",
                text="auditable private message",
            ),
            directory=observed,
            keys=self.alice,
            audience_type="direct",
            audience_id="worker@localhost",
            local_agent_ids=self.local_agent_ids,
            now_ms=NOW,
        )
        self.assertEqual(
            {recipient["id"] for recipient in envelope["recipients"]},
            {"worker@localhost", "mirror"},
        )
        for keys in (self.worker, self.mirror):
            self.assertEqual(
                decrypt_envelope(
                    envelope,
                    directory=observed,
                    keys=keys,
                    now_ms=NOW,
                )["text"],
                "auditable private message",
            )

        broker = SQLiteBroker(self.root / "observed.sqlite")
        broker.enqueue(
            envelope,
            observed.context(sender_id="alice", now_ms=NOW),
            received_at_ms=NOW,
        )
        self.assertEqual(
            len(broker.claim("worker@localhost", now_ms=NOW)), 1
        )
        self.assertEqual(len(broker.claim("mirror", now_ms=NOW)), 1)

        with self.assertRaisesRegex(
            DirectoryError, "sender is not authorized"
        ):
            encrypt_envelope(
                message_payload(
                    sender="mirror",
                    to="worker@localhost",
                    text="observer cannot publish",
                ),
                directory=observed,
                keys=self.mirror,
                audience_type="direct",
                audience_id="worker@localhost",
                local_agent_ids=self.local_agent_ids,
                now_ms=NOW,
            )

        missing_observer = copy.deepcopy(envelope)
        missing_observer["recipients"] = [
            recipient
            for recipient in missing_observer["recipients"]
            if recipient["id"] != "mirror"
        ]
        missing_observer["signature"]["value"] = b64url(
            self.material["agents"]["alice"]["signing"].sign(
                protocol.signature_preimage(missing_observer)
            )
        )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "invalid_recipient_set"
        ):
            protocol.validate_broker_admission(
                missing_observer,
                observed.context(sender_id="alice", now_ms=NOW),
            )

        with self.assertRaisesRegex(
            protocol.ProtocolError, "invalid_recipient_set"
        ):
            protocol.validate_broker_admission(
                envelope,
                self.directory.context(sender_id="alice", now_ms=NOW),
            )

    def test_direct_observers_are_strict_and_part_of_locality_boundary(self):
        invalid_cases = (
            (2, ["alice"], "only valid for direct"),
            (0, [], "invalid audience observers"),
            (0, ["mirror", "mirror"], "duplicate audience observers"),
            (0, ["worker@localhost"], "must not be members"),
            (0, ["unknown"], "unknown agent"),
            (1, ["worker@localhost"], "must not be allowed senders"),
        )
        for index, (audience_index, observers, error) in enumerate(
            invalid_cases
        ):
            with self.subTest(observers=observers, error=error):
                snapshot = copy.deepcopy(self.material["snapshot"])
                snapshot["audiences"][audience_index]["observers"] = observers
                with self.assertRaisesRegex(DirectoryError, error):
                    self.directory_from_snapshot(snapshot, f"invalid-{index}")

        snapshot = copy.deepcopy(self.material["snapshot"])
        snapshot["audiences"][1]["observers"] = ["mirror"]
        observed = self.directory_from_snapshot(snapshot, "local-observer")
        with self.assertRaisesRegex(
            LocalityPolicyError, "remote or mixed audience"
        ):
            encrypt_envelope(
                message_payload(
                    sender="worker@localhost",
                    to="alice",
                    text="must remain local",
                ),
                directory=observed,
                keys=self.worker,
                audience_type="direct",
                audience_id="alice",
                local_agent_ids=frozenset(
                    {"worker@localhost", "alice"}
                ),
                now_ms=NOW,
            )

    def test_retired_audience_allows_queued_receive_but_not_new_admission(self):
        old_envelope = self.direct_envelope()
        broker = SQLiteBroker(self.root / "transition.sqlite")
        broker.enqueue(
            old_envelope,
            self.directory.context(sender_id="alice", now_ms=NOW),
            received_at_ms=NOW,
        )

        snapshot = copy.deepcopy(self.material["snapshot"])
        old_audience = snapshot["audiences"][0]
        old_audience["status"] = "retired"
        new_audience = copy.deepcopy(old_audience)
        new_audience.update(
            {"epoch": 2, "status": "active", "observers": ["mirror"]}
        )
        snapshot["audiences"].append(new_audience)
        transitioned = self.directory_from_snapshot(snapshot, "transitioned")

        claim = broker.claim("worker@localhost", now_ms=NOW)[0]
        self.assertEqual(
            decrypt_envelope(
                claim["envelope"],
                directory=transitioned,
                keys=self.worker,
                now_ms=NOW,
            )["text"],
            "hola <worker>",
        )
        with self.assertRaises(protocol.ProtocolError):
            decrypt_envelope(
                old_envelope,
                directory=transitioned,
                keys=self.mirror,
                now_ms=NOW,
            )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "unauthorized_audience"
        ):
            protocol.validate_broker_admission(
                old_envelope,
                transitioned.context(sender_id="alice", now_ms=NOW),
            )

        new_envelope = encrypt_envelope(
            message_payload(
                sender="alice",
                to="worker@localhost",
                text="new observed epoch",
            ),
            directory=transitioned,
            keys=self.alice,
            audience_type="direct",
            audience_id="worker@localhost",
            local_agent_ids=self.local_agent_ids,
            now_ms=NOW,
        )
        self.assertEqual(new_envelope["audience"]["epoch"], 2)
        self.assertEqual(
            {recipient["id"] for recipient in new_envelope["recipients"]},
            {"worker@localhost", "mirror"},
        )

    def test_real_crypto_group_and_mirror_policy(self):
        public_payload = message_payload(
            sender="alice",
            to="public-agents",
            text="<b>not trusted HTML</b>",
            classification="tribe-public",
        )
        group = encrypt_envelope(
            public_payload,
            directory=self.directory,
            keys=self.alice,
            audience_type="group",
            audience_id="public-agents",
            local_agent_ids=self.local_agent_ids,
            now_ms=NOW,
        )
        mirror_payload = decrypt_envelope(
            group,
            directory=self.directory,
            keys=self.mirror,
            now_ms=NOW,
        )
        policy = TelegramPolicy.from_values(
            chat_ids=[-1001],
            user_ids=[7],
            audiences=["public-agents"],
        )
        rendered = policy.render(mirror_payload, group)
        self.assertIn("&lt;b&gt;not trusted HTML&lt;/b&gt;", rendered)
        self.assertIn(group["message_id"], rendered)
        private = copy.deepcopy(mirror_payload)
        private["classification"] = "private"
        with self.assertRaises(MirrorPolicyError):
            policy.render(private, group)
        with self.assertRaises(MirrorPolicyError):
            policy.validate_inbound_update(
                {
                    "update_id": 1,
                    "message": {
                        "chat": {"id": -999},
                        "from": {"id": 7},
                        "text": "hola",
                    },
                }
            )

    def test_mirror_transparency_mode_renders_configured_direct_private(self):
        payload = message_payload(
            sender="alice",
            to="worker@localhost",
            text="coordination note",
            classification="private",
        )
        direct = {
            "audience": {"type": "direct", "id": "worker@localhost"},
            "sender": {"id": "alice"},
            "message_id": "019f0000-0000-7000-8000-000000000001",
        }
        policy = TelegramPolicy.from_values(
            chat_ids=[-1001],
            user_ids=[7],
            audiences=["worker@localhost"],
            audience_types=["direct"],
            classifications=["tribe-public", "private"],
        )
        rendered = policy.render(payload, direct)
        self.assertIn("alice", rendered)
        self.assertIn("worker@localhost", rendered)
        self.assertIn(direct["message_id"], rendered)
        # An unconfigured audience still fails closed.
        with self.assertRaises(MirrorPolicyError):
            TelegramPolicy.from_values(
                chat_ids=[-1001],
                user_ids=[7],
                audiences=["public-agents"],
                audience_types=["direct"],
                classifications=["tribe-public", "private"],
            ).render(payload, direct)
        # An unconfigured classification still fails closed.
        restricted_classification = TelegramPolicy.from_values(
            chat_ids=[-1001],
            user_ids=[7],
            audiences=["worker@localhost"],
            audience_types=["direct"],
        )
        with self.assertRaises(MirrorPolicyError):
            restricted_classification.render(payload, direct)
        # An unconfigured audience type still fails closed.
        restricted_type = TelegramPolicy.from_values(
            chat_ids=[-1001],
            user_ids=[7],
            audiences=["worker@localhost"],
            classifications=["tribe-public", "private"],
        )
        with self.assertRaises(MirrorPolicyError):
            restricted_type.render(payload, direct)
        # A non-group/non-direct audience type still fails closed.
        weird = copy.deepcopy(direct)
        weird["audience"] = {"type": "channel", "id": "worker@localhost"}
        with self.assertRaises(MirrorPolicyError):
            policy.render(payload, weird)

        # The complete default remains group-only even if a direct audience
        # identifier is already present in the audience allowlist.
        public_direct = copy.deepcopy(payload)
        public_direct["classification"] = "tribe-public"
        with self.assertRaises(MirrorPolicyError):
            TelegramPolicy.from_values(
                chat_ids=[-1001],
                user_ids=[7],
                audiences=["worker@localhost"],
            ).render(public_direct, direct)

    def test_mirror_policy_rejects_malformed_transparency_allowlists(self):
        base = {
            "chat_ids": [-1001],
            "user_ids": [7],
            "audiences": ["worker@localhost"],
        }
        invalid_classifications = (
            {"private": False},
            "private",
            [1],
            ["unknown"],
            [],
        )
        for classifications in invalid_classifications:
            with self.subTest(classifications=classifications):
                with self.assertRaises(MirrorPolicyError):
                    TelegramPolicy.from_values(
                        **base, classifications=classifications
                    )
        invalid_audience_types = (
            {"direct": False},
            "direct",
            [1],
            ["channel"],
            [],
        )
        for audience_types in invalid_audience_types:
            with self.subTest(audience_types=audience_types):
                with self.assertRaises(MirrorPolicyError):
                    TelegramPolicy.from_values(
                        **base, audience_types=audience_types
                    )

    def test_localhost_sender_never_wraps_or_delivers_to_remote_members(self):
        with self.assertRaisesRegex(
            LocalityPolicyError, "remote or mixed audience"
        ):
            self.worker_envelope(
                "direct",
                "alice",
                local_agent_ids={"worker@localhost", "mirror"},
            )
        with self.assertRaisesRegex(
            LocalityPolicyError, "remote or mixed audience"
        ):
            self.worker_envelope(
                "group",
                "public-agents",
                local_agent_ids={"worker@localhost"},
            )

        local = self.worker_envelope(
            "direct",
            "alice",
            local_agent_ids={"worker@localhost", "alice"},
        )
        local_wrapper = wrap_request(
            local,
            keys=self.worker,
            method="POST",
            path="/v1/messages",
            now_ms=NOW,
        )
        status, _receipt = self.service(
            "local-boundary",
            local_agent_ids={"worker@localhost", "alice"},
        ).post("/v1/messages", local_wrapper)
        self.assertEqual(status, 201)

        escaped = self.worker_envelope(
            "direct",
            "alice",
            local_agent_ids=self.local_agent_ids,
        )
        escaped_wrapper = wrap_request(
            escaped,
            keys=self.worker,
            method="POST",
            path="/v1/messages",
            now_ms=NOW,
        )
        with self.assertRaises(LocalityPolicyError):
            self.service(
                "remote-boundary", local_agent_ids={"alice", "mirror"}
            ).post("/v1/messages", escaped_wrapper)

        escaped_outbox = SQLiteBroker(self.root / "escaped-outbox.sqlite")
        escaped_outbox.stage_outbox(escaped, now_ms=NOW)
        flush_result = flush_outbox(
            escaped_outbox,
            {"alice": {"direct": "http://127.0.0.1:1"}},
            keys=self.worker,
            local_agent_ids=frozenset({"worker@localhost"}),
            now_ms=NOW,
        )
        self.assertEqual(len(flush_result["dead_letter"]), 1)
        self.assertEqual(flush_result["sent"], [])
        self.assertEqual(flush_result["pending"], [])

        mixed = self.worker_envelope(
            "group",
            "public-agents",
            local_agent_ids=self.local_agent_ids,
        )
        mixed_wrapper = wrap_request(
            mixed,
            keys=self.worker,
            method="POST",
            path="/v1/messages",
            now_ms=NOW,
        )
        with self.assertRaises(LocalityPolicyError):
            self.service(
                "mixed-boundary",
                local_agent_ids={"worker@localhost", "alice"},
            ).post("/v1/messages", mixed_wrapper)

    def test_service_auth_replay_claim_decrypt_and_ack(self):
        service = self.service("service")
        envelope = self.direct_envelope()
        wrapper = wrap_request(
            envelope,
            keys=self.alice,
            method="POST",
            path="/v1/messages",
            now_ms=NOW,
        )
        status, receipt = service.post("/v1/messages", wrapper)
        self.assertEqual(status, 201)
        with self.assertRaises(RequestReplay):
            service.post("/v1/messages", wrapper)

        claim_wrapper = wrap_request(
            {
                "recipient_id": "worker@localhost",
                "limit": 3,
                "lease_ms": 60_000,
            },
            keys=self.worker,
            method="POST",
            path="/v1/claims",
            now_ms=NOW,
        )
        status, response = service.post("/v1/claims", claim_wrapper)
        claim = response["claims"][0]
        plaintext = decrypt_envelope(
            claim["envelope"],
            directory=self.directory,
            keys=self.worker,
            now_ms=NOW,
        )
        self.assertEqual(plaintext["from"], "alice")
        ack = make_ack(
            claim, keys=self.worker, outcome="processed", now_ms=NOW
        )
        ack_wrapper = wrap_request(
            ack,
            keys=self.worker,
            method="POST",
            path="/v1/acks",
            now_ms=NOW,
        )
        status, result = service.post("/v1/acks", ack_wrapper)
        self.assertEqual(result["state"], "acknowledged")
        self.assertEqual(service.health()["protocol"], "tribe/v1")
        self.assertEqual(service.health()["build_commit"], "a" * 40)
        self.assertNotIn("path", service.health()["broker"])

    def test_http_direct_failure_falls_back_and_outbox_recovers(self):
        _service, hub = self.serve("hub")
        envelope = self.direct_envelope()
        outbox = SQLiteBroker(self.root / "client.sqlite")
        result = send_with_fallback(
            envelope,
            ["http://127.0.0.1:1", hub],
            keys=self.alice,
            local_agent_ids=self.local_agent_ids,
            outbox=outbox,
            now_ms=NOW,
            timeout=2,
        )
        self.assertEqual(result["endpoint"], hub)
        self.assertEqual(len(result["fallbacks"]), 1)
        self.assertEqual(outbox.metrics()["outbox"]["sent"], 1)

    def test_offline_staged_outbox_flushes_after_restart(self):
        envelope = self.direct_envelope()
        path = self.root / "offline-client.sqlite"
        SQLiteBroker(path).stage_outbox(envelope, now_ms=NOW)
        _service, hub = self.serve("recovery-hub")
        reopened = SQLiteBroker(path)
        result = flush_outbox(
            reopened,
            {"worker@localhost": {"hub": hub}},
            keys=self.alice,
            local_agent_ids=self.local_agent_ids,
            now_ms=NOW,
        )
        self.assertEqual(len(result["sent"]), 1)
        self.assertEqual(result["pending"], [])
        self.assertEqual(reopened.metrics()["outbox"]["sent"], 1)

    def test_duplicate_across_direct_and_hub_has_one_local_effect(self):
        _direct_service, direct = self.serve("direct")
        _hub_service, hub = self.serve("hub-duplicate")
        envelope = self.direct_envelope()
        post_signed(
            direct,
            "/v1/messages",
            envelope,
            keys=self.alice,
            now_ms=NOW,
        )
        post_signed(
            hub,
            "/v1/messages",
            envelope,
            keys=self.alice,
            now_ms=NOW,
        )
        store = InboxStore(self.root / "inbox.sqlite")
        first = claim_and_process(
            direct,
            directory=self.directory,
            keys=self.worker,
            store=store,
            now_ms=NOW,
        )
        second = claim_and_process(
            hub,
            directory=self.directory,
            keys=self.worker,
            store=store,
            now_ms=NOW,
        )
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])

    def test_expired_message_is_rejected_without_v0_fallback(self):
        envelope = self.direct_envelope(ttl_ms=1_000)
        service = self.service("expired")
        self.clock.value = NOW + 1_001
        wrapper = wrap_request(
            envelope,
            keys=self.alice,
            method="POST",
            path="/v1/messages",
            now_ms=self.clock.value,
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "expired"):
            service.post("/v1/messages", wrapper)
        v0 = copy.deepcopy(envelope)
        v0["version"] = 0
        wrapper = wrap_request(
            v0,
            keys=self.alice,
            method="POST",
            path="/v1/messages",
            now_ms=self.clock.value,
        )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "unsupported_version"
        ):
            service.post("/v1/messages", wrapper)

    def test_compromise_revocation_rejects_an_existing_valid_envelope(self):
        envelope = self.direct_envelope()
        revoked = copy.deepcopy(self.material["snapshot"])
        revoked["directory_epoch"] = 2
        revoked["previous_sha256"] = directory_sha256(
            self.material["snapshot"]
        )
        for agent in revoked["agents"]:
            if agent["id"] == "alice":
                agent["signing_keys"][0]["status"] = "compromised"
        revoked = resign_directory(revoked, signing_key(1))
        self.material["directory_path"].write_text(json.dumps(revoked))
        revoked_directory = Directory.load(
            self.material["directory_path"],
            self.material["roots_path"],
            self.material["state_path"],
            now_ms=NOW + 1,
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "revoked_key"):
            decrypt_envelope(
                envelope,
                directory=revoked_directory,
                keys=self.worker,
                now_ms=NOW + 1,
            )

    def test_clean_cutover_tree_has_no_v0_executables_or_plugin_crypto(self):
        removed = [
            "src/lcm-server.py",
            "src/mirror-bot.py",
            "scripts/send.py",
            "scripts/check_inbox.py",
            "scripts/client_common.py",
            "templates/tribe-bridge@.service",
            "templates/plugins/send-to-agent/__init__.py",
            "allowed_signers",
        ]
        for relative in removed:
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists())
        plugin = (
            ROOT
            / "integrations"
            / "hermes"
            / "send-to-agent-v1"
            / "__init__.py"
        ).read_text()
        self.assertNotIn("cryptography.", plugin)
        self.assertIn("--text-stdin", plugin)
        self.assertIn("input=stdin_text", plugin)

    def test_key_generator_is_non_overwriting_and_private(self):
        output = self.root / "generated" / "new-agent.keys.json"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "generate_v1_keys.py"),
            "agent",
            "--agent-id",
            "new-agent",
            "--epoch",
            "1",
            "--output",
            str(output),
        ]
        first = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        public = json.loads(first.stdout)
        self.assertNotIn("private_key", json.dumps(public))
        second = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True
        )
        self.assertNotEqual(second.returncode, 0)


if __name__ == "__main__":
    unittest.main()
