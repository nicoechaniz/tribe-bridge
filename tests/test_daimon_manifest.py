import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daimon_manifest import (  # noqa: E402
    DaimonManifestError,
    select_manifest,
    validate_concept_inventory,
    validate_manifest,
    validate_task,
)
from scripts.bind_daimon_generation import (  # noqa: E402
    BindingError,
    bind_generation,
    reviewed_state_manifest,
)


class DaimonManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (ROOT / "daimon" / "examples" / "compaii.manifest.json").read_text(
                encoding="utf-8"
            )
        )
        cls.task = json.loads(
            (ROOT / "daimon" / "examples" / "github-task.json").read_text(
                encoding="utf-8"
            )
        )

    def test_examples_validate_and_selector_explains_without_authorizing(self):
        validate_manifest(self.manifest)
        validate_task(self.task)

        decision = select_manifest(self.manifest, self.task)

        self.assertTrue(decision["eligible_for_consideration"])
        self.assertEqual(decision["authorization"], "not-evaluated")
        self.assertEqual(
            decision["matched_capabilities"], ["tool.github-coordination"]
        )
        self.assertTrue(
            any("share one GitHub account" in item for item in decision["warnings"])
        )

    def test_partial_capability_is_ineligible_without_explicit_opt_in(self):
        task = copy.deepcopy(self.task)
        task["allow_partial"] = False

        decision = select_manifest(self.manifest, task)

        self.assertFalse(decision["eligible_for_consideration"])
        self.assertIn(
            "capability is only partial: tool.github-coordination",
            decision["reasons"],
        )

    def test_missing_capability_tool_domain_and_realm_are_all_reported(self):
        task = copy.deepcopy(self.task)
        task["required_capabilities"] = ["tool.unknown"]
        task["required_tools"] = ["tool.unknown"]
        task["required_trust_domains"] = ["unknown-domain"]
        task["required_realm"] = "minecraft"

        decision = select_manifest(self.manifest, task)

        self.assertFalse(decision["eligible_for_consideration"])
        self.assertEqual(len(decision["reasons"]), 4)
        self.assertIn("missing capability: tool.unknown", decision["reasons"])
        self.assertIn("missing embodied tool: tool.unknown", decision["reasons"])

    def test_private_task_cannot_cross_federation_trust_domain(self):
        task = copy.deepcopy(self.task)
        task["required_classification"] = "private"

        decision = select_manifest(self.manifest, task)

        self.assertFalse(decision["eligible_for_consideration"])
        self.assertTrue(
            any("not allowed in trust domain" in item for item in decision["reasons"])
        )

    def test_capability_must_cover_every_required_trust_domain(self):
        task = copy.deepcopy(self.task)
        task["required_trust_domains"] = [
            "tribe-federation",
            "local-private",
        ]

        decision = select_manifest(self.manifest, task)

        self.assertFalse(decision["eligible_for_consideration"])
        self.assertNotIn(
            "tool.github-coordination", decision["matched_capabilities"]
        )
        self.assertIn(
            "capability tool.github-coordination does not cover required "
            "trust domains: local-private",
            decision["reasons"],
        )

    def test_unknown_fields_are_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["poetic_authorization"] = True
        with self.assertRaisesRegex(DaimonManifestError, "unknown or missing"):
            validate_manifest(manifest)

        task = copy.deepcopy(self.task)
        task["prompt"] = "trust me"
        with self.assertRaisesRegex(DaimonManifestError, "unknown or missing"):
            validate_task(task)

    def test_embedded_secret_shaped_values_are_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["capabilities"][0]["constraints"].append(
            "Bearer abcdefghijklmnopqrstuvwxyz123456"
        )

        with self.assertRaisesRegex(DaimonManifestError, "embedded secret"):
            validate_manifest(manifest)

    def test_secret_references_are_names_not_values(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["secret_refs"][0]["reference"] = "env://TRIBE_SIGNING_KEY"
        validate_manifest(manifest)

        manifest["secret_refs"][0]["reference"] = "file:///private/key"
        with self.assertRaisesRegex(DaimonManifestError, "unsupported URI"):
            validate_manifest(manifest)

    def test_endpoint_cannot_exceed_trust_domain_classification(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["memory_endpoints"][2]["classifications"].append("private")

        with self.assertRaisesRegex(DaimonManifestError, "exceed trust domain"):
            validate_manifest(manifest)

    def test_implemented_capability_requires_immutable_evidence(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["capabilities"][0]["evidence"] = []

        with self.assertRaisesRegex(DaimonManifestError, "requires immutable"):
            validate_manifest(manifest)

    def test_embodiment_references_only_declared_capabilities(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["embodiment"]["tools"].append("tool.imaginary")

        with self.assertRaisesRegex(DaimonManifestError, "unknown capabilities"):
            validate_manifest(manifest)

    def test_json_schemas_are_closed_and_parseable(self):
        manifest_schema = json.loads(
            (ROOT / "daimon" / "manifest.schema.json").read_text(encoding="utf-8")
        )
        task_schema = json.loads(
            (ROOT / "daimon" / "task.schema.json").read_text(encoding="utf-8")
        )
        inventory_schema = json.loads(
            (ROOT / "daimon" / "concept-inventory.schema.json").read_text(
                encoding="utf-8"
            )
        )
        inventory = json.loads(
            (ROOT / "daimon" / "concept-inventory.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertFalse(manifest_schema["additionalProperties"])
        self.assertFalse(task_schema["additionalProperties"])
        self.assertFalse(inventory_schema["additionalProperties"])
        validate_concept_inventory(inventory)
        self.assertEqual(
            manifest_schema["properties"]["schema"]["const"], "daimon-manifest/v1"
        )

    def test_metaphor_cannot_be_promoted_to_executable_policy(self):
        inventory = json.loads(
            (ROOT / "daimon" / "concept-inventory.json").read_text(
                encoding="utf-8"
            )
        )
        metaphor = next(
            item
            for item in inventory["concepts"]
            if item["classification"] == "metaphor"
        )
        metaphor["executable_mapping"] = "grant:all"

        with self.assertRaisesRegex(DaimonManifestError, "metaphor"):
            validate_concept_inventory(inventory)

    def test_compaii_generation_binding_is_external_and_exact(self):
        state = {
            "schema_version": "compaii-state-manifest/v2",
            "generation": {"id": "12345678-1234-4234-9234-123456789abc"},
            "artifact_index": {"sha256": "b" * 64},
        }

        bound = bind_generation(self.manifest, state, "c" * 40)

        self.assertEqual(
            bound["portability"]["generation_id"],
            "12345678-1234-4234-9234-123456789abc",
        )
        self.assertEqual(bound["portability"]["source_commit"], "c" * 40)
        self.assertEqual(bound["portability"]["artifact_index_sha256"], "b" * 64)

    def test_generation_binding_rejects_wrong_state_schema(self):
        with self.assertRaisesRegex(BindingError, "unsupported"):
            bind_generation(self.manifest, {"schema_version": "v1"}, "c" * 40)

    def test_reviewed_state_loader_rejects_non_full_commit(self):
        with self.assertRaisesRegex(BindingError, "full lowercase"):
            reviewed_state_manifest(ROOT, "main", "refs/remotes/origin/main")

    def test_reviewed_state_loader_requires_remote_reviewed_ancestry(self):
        state = {
            "schema_version": "compaii-state-manifest/v2",
            "generation": {"id": "12345678-1234-4234-9234-123456789abc"},
            "artifact_index": {"sha256": "b" * 64},
        }
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(
                ["git", "init", "--initial-branch=main"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repo,
                check=True,
            )
            (repo / "manifest.json").write_text(
                json.dumps(state), encoding="utf-8"
            )
            subprocess.run(["git", "add", "manifest.json"], cwd=repo, check=True)
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            reviewed = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "git",
                    "update-ref",
                    "refs/remotes/origin/reviewed",
                    reviewed,
                ],
                cwd=repo,
                check=True,
            )

            loaded = reviewed_state_manifest(
                repo, reviewed, "refs/remotes/origin/reviewed"
            )
            self.assertEqual(loaded, state)

            (repo / "manifest.json").write_text(
                json.dumps({**state, "unreviewed": True}), encoding="utf-8"
            )
            subprocess.run(["git", "add", "manifest.json"], cwd=repo, check=True)
            subprocess.run(
                ["git", "commit", "-m", "unreviewed"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            unreviewed = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            with self.assertRaisesRegex(BindingError, "not reachable"):
                reviewed_state_manifest(
                    repo, unreviewed, "refs/remotes/origin/reviewed"
                )


if __name__ == "__main__":
    unittest.main()
