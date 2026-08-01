import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def _load_check_inbox_module():
    spec = importlib.util.spec_from_file_location(
        "check_inbox_v1", ROOT / "scripts" / "check_inbox_v1.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckInboxCliTests(unittest.TestCase):
    def test_claim_limit_is_rejected_before_identity_or_network_access(self):
        for value in ("0", "4", "-1", "not-an-integer"):
            with self.subTest(value=value):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "check_inbox_v1.py"),
                        "--limit",
                        value,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 2)
                self.assertNotIn("TRIBE_V1_DIRECTORY is required", result.stderr)

    def test_out_of_range_claim_limit_reports_supported_bounds(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_inbox_v1.py"),
                "--limit",
                "4",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertIn("must be between 1 and 3", result.stderr)


class CheckInboxEndpointSemanticsTests(unittest.TestCase):
    """Redundant inbox endpoints: the poll fails closed only when ALL fail."""

    ENV = {
        "TRIBE_V1_DIRECTORY": "/unused/directory.json",
        "TRIBE_V1_GOVERNANCE_ROOTS": "/unused/roots.json",
        "TRIBE_V1_DIRECTORY_STATE": "/unused/state.json",
        "TRIBE_V1_KEYS": "/unused/keys.json",
        "TRIBE_V1_BUILD_COMMIT": "test-build",
        "TRIBE_V1_CLIENT_INBOX_DB": "/unused/inbox.sqlite",
    }

    def _run(self, endpoints, behaviour):
        module = _load_check_inbox_module()
        env = {
            **self.ENV,
            "TRIBE_V1_INBOX_ENDPOINTS": json.dumps(endpoints),
        }
        with (
            mock.patch.dict("os.environ", env, clear=True),
            mock.patch.object(sys, "argv", ["check_inbox_v1.py"]),
            mock.patch.object(module.Directory, "load", return_value=object()),
            mock.patch.object(module.KeyBundle, "load", return_value=object()),
            mock.patch.object(module, "InboxStore", return_value=object()),
            mock.patch.object(
                module, "claim_and_process", side_effect=behaviour
            ) as claim,
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = module.main()
        self.assertEqual(claim.call_count, len(endpoints))
        return code, json.loads(stdout.getvalue())

    def test_partial_endpoint_failure_is_degraded_not_failed(self):
        def behaviour(endpoint, **kwargs):
            if endpoint == "http://dead:8685":
                raise RuntimeError("http://dead:8685 unavailable")
            return [{"payload": {"text": "hola"}}]

        code, out = self._run(
            ["http://dead:8685", "http://alive:8685"], behaviour
        )
        self.assertEqual(code, 0)
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 1)
        self.assertEqual(len(out["failures"]), 1)
        self.assertEqual(out["failures"][0]["endpoint"], "http://dead:8685")

    def test_all_endpoints_failing_fails_closed(self):
        def behaviour(endpoint, **kwargs):
            raise RuntimeError(f"{endpoint} unavailable")

        code, out = self._run(
            ["http://dead-a:8685", "http://dead-b:8685"], behaviour
        )
        self.assertEqual(code, 1)
        self.assertFalse(out["ok"])
        self.assertEqual(out["count"], 0)
        self.assertEqual(len(out["failures"]), 2)

    def test_single_endpoint_failure_unchanged(self):
        def behaviour(endpoint, **kwargs):
            raise RuntimeError(f"{endpoint} unavailable")

        code, out = self._run(["http://dead:8685"], behaviour)
        self.assertEqual(code, 1)
        self.assertFalse(out["ok"])
        self.assertEqual(len(out["failures"]), 1)

    def test_all_endpoints_succeeding_with_zero_messages_is_ok(self):
        code, out = self._run(
            ["http://a:8685", "http://b:8685"], lambda endpoint, **kwargs: []
        )
        self.assertEqual(code, 0)
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["failures"], [])


if __name__ == "__main__":
    unittest.main()
