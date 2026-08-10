import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "scripts" / "tribe"
PROVIDER_PATH = (
    ROOT / "integrations" / "hermes" / "send-to-agent-v1" / "__init__.py"
)


def load_provider_module():
    spec = importlib.util.spec_from_file_location(
        "tribe_send_to_agent_v1", PROVIDER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Tribe v1 Hermes provider")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TribeCommandTests(unittest.TestCase):
    def test_help_does_not_require_runtime_identity(self):
        result = subprocess.run(
            ["bash", str(COMMAND), "--help"],
            capture_output=True,
            text=True,
            check=False,
            env={"HOME": "/nonexistent"},
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("tribe <command>", result.stdout)

    def test_unknown_command_fails_closed(self):
        result = subprocess.run(
            ["bash", str(COMMAND), "v0"],
            capture_output=True,
            text=True,
            check=False,
            env={"HOME": "/nonexistent"},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown command: v0", result.stderr)

    def test_send_requires_explicit_identity(self):
        with tempfile.TemporaryDirectory() as home:
            result = subprocess.run(
                ["bash", str(COMMAND), "send", "--to", "peer", "--text", "hi"],
                capture_output=True,
                text=True,
                check=False,
                env={"HOME": home},
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("TRIBE_CLIENT_ENV is required", result.stderr)


class HermesProviderCommandTests(unittest.TestCase):
    def setUp(self):
        self.provider = load_provider_module()

    def test_explicit_client_environment_uses_identity_aware_launcher(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"ok": true}', stderr=""
        )
        environment = {
            "TRIBE_V1_REPO": str(ROOT),
            "TRIBE_CLIENT_ENV": "/private/client.env",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            with mock.patch.object(
                self.provider.subprocess, "run", return_value=completed
            ) as run:
                result = self.provider._run(
                    ["send", "--to", "peer", "--text-stdin"],
                    stdin_text="hello",
                )

        self.assertEqual(result, {"ok": True})
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                str(COMMAND),
                "send",
                "--to",
                "peer",
                "--text-stdin",
            ],
        )
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)
        self.assertEqual(run.call_args.kwargs["input"], "hello")
        self.assertEqual(
            run.call_args.kwargs["env"]["TRIBE_CLIENT_ENV"],
            "/private/client.env",
        )

    def test_legacy_environment_keeps_direct_v1_script_fallback(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"ok": True}), stderr=""
        )
        environment = {
            "TRIBE_V1_REPO": str(ROOT),
            "TRIBE_V1_PYTHON": "/runtime/python",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            with mock.patch.object(
                self.provider.subprocess, "run", return_value=completed
            ) as run:
                result = self.provider._run(["inbox"])

        self.assertEqual(result, {"ok": True})
        self.assertEqual(
            run.call_args.args[0],
            ["/runtime/python", "scripts/check_inbox_v1.py"],
        )


if __name__ == "__main__":
    unittest.main()
