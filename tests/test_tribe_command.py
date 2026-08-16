import importlib.util
import json
import os
import subprocess
import sys
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

    def test_client_environment_cannot_replace_reviewed_repo_or_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reviewed_repo = root / "reviewed"
            attacker_repo = root / "attacker"
            reviewed_repo.mkdir()
            attacker_repo.mkdir()
            scripts = reviewed_repo / "scripts"
            scripts.mkdir()
            log = root / "execution.json"
            (scripts / "tribe_launcher.py").write_bytes(
                (ROOT / "scripts" / "tribe_launcher.py").read_bytes()
            )
            (scripts / "send_v1.py").write_text(
                "import json, os, sys\n"
                f"open({str(log)!r}, 'w').write(json.dumps({{'argv': sys.argv, "
                "'repo': os.environ['TRIBE_V1_REPO'], "
                "'python': os.environ['TRIBE_V1_PYTHON']}))\n"
            )
            client_env = root / "client.env"
            client_env.write_text("TRIBE_CLIENT_ID=fixture\n")
            client_env.chmod(0o600)
            result = subprocess.run(
                ["bash", str(COMMAND), "send", "--to", "peer", "--text", "hi"],
                capture_output=True,
                text=True,
                check=False,
                env={
                    "HOME": str(root),
                    "PATH": os.environ["PATH"],
                    "TRIBE_CLIENT_ENV": str(client_env),
                    "TRIBE_V1_REPO": str(reviewed_repo),
                    "TRIBE_V1_PYTHON": sys.executable,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            execution = json.loads(log.read_text())
            self.assertEqual(execution["argv"][0], str(reviewed_repo / "scripts/send_v1.py"))
            self.assertEqual(execution["repo"], str(reviewed_repo))
            self.assertEqual(execution["python"], sys.executable)

    def test_client_environment_rejects_shell_and_executable_overrides(self):
        attacks = (
            "repo=/tmp\nTRIBE_CLIENT_ID=fixture\n",
            "python=/bin/echo\nTRIBE_CLIENT_ID=fixture\n",
            "TRIBE_V1_REPO=/tmp\nTRIBE_CLIENT_ID=fixture\n",
            "TRIBE_V1_PYTHON=/bin/echo\nTRIBE_CLIENT_ID=fixture\n",
            "exec /bin/echo compromised\n",
            "TRIBE_CLIENT_ID=$(exec /bin/echo compromised)\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, attack in enumerate(attacks):
                client_env = root / f"attack-{index}.env"
                client_env.write_text(attack)
                client_env.chmod(0o600)
                result = subprocess.run(
                    ["bash", str(COMMAND), "send", "--to", "peer", "--text", "hi"],
                    capture_output=True,
                    text=True,
                    check=False,
                    env={
                        "HOME": str(root),
                        "PATH": os.environ["PATH"],
                        "TRIBE_CLIENT_ENV": str(client_env),
                        "TRIBE_V1_REPO": str(ROOT),
                        "TRIBE_V1_PYTHON": sys.executable,
                    },
                )
                self.assertEqual(result.returncode, 2, (attack, result))
                self.assertNotIn("compromised", result.stdout)

    def test_client_environment_must_be_owner_only_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "identity.env"
            target.write_text("TRIBE_CLIENT_ID=fixture\n")
            target.chmod(0o644)
            link = root / "identity-link.env"
            link.symlink_to(target)
            for client_env in (target, link):
                result = subprocess.run(
                    ["bash", str(COMMAND), "inbox"],
                    capture_output=True,
                    text=True,
                    check=False,
                    env={
                        "HOME": str(root),
                        "PATH": os.environ["PATH"],
                        "TRIBE_CLIENT_ENV": str(client_env),
                        "TRIBE_V1_REPO": str(ROOT),
                        "TRIBE_V1_PYTHON": sys.executable,
                    },
                )
                self.assertEqual(result.returncode, 2, result)
                self.assertIn("client environment", result.stderr)

    def test_client_environment_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client_env = root / "identity.env"
            os.mkfifo(client_env, mode=0o600)
            result = subprocess.run(
                ["bash", str(COMMAND), "inbox"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
                env={
                    "HOME": str(root),
                    "PATH": os.environ["PATH"],
                    "TRIBE_CLIENT_ENV": str(client_env),
                    "TRIBE_V1_REPO": str(ROOT),
                    "TRIBE_V1_PYTHON": sys.executable,
                },
            )

            self.assertEqual(result.returncode, 2, result)
            self.assertIn("owner-only regular file", result.stderr)


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

    def test_provider_refuses_missing_explicit_client_environment(self):
        environment = {
            "TRIBE_V1_REPO": str(ROOT),
            "TRIBE_V1_PYTHON": "/runtime/python",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "TRIBE_CLIENT_ENV is required"):
                self.provider._run(["inbox"])


if __name__ == "__main__":
    unittest.main()
