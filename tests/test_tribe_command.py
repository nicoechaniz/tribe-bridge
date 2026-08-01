import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "scripts" / "tribe"


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

    def test_send_requires_explicit_identity_or_host_default(self):
        with tempfile.TemporaryDirectory() as home:
            result = subprocess.run(
                ["bash", str(COMMAND), "send", "--to", "compaii", "--text", "hi"],
                capture_output=True,
                text=True,
                check=False,
                env={"HOME": home},
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("client environment is not readable", result.stderr)


if __name__ == "__main__":
    unittest.main()
