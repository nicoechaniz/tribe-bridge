import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
