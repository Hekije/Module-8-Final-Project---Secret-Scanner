import unittest
import tempfile
from pathlib import Path

from scanner import (
    detect_secrets,
    scan_path,
    mask_secret,
    is_supported_file
)


class TestSecretScanner(unittest.TestCase):

    def test_password_detection(self):
        findings = detect_secrets(
            'password = "FakePassword123"'
        )
        self.assertTrue(
            any(f["type"] == "Password"
                for f in findings)
        )

    def test_api_key_detection(self):
        findings = detect_secrets(
            'api_key = "EXAMPLE_KEY_123"'
        )
        self.assertTrue(
            any(f["type"] == "API Key"
                for f in findings)
        )

    def test_token_detection(self):
        findings = detect_secrets(
            'access_token = "FAKE_TOKEN_123"'
        )
        self.assertTrue(
            any(f["type"] == "Token"
                for f in findings)
        )

    def test_private_key_detection(self):
        findings = detect_secrets(
            "-----BEGIN RSA PRIVATE KEY-----"
        )
        self.assertTrue(
            any(f["type"] == "Private Key"
                for f in findings)
        )

    def test_safe_text(self):
        findings = detect_secrets(
            'username = "admin"'
        )
        self.assertEqual(len(findings), 0)

    def test_multiple_secrets(self):
        findings = detect_secrets(
            'password = "Fake123" '
            'token = "Example456"'
        )
        self.assertEqual(len(findings), 2)

    def test_secret_masking(self):
        masked = mask_secret(
            'password = "FakePassword123"'
        )
        self.assertNotIn(
            "FakePassword123", masked
        )

    def test_nonexistent_file(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / "missing.txt"

            with self.assertRaises(FileNotFoundError):
                scan_path(missing)

    def test_line_numbers(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "sample.txt"

            file.write_text(
                'username = "admin"\n'
                'password = "Fake123"\n',
                encoding="utf-8"
            )

            findings = scan_path(file)

            self.assertEqual(len(findings), 1)
            self.assertEqual(
                findings[0]["line"], 2
            )

    def test_env_local_support(self):
        self.assertTrue(
            is_supported_file(".env.local")
        )

    def test_directory_scanning(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "config.py"

            file.write_text(
                'api_key = "FAKE_KEY_123"\n',
                encoding="utf-8"
            )

            findings = scan_path(folder)
            self.assertEqual(len(findings), 1)

    def test_excluded_file(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "config.py"

            file.write_text(
                'password = "Fake123"\n',
                encoding="utf-8"
            )

            findings = scan_path(
                folder,
                exclude_paths=[file]
            )
            self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()