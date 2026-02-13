import binascii
import hashlib
import unittest
from unittest.mock import patch

import login_cli_bg as app


class PasswordTests(unittest.TestCase):
    def test_hash_password_uses_default_iterations(self):
        record = app.hash_password("StrongPass1!")
        self.assertEqual(record["iterations"], app.DEFAULT_ITERATIONS)
        self.assertTrue(
            app.verify_password(
                "StrongPass1!",
                record["salt"],
                record["password_hash"],
                iterations=record["iterations"],
            )
        )

    def test_verify_password_supports_legacy_iterations(self):
        password = "LegacyPass1!"
        salt = b"1234567890ABCDEF"
        legacy_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, app.LEGACY_ITERATIONS
        )

        self.assertTrue(
            app.verify_password(
                password,
                binascii.hexlify(salt).decode("utf-8"),
                binascii.hexlify(legacy_hash).decode("utf-8"),
            )
        )

    def test_read_password_preserves_whitespace_in_fallback(self):
        with patch.object(app, "msvcrt", None):
            with patch("builtins.input", return_value="  SpaceyPass1!  "):
                value = app.read_password("Password: ")
        self.assertEqual(value, "  SpaceyPass1!  ")


class AuthFlowTests(unittest.TestCase):
    def test_authenticate_user_accepts_legacy_record_without_iterations(self):
        password = "LegacyPass1!"
        salt = b"1234567890ABCDEF"
        legacy_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, app.LEGACY_ITERATIONS
        )
        users = {
            "Alice": {
                "salt": binascii.hexlify(salt).decode("utf-8"),
                "password_hash": binascii.hexlify(legacy_hash).decode("utf-8"),
            }
        }

        with patch.object(app, "read_text", return_value="alice"):
            with patch.object(app, "read_password", return_value=password):
                self.assertEqual(app.authenticate_user(users), "Alice")

    def test_register_rejects_case_insensitive_duplicate(self):
        users = {"SampleUser90": app.hash_password("StrongPass1!")}
        profiles = {}

        with patch.object(app, "read_non_empty", return_value="sampleuser90"):
            app.register_user(users, profiles)

        self.assertEqual(len(users), 1)
        self.assertEqual(profiles, {})

    def test_register_creates_user_and_profile(self):
        users = {}
        profiles = {}

        with patch.object(
            app, "read_non_empty", side_effect=["NewUser", "USA", "Boston"]
        ), patch.object(app, "read_new_password", return_value="StrongPass1!"), patch.object(
            app, "read_email", return_value="new@example.com"
        ), patch.object(
            app, "read_gender", return_value="male"
        ), patch.object(
            app, "read_birth_date", return_value="2000-01-01"
        ), patch.object(
            app, "save_users", return_value=None
        ), patch.object(
            app, "save_profiles", return_value=None
        ):
            app.register_user(users, profiles)

        self.assertIn("NewUser", users)
        self.assertIn("NewUser", profiles)
        self.assertEqual(profiles["NewUser"]["email"], "new@example.com")

    def test_edit_profile_updates_selected_fields(self):
        profiles = {
            "SampleUser90": {
                "email": "old@example.com",
                "country": "Exampleland",
                "city": "Sample City",
                "gender": "male",
                "birth_date": "1990-06-12",
            }
        }

        with patch.object(
            app,
            "read_text",
            side_effect=[
                "new@example.com",
                "",
                "Demo City",
                "female",
                "1991-01-01",
            ],
        ), patch.object(app, "save_profiles", return_value=None):
            app.edit_profile("SampleUser90", profiles)

        self.assertEqual(profiles["SampleUser90"]["email"], "new@example.com")
        self.assertEqual(profiles["SampleUser90"]["country"], "Exampleland")
        self.assertEqual(profiles["SampleUser90"]["city"], "Demo City")
        self.assertEqual(profiles["SampleUser90"]["gender"], "female")
        self.assertEqual(profiles["SampleUser90"]["birth_date"], "1991-01-01")

    def test_edit_profile_rejects_invalid_email(self):
        profiles = {
            "SampleUser90": {
                "email": "old@example.com",
                "country": "Exampleland",
                "city": "Sample City",
                "gender": "male",
                "birth_date": "1990-06-12",
            }
        }

        with patch.object(app, "read_text", side_effect=["bad-email"]), patch.object(
            app, "save_profiles", return_value=None
        ) as save_mock:
            app.edit_profile("SampleUser90", profiles)

        self.assertEqual(profiles["SampleUser90"]["email"], "old@example.com")
        save_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
