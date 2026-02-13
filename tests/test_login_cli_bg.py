import binascii
import hashlib
import unittest
import uuid
from pathlib import Path
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
            with patch("getpass.getpass", return_value="  SpaceyPass1!  "):
                value = app.read_password("Password: ")
        self.assertEqual(value, "  SpaceyPass1!  ")

    def test_verify_password_returns_false_for_non_string_password(self):
        record = app.hash_password("StrongPass1!")
        self.assertFalse(
            app.verify_password(
                None,
                record["salt"],
                record["password_hash"],
                iterations=record["iterations"],
            )
        )


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

        with patch.object(app, "read_text", return_value="alice"), patch.object(
            app, "read_password", return_value=password
        ):
            self.assertEqual(app.authenticate_user(users), "Alice")

    def test_authenticate_user_migrates_legacy_plaintext_record(self):
        users = {"Alice": {"password": "LegacyPass1!"}}

        with patch.object(app, "read_text", return_value="Alice"), patch.object(
            app, "read_password", return_value="LegacyPass1!"
        ), patch.object(app, "save_user", return_value=None) as save_mock:
            username = app.authenticate_user(users)

        self.assertEqual(username, "Alice")
        self.assertIn("salt", users["Alice"])
        self.assertIn("password_hash", users["Alice"])
        self.assertIn("iterations", users["Alice"])
        self.assertNotIn("password", users["Alice"])
        save_mock.assert_called_once_with("Alice", users["Alice"])

    def test_authenticate_user_keeps_legacy_record_when_migration_save_fails(self):
        users = {"Alice": {"password": "LegacyPass1!"}}

        with patch.object(app, "read_text", return_value="Alice"), patch.object(
            app, "read_password", return_value="LegacyPass1!"
        ), patch.object(app, "save_user", side_effect=app.DataFileError("db locked")):
            username = app.authenticate_user(users)

        self.assertIsNone(username)
        self.assertEqual(users["Alice"], {"password": "LegacyPass1!"})

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
            app, "read_non_empty", side_effect=["NewUser", "Tom", "Popov", "USA", "Boston"]
        ), patch.object(app, "read_new_password", return_value="StrongPass1!"), patch.object(
            app, "read_email", return_value="new@example.com"
        ), patch.object(
            app, "read_gender", return_value="male"
        ), patch.object(
            app, "read_birth_date", return_value="2000-01-01"
        ), patch.object(
            app, "save_account", return_value=None
        ):
            app.register_user(users, profiles)

        self.assertIn("NewUser", users)
        self.assertIn("NewUser", profiles)
        self.assertEqual(profiles["NewUser"]["name"], "Tom")
        self.assertEqual(profiles["NewUser"]["surname"], "Popov")
        self.assertEqual(profiles["NewUser"]["email"], "new@example.com")

    def test_edit_profile_updates_selected_fields(self):
        profiles = {
            "SampleUser90": {
                "name": "OldName",
                "surname": "OldSurname",
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
                "NewName",
                "",
                "new@example.com",
                "",
                "Demo City",
                "female",
                "1991-01-01",
            ],
        ), patch.object(app, "save_profile", return_value=None):
            app.edit_profile("SampleUser90", profiles)

        self.assertEqual(profiles["SampleUser90"]["name"], "NewName")
        self.assertEqual(profiles["SampleUser90"]["surname"], "OldSurname")
        self.assertEqual(profiles["SampleUser90"]["email"], "new@example.com")
        self.assertEqual(profiles["SampleUser90"]["country"], "Exampleland")
        self.assertEqual(profiles["SampleUser90"]["city"], "Demo City")
        self.assertEqual(profiles["SampleUser90"]["gender"], "female")
        self.assertEqual(profiles["SampleUser90"]["birth_date"], "1991-01-01")

    def test_edit_profile_rejects_invalid_email(self):
        profiles = {
            "SampleUser90": {
                "name": "OldName",
                "surname": "OldSurname",
                "email": "old@example.com",
                "country": "Exampleland",
                "city": "Sample City",
                "gender": "male",
                "birth_date": "1990-06-12",
            }
        }

        with patch.object(app, "read_text", side_effect=["", "", "bad-email"]), patch.object(
            app, "save_profile", return_value=None
        ) as save_mock:
            app.edit_profile("SampleUser90", profiles)

        self.assertEqual(profiles["SampleUser90"]["email"], "old@example.com")
        save_mock.assert_not_called()

    def test_edit_profile_rejects_late_invalid_input_without_partial_changes(self):
        profiles = {
            "SampleUser90": {
                "name": "OldName",
                "surname": "OldSurname",
                "email": "old@example.com",
                "country": "Exampleland",
                "city": "Sample City",
                "gender": "male",
                "birth_date": "1990-06-12",
            }
        }
        original = profiles["SampleUser90"].copy()

        with patch.object(
            app,
            "read_text",
            side_effect=[
                "NewName",
                "NewSurname",
                "new@example.com",
                "NewCountry",
                "NewCity",
                "unknown",
            ],
        ), patch.object(app, "save_profile", return_value=None) as save_mock:
            app.edit_profile("SampleUser90", profiles)

        self.assertEqual(profiles["SampleUser90"], original)
        save_mock.assert_not_called()

    def test_show_profile_handles_invalid_profile_record(self):
        profiles = {"SampleUser90": "not-a-dict"}

        with patch("builtins.print") as print_mock:
            app.show_profile("SampleUser90", profiles)

        print_mock.assert_any_call("Profile data is invalid for this user.")

    def test_edit_profile_handles_invalid_profile_record(self):
        profiles = {"SampleUser90": "not-a-dict"}

        with patch("builtins.print") as print_mock, patch.object(
            app, "save_profile", return_value=None
        ) as save_mock:
            app.edit_profile("SampleUser90", profiles)

        print_mock.assert_any_call("Profile data is invalid for this user.")
        save_mock.assert_not_called()

    def test_login_user_limits_failed_attempts(self):
        users = {}
        profiles = {}

        with patch.object(app, "authenticate_user", side_effect=[None, None, None, None, None]), patch.object(
            app, "user_session_menu", return_value=None
        ) as menu_mock, patch.object(app.time, "sleep", return_value=None) as sleep_mock:
            app.login_user(users, profiles)

        menu_mock.assert_not_called()
        self.assertEqual(sleep_mock.call_count, 4)
        self.assertEqual([call.args[0] for call in sleep_mock.call_args_list], [1, 2, 4, 8])

    def test_login_user_succeeds_on_retry(self):
        users = {}
        profiles = {"Alice": {}}

        with patch.object(app, "authenticate_user", side_effect=[None, "Alice"]), patch.object(
            app, "user_session_menu", return_value=None
        ) as menu_mock, patch.object(app.time, "sleep", return_value=None) as sleep_mock:
            app.login_user(users, profiles)

        menu_mock.assert_called_once_with("Alice", profiles)
        sleep_mock.assert_called_once_with(1)

    def test_register_rolls_back_memory_when_atomic_save_fails(self):
        users = {}
        profiles = {}

        with patch.object(
            app, "read_non_empty", side_effect=["NewUser", "Tom", "Popov", "USA", "Boston"]
        ), patch.object(app, "read_new_password", return_value="StrongPass1!"), patch.object(
            app, "read_email", return_value="new@example.com"
        ), patch.object(
            app, "read_gender", return_value="male"
        ), patch.object(
            app, "read_birth_date", return_value="2000-01-01"
        ), patch.object(
            app, "save_account", side_effect=app.DataFileError("disk full")
        ):
            app.register_user(users, profiles)

        self.assertEqual(users, {})
        self.assertEqual(profiles, {})

    def test_edit_profile_restores_original_when_save_fails(self):
        profiles = {
            "SampleUser90": {
                "name": "OldName",
                "surname": "OldSurname",
                "email": "old@example.com",
                "country": "Exampleland",
                "city": "Sample City",
                "gender": "male",
                "birth_date": "1990-06-12",
            }
        }
        original = profiles["SampleUser90"].copy()

        with patch.object(
            app,
            "read_text",
            side_effect=[
                "NewName",
                "",
                "new@example.com",
                "",
                "",
                "",
                "",
            ],
        ), patch.object(app, "save_profile", side_effect=app.DataFileError("write failed")):
            app.edit_profile("SampleUser90", profiles)

        self.assertEqual(profiles["SampleUser90"], original)

    def test_main_shows_startup_error_on_invalid_users_json(self):
        unique = uuid.uuid4().hex
        users_file = Path(f"users.invalid.{unique}.json")
        profiles_file = Path(f"profiles.invalid.{unique}.json")
        db_file = Path(f"app.invalid.{unique}.db")

        try:
            users_file.write_text("{invalid-json", encoding="utf-8")
            profiles_file.write_text("{}", encoding="utf-8")

            with patch.object(app, "USERS_FILE", users_file), patch.object(
                app, "PROFILES_FILE", profiles_file
            ), patch.object(
                app, "DB_FILE", db_file
            ), patch("builtins.print") as print_mock:
                app.main()
        finally:
            users_file.unlink(missing_ok=True)
            profiles_file.unlink(missing_ok=True)
            for path in (db_file, Path(f"{db_file}-wal"), Path(f"{db_file}-shm")):
                try:
                    path.unlink(missing_ok=True)
                except PermissionError:
                    pass

        self.assertTrue(any("Startup error:" in call.args[0] for call in print_mock.call_args_list))


class IntegrationDbTests(unittest.TestCase):
    def setUp(self):
        unique = uuid.uuid4().hex
        self.db_file = Path(f"app.integration.{unique}.db")
        self.users_file = Path(f"users.integration.{unique}.json")
        self.profiles_file = Path(f"profiles.integration.{unique}.json")

    def tearDown(self):
        for path in (
            self.users_file,
            self.profiles_file,
            self.db_file,
            Path(f"{self.db_file}-wal"),
            Path(f"{self.db_file}-shm"),
        ):
            try:
                path.unlink(missing_ok=True)
            except PermissionError:
                pass

    def test_register_persists_profile_and_auth(self):
        with patch.object(app, "DB_FILE", self.db_file), patch.object(
            app, "USERS_FILE", self.users_file
        ), patch.object(app, "PROFILES_FILE", self.profiles_file):
            app.init_storage()
            users = {}
            profiles = {}
            with patch.object(
                app, "read_non_empty", side_effect=["NewUser", "Tom", "Popov", "USA", "Boston"]
            ), patch.object(app, "read_new_password", return_value="StrongPass1!"), patch.object(
                app, "read_email", return_value="new@example.com"
            ), patch.object(
                app, "read_gender", return_value="male"
            ), patch.object(
                app, "read_birth_date", return_value="2000-01-01"
            ):
                app.register_user(users, profiles)

            db_users = app.load_users()
            db_profiles = app.load_profiles()

        self.assertIn("NewUser", db_users)
        self.assertIn("NewUser", db_profiles)
        self.assertEqual(db_profiles["NewUser"]["name"], "Tom")
        self.assertEqual(db_profiles["NewUser"]["surname"], "Popov")

    def test_edit_profile_persists_to_database(self):
        with patch.object(app, "DB_FILE", self.db_file), patch.object(
            app, "USERS_FILE", self.users_file
        ), patch.object(app, "PROFILES_FILE", self.profiles_file):
            app.init_storage()
            app.save_user("Demo", app.hash_password("StrongPass1!"))
            app.save_profile(
                "Demo",
                {
                    "name": "Old",
                    "surname": "Value",
                    "email": "old@example.com",
                    "country": "Oldland",
                    "city": "Oldcity",
                    "gender": "male",
                    "birth_date": "1990-01-01",
                },
            )

            profiles = app.load_profiles()
            with patch.object(
                app,
                "read_text",
                side_effect=[
                    "New",
                    "Name",
                    "new@example.com",
                    "Newland",
                    "Newcity",
                    "female",
                    "1992-02-02",
                ],
            ):
                app.edit_profile("Demo", profiles)

            db_profiles = app.load_profiles()

        self.assertEqual(db_profiles["Demo"]["name"], "New")
        self.assertEqual(db_profiles["Demo"]["surname"], "Name")
        self.assertEqual(db_profiles["Demo"]["email"], "new@example.com")

    def test_legacy_password_migration_persists_to_database(self):
        with patch.object(app, "DB_FILE", self.db_file), patch.object(
            app, "USERS_FILE", self.users_file
        ), patch.object(app, "PROFILES_FILE", self.profiles_file):
            app.init_storage()
            app.save_user("Alice", {"password": "LegacyPass1!"})
            users = app.load_users()

            with patch.object(app, "read_text", return_value="Alice"), patch.object(
                app, "read_password", return_value="LegacyPass1!"
            ):
                username = app.authenticate_user(users)

            db_users = app.load_users()

        self.assertEqual(username, "Alice")
        self.assertIn("salt", db_users["Alice"])
        self.assertIn("password_hash", db_users["Alice"])
        self.assertNotIn("password", db_users["Alice"])

    def test_init_storage_migrates_legacy_profile_schema(self):
        import sqlite3

        conn = sqlite3.connect(self.db_file)
        conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE profiles (username TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

        with patch.object(app, "DB_FILE", self.db_file):
            app.init_storage()
            profiles = app.load_profiles()

        self.assertEqual(profiles, {})

    def test_init_storage_migrates_legacy_users_schema(self):
        import sqlite3

        conn = sqlite3.connect(self.db_file)
        conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE profiles (username TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

        with patch.object(app, "DB_FILE", self.db_file):
            app.init_storage()
            users = app.load_users()

        self.assertEqual(users, {})


if __name__ == "__main__":
    unittest.main()
