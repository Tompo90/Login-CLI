import binascii
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path

try:
    import msvcrt
except ImportError:
    msvcrt = None

USERS_FILE = Path(__file__).parent / "users.json"
PROFILES_FILE = Path(__file__).parent / "profiles.json"
DEFAULT_ITERATIONS = 310_000
LEGACY_ITERATIONS = 100_000
MIN_ITERATIONS = 50_000
MAX_ITERATIONS = 2_000_000
CANCEL_WORDS = {"exit", "quit", "q"}


class CancelOperation(Exception):
    """Raised when user requests to cancel current flow."""


class DataFileError(Exception):
    """Raised when a required JSON data file is invalid."""


def should_cancel(value):
    """Return True if user entered a cancel command."""
    return value.strip().casefold() in CANCEL_WORDS


def read_text(prompt):
    """Read text input and allow cancel keywords."""
    value = input(prompt).strip()
    if should_cancel(value):
        raise CancelOperation
    return value


def configure_console():
    """Force UTF-8 output in Windows terminals."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass


def load_json(path):
    """Load dict data from JSON file. Return empty dict only if file is missing."""
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        raise DataFileError(f"Could not read '{path.name}': {error}") from error

    if not isinstance(data, dict):
        raise DataFileError(f"Invalid format in '{path.name}': root JSON value must be an object.")

    return data


def save_json(path, data):
    """Save dict data to JSON file."""
    # Write to a temporary file first to reduce risk of partial/corrupt writes.
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
    temp_path.replace(path)


def load_users():
    """Load credential records."""
    return load_json(USERS_FILE)


def save_users(users):
    """Save credential records."""
    save_json(USERS_FILE, users)


def load_profiles():
    """Load user profile records."""
    return load_json(PROFILES_FILE)


def save_profiles(profiles):
    """Save user profile records."""
    save_json(PROFILES_FILE, profiles)


def hash_password(password, iterations=DEFAULT_ITERATIONS):
    """Return salt + password hash for secure storage."""
    if not isinstance(iterations, int) or not (MIN_ITERATIONS <= iterations <= MAX_ITERATIONS):
        raise ValueError("Invalid PBKDF2 iteration count.")

    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return {
        "salt": binascii.hexlify(salt).decode("utf-8"),
        "password_hash": binascii.hexlify(password_hash).decode("utf-8"),
        "iterations": iterations,
    }


def verify_password(password, salt_hex, stored_hash_hex, iterations=LEGACY_ITERATIONS):
    """Check whether an entered password matches the stored hash."""
    try:
        if not isinstance(salt_hex, str) or not isinstance(stored_hash_hex, str):
            return False
        if not isinstance(iterations, int):
            return False
        if not (MIN_ITERATIONS <= iterations <= MAX_ITERATIONS):
            return False
        salt = binascii.unhexlify(salt_hex.encode("utf-8"))
        stored_hash = binascii.unhexlify(stored_hash_hex.encode("utf-8"))
    except (AttributeError, ValueError, TypeError, binascii.Error):
        return False

    entered_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(entered_hash, stored_hash)


def normalize_username(username):
    """Return normalized username for comparisons."""
    return username.strip().casefold()


def find_existing_username(users, entered_username):
    """
    Resolve username key.

    Rules:
    - exact match first
    - then case-insensitive match if unique
    - if case-insensitive match is ambiguous, return (None, True)
    """
    entered_username = entered_username.strip()
    if entered_username in users:
        return entered_username, False

    target = normalize_username(entered_username)
    matches = [
        existing_username
        for existing_username in users
        if normalize_username(existing_username) == target
    ]

    if len(matches) == 1:
        return matches[0], False
    if len(matches) > 1:
        return None, True
    return None, False


def read_password(prompt):
    """Read password and show '*' for typed characters."""
    if msvcrt is None or not sys.stdin.isatty():
        # Password input should treat any text literally (including words like "exit").
        value = input(prompt)
        return value

    print(prompt, end="", flush=True)
    chars = []

    while True:
        key = msvcrt.getwch()

        if key in ("\r", "\n"):
            print()
            break

        if key == "\003":
            raise KeyboardInterrupt

        if key == "\b":
            if chars:
                chars.pop()
                print("\b \b", end="", flush=True)
            continue

        if key in ("\x00", "\xe0"):
            msvcrt.getwch()
            continue

        chars.append(key)
        print("*", end="", flush=True)

    return "".join(chars)


def read_non_empty(prompt):
    """Read non-empty text input."""
    while True:
        value = read_text(prompt)
        if value:
            return value
        print("This field cannot be empty.")


def is_valid_email(email):
    """Basic email format validation."""
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email))


def read_email(prompt):
    """Read and validate email format."""
    while True:
        email = read_text(prompt)
        if is_valid_email(email):
            return email
        print("Invalid email format. Example: name@example.com")


def read_gender(prompt):
    """Read gender as male/female."""
    while True:
        value = read_text(prompt).lower()
        if value in ("male", "female"):
            return value
        print("Please enter 'male' or 'female'.")


def is_valid_birth_date(value):
    """Validate birth date format and range."""
    try:
        birth_date = datetime.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return False

    today = datetime.date.today()
    return datetime.date(1900, 1, 1) <= birth_date <= today


def read_birth_date(prompt):
    """Read birth date in YYYY-MM-DD format."""
    while True:
        value = read_text(prompt)
        if is_valid_birth_date(value):
            return value
        print("Invalid date. Use YYYY-MM-DD between 1900-01-01 and today.")


def password_strength_errors(password):
    """Return a list of unmet password rules."""
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("one symbol")
    return errors


def read_new_password():
    """Read and confirm a strong password."""
    while True:
        password = read_password("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            continue

        errors = password_strength_errors(password)
        if errors:
            print("Weak password. Add: " + ", ".join(errors) + ".")
            continue

        confirm_password = read_password("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match.")
            continue

        return password


def authenticate_user(users):
    """Authenticate a user and return username if successful."""
    entered_username = read_text("Username: ")
    password = read_password("Password: ")

    username, ambiguous = find_existing_username(users, entered_username)
    if ambiguous:
        print("Multiple accounts match that username. Please use exact capitalization.")
        return None

    if not username:
        print("User not found.")
        return None

    user_record = users[username]
    if not isinstance(user_record, dict):
        print("Account record is invalid. Please contact support.")
        return None

    if "salt" in user_record and "password_hash" in user_record:
        iterations = user_record.get("iterations", LEGACY_ITERATIONS)
        if verify_password(
            password,
            user_record["salt"],
            user_record["password_hash"],
            iterations=iterations,
        ):
            return username
        print("Wrong password.")
        return None

    # Backward compatibility: migrate old plain-text password records after first successful login.
    if "password" in user_record and user_record["password"] == password:
        users[username] = hash_password(password)
        try:
            save_users(users)
        except OSError:
            # Keep the old record in memory if migration cannot be persisted.
            users[username] = user_record
            print("Login failed: could not update account data. Please try again later.")
            return None
        return username

    print("Wrong password.")
    return None


def register_user(users, profiles):
    """Register a new user."""
    print("\n--- Register ---")
    try:
        username = read_non_empty("Enter username: ")

        existing_username, ambiguous = find_existing_username(users, username)
        if ambiguous:
            print("Cannot register: existing usernames are ambiguous by case. Please contact support.")
            return

        if existing_username:
            print("This username already exists.")
            return

        password = read_new_password()
        email = read_email("Enter email: ")
        country = read_non_empty("Enter country: ")
        city = read_non_empty("Enter city: ")
        gender = read_gender("Enter gender (male/female): ")
        birth_date = read_birth_date("Enter birth date (YYYY-MM-DD): ")

        user_record = hash_password(password)
        profile_record = {
            "email": email,
            "country": country,
            "city": city,
            "gender": gender,
            "birth_date": birth_date,
        }

        users[username] = user_record
        profiles[username] = profile_record
        try:
            save_users(users)
            save_profiles(profiles)
        except OSError:
            # Roll back memory and try to restore files to a consistent state.
            users.pop(username, None)
            profiles.pop(username, None)
            rollback_ok = True
            try:
                save_users(users)
                save_profiles(profiles)
            except OSError:
                rollback_ok = False

            if rollback_ok:
                print("Registration failed while saving data. No account was created.")
            else:
                print("Registration failed while saving data. Files may be inconsistent.")
            return

        print("Registration successful.")
    except CancelOperation:
        print("Registration canceled. Returning to main menu.")


def login_user(users, profiles):
    """Log in existing user."""
    print("\n--- Login ---")
    try:
        username = authenticate_user(users)
        if not username:
            return

        print(f"Login successful. Welcome, {username}!")
        user_session_menu(username, profiles)
    except CancelOperation:
        print("Login canceled. Returning to main menu.")


def show_profile(username, profiles):
    """Show profile details for a logged-in user."""
    profile = profiles.get(username)
    if not profile:
        print("No profile data found for this user.")
        return

    print(f"\nUsername: {username}")
    print(f"Email: {profile.get('email', '-')}")
    print(f"Country: {profile.get('country', '-')}")
    print(f"City: {profile.get('city', '-')}")
    print(f"Gender: {profile.get('gender', '-')}")
    print(f"Birth date: {profile.get('birth_date', '-')}")


def edit_profile(username, profiles):
    """Edit profile fields for a logged-in user."""
    profile = profiles.get(username)
    if not profile:
        print("No profile data found for this user.")
        return

    print("\n--- Edit Profile ---")
    print("Press Enter to keep current value, or type a new one.")
    print("Tip: type 'exit' (or 'quit'/'q') to cancel editing.")

    try:
        email = read_text(f"Email [{profile.get('email', '')}]: ")
        if email:
            if not is_valid_email(email):
                print("Invalid email format. Example: name@example.com")
                return
            profile["email"] = email

        country = read_text(f"Country [{profile.get('country', '')}]: ")
        if country:
            profile["country"] = country

        city = read_text(f"City [{profile.get('city', '')}]: ")
        if city:
            profile["city"] = city

        gender = read_text(f"Gender (male/female) [{profile.get('gender', '')}]: ")
        if gender:
            normalized_gender = gender.lower()
            if normalized_gender not in ("male", "female"):
                print("Please enter 'male' or 'female'.")
                return
            profile["gender"] = normalized_gender

        birth_date = read_text(
            f"Birth date (YYYY-MM-DD) [{profile.get('birth_date', '')}]: "
        )
        if birth_date:
            if not is_valid_birth_date(birth_date):
                print("Invalid date. Use YYYY-MM-DD between 1900-01-01 and today.")
                return
            profile["birth_date"] = birth_date

        save_profiles(profiles)
        print("Profile updated successfully.")
    except CancelOperation:
        print("Profile editing canceled.")
    except OSError:
        print("Could not save profile changes. Please try again.")


def user_session_menu(username, profiles):
    """Menu shown after a user logs in."""
    while True:
        print("\n=== Profile Menu ===")
        print("1. Profile")
        print("2. Edit Profile")
        print("3. Quit")

        try:
            choice = read_text("Choose an option (1/2/3): ")
        except CancelOperation:
            print("Logged out.")
            return

        if choice == "1":
            show_profile(username, profiles)
        elif choice == "2":
            edit_profile(username, profiles)
        elif choice == "3":
            print("Logged out.")
            return
        else:
            print("Invalid choice. Try again.")


def main():
    configure_console()
    try:
        users = load_users()
        profiles = load_profiles()
    except DataFileError as error:
        print(f"Startup error: {error}")
        print("Fix the data file or restore from backup before continuing.")
        return

    print("Tip: type 'exit' (or 'quit'/'q') at text prompts to cancel.")

    while True:
        print("\n=== Menu ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        try:
            choice = read_text("Choose an option (1/2/3): ")
        except CancelOperation:
            print("Program ended.")
            break

        if choice == "1":
            register_user(users, profiles)
        elif choice == "2":
            login_user(users, profiles)
        elif choice == "3":
            print("Program ended.")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting.")
