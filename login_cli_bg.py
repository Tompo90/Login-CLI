import getpass
import logging
import sys
import time
from pathlib import Path

import database
import security
import validation

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None

USERS_FILE = Path(__file__).parent / "users.json"
PROFILES_FILE = Path(__file__).parent / "profiles.json"
DB_FILE = Path(__file__).parent / "app.db"
DEFAULT_ITERATIONS = 310_000
LEGACY_ITERATIONS = 100_000
MIN_ITERATIONS = 50_000
MAX_ITERATIONS = 2_000_000
CANCEL_WORDS = {"exit", "quit", "q"}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BACKOFF_SECONDS = (1, 2, 4, 8)
logger = logging.getLogger("login_cli")


class CancelOperation(Exception):
    """Raised when user requests to cancel current flow."""


class DataFileError(Exception):
    """Raised when persistent storage is invalid or unavailable."""


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


def load_users():
    """Load credential records from SQLite."""
    try:
        return database.load_users(DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def load_profiles():
    """Load user profile records from SQLite."""
    try:
        return database.load_profiles(DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def init_storage():
    """Initialize SQLite schema."""
    try:
        database.init_db(DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def maybe_migrate_json_data():
    """Import legacy JSON files once when the database is empty."""
    try:
        database.maybe_migrate_json_data(USERS_FILE, PROFILES_FILE, DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def save_user(username, user_record):
    """Persist one user record."""
    try:
        database.upsert_user(username, user_record, DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def delete_user(username):
    """Delete one user record."""
    try:
        database.delete_user(username, DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def save_profile(username, profile_record):
    """Persist one profile record."""
    try:
        database.upsert_profile(username, profile_record, DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def save_account(username, user_record, profile_record):
    """Persist user and profile atomically."""
    try:
        database.upsert_user_and_profile(username, user_record, profile_record, DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def delete_profile(username):
    """Delete one profile record."""
    try:
        database.delete_profile(username, DB_FILE)
    except database.DataStoreError as error:
        raise DataFileError(str(error)) from error


def hash_password(password, iterations=DEFAULT_ITERATIONS):
    """Return salt + password hash for secure storage."""
    return security.hash_password_record(
        password,
        iterations=iterations,
        min_iterations=MIN_ITERATIONS,
        max_iterations=MAX_ITERATIONS,
    )


def verify_password(password, salt_hex, stored_hash_hex, iterations=LEGACY_ITERATIONS):
    """Check whether an entered password matches the stored hash."""
    return security.verify_password_hash(
        password,
        salt_hex,
        stored_hash_hex,
        iterations=iterations,
        min_iterations=MIN_ITERATIONS,
        max_iterations=MAX_ITERATIONS,
    )


def normalize_username(username):
    """Return normalized username for comparisons."""
    return validation.normalize_username(username)


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
    # We allow case-insensitive lookup for convenience, but only if it resolves uniquely.
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
    if not sys.stdin.isatty():
        # Fallback to getpass so password input is not echoed.
        value = getpass.getpass(prompt)
        return value

    if msvcrt is None:
        value = read_password_posix(prompt)
        if value is not None:
            return value
        value = getpass.getpass(prompt)
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


def read_password_posix(prompt):
    """Read password in POSIX terminals and show '*' per character."""
    if termios is None or tty is None:
        return None

    try:
        fileno = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fileno)
    except (termios.error, ValueError, OSError):
        return None

    print(prompt, end="", flush=True)
    chars = []
    try:
        tty.setraw(fileno)
        while True:
            key = sys.stdin.read(1)

            if key in ("\r", "\n"):
                print()
                break

            if key == "\x03":
                raise KeyboardInterrupt

            if key in ("\x7f", "\b"):
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
                continue

            chars.append(key)
            print("*", end="", flush=True)
    finally:
        termios.tcsetattr(fileno, termios.TCSADRAIN, old_settings)

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
    return validation.is_valid_email(email)


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
    return validation.is_valid_birth_date(value)


def read_birth_date(prompt):
    """Read birth date in YYYY-MM-DD format."""
    while True:
        value = read_text(prompt)
        if is_valid_birth_date(value):
            return value
        print("Invalid date. Use YYYY-MM-DD between 1900-01-01 and today.")


def password_strength_errors(password):
    """Return a list of unmet password rules."""
    return validation.password_strength_errors(password)


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
        logger.warning("Login blocked due to ambiguous case-insensitive username match.")
        return None

    if not username:
        print("Invalid username or password.")
        logger.info("Failed login attempt for unknown username.")
        return None

    user_record = users[username]
    if not isinstance(user_record, dict):
        print("Account record is invalid. Please contact support.")
        logger.error("Invalid account record encountered for username '%s'.", username)
        return None

    # Preferred modern record format: salted PBKDF2 hash.
    if "salt" in user_record and "password_hash" in user_record:
        iterations = user_record.get("iterations", LEGACY_ITERATIONS)
        if verify_password(
            password,
            user_record["salt"],
            user_record["password_hash"],
            iterations=iterations,
        ):
            logger.info("User '%s' authenticated successfully.", username)
            return username
        print("Invalid username or password.")
        logger.info("Failed login attempt for existing username '%s'.", username)
        return None

    # Backward compatibility: migrate old plain-text records after first successful login.
    if "password" in user_record and user_record["password"] == password:
        users[username] = hash_password(password)
        try:
            save_user(username, users[username])
        except DataFileError:
            # Keep the old record in memory if migration cannot be persisted.
            users[username] = user_record
            print("Login failed: could not update account data. Please try again later.")
            logger.exception("Failed to persist legacy password migration for '%s'.", username)
            return None
        logger.info("Migrated legacy password record for user '%s'.", username)
        return username

    print("Invalid username or password.")
    logger.info("Failed login attempt for existing username '%s'.", username)
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
        name = read_non_empty("Enter name: ")
        surname = read_non_empty("Enter surname: ")
        email = read_email("Enter email: ")
        country = read_non_empty("Enter country: ")
        city = read_non_empty("Enter city: ")
        gender = read_gender("Enter gender (male/female): ")
        birth_date = read_birth_date("Enter birth date (YYYY-MM-DD): ")

        # Build records in memory first, then persist once.
        user_record = hash_password(password)
        profile_record = {
            "name": name,
            "surname": surname,
            "email": email,
            "country": country,
            "city": city,
            "gender": gender,
            "birth_date": birth_date,
        }

        users[username] = user_record
        profiles[username] = profile_record
        try:
            save_account(username, user_record, profile_record)
        except DataFileError:
            # Keep in-memory state aligned with DB state if persistence fails.
            users.pop(username, None)
            profiles.pop(username, None)
            print("Registration failed while saving data. No account was created.")
            logger.exception("Failed registration persistence for '%s'.", username)
            return

        print("Registration successful.")
        logger.info("Registered user '%s'.", username)
    except CancelOperation:
        print("Registration canceled. Returning to main menu.")


def login_user(users, profiles):
    """Log in existing user."""
    print("\n--- Login ---")
    try:
        for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
            username = authenticate_user(users)
            if username:
                print(f"Login successful. Welcome, {username}!")
                user_session_menu(username, profiles)
                return

            if attempt == MAX_LOGIN_ATTEMPTS:
                print("Too many failed login attempts. Returning to main menu.")
                return

            # Exponential backoff slows brute-force retries without locking the app forever.
            wait_seconds = LOGIN_BACKOFF_SECONDS[min(attempt - 1, len(LOGIN_BACKOFF_SECONDS) - 1)]
            print(f"Please wait {wait_seconds} second(s) before trying again.")
            time.sleep(wait_seconds)
    except CancelOperation:
        print("Login canceled. Returning to main menu.")


def show_profile(username, profiles):
    """Show profile details for a logged-in user."""
    if username not in profiles:
        print("No profile data found for this user.")
        return
    profile = profiles[username]
    if not isinstance(profile, dict):
        print("Profile data is invalid for this user.")
        return

    print(f"\nUsername: {username}")
    print(f"Name: {profile.get('name', '-')}")
    print(f"Surname: {profile.get('surname', '-')}")
    print(f"Email: {profile.get('email', '-')}")
    print(f"Country: {profile.get('country', '-')}")
    print(f"City: {profile.get('city', '-')}")
    print(f"Gender: {profile.get('gender', '-')}")
    print(f"Birth date: {profile.get('birth_date', '-')}")


def edit_profile(username, profiles):
    """Edit profile fields for a logged-in user."""
    if username not in profiles:
        print("No profile data found for this user.")
        return
    profile = profiles[username]
    if not isinstance(profile, dict):
        print("Profile data is invalid for this user.")
        return

    print("\n--- Edit Profile ---")
    print("Press Enter to keep current value, or type a new one.")
    print("Tip: type 'exit' (or 'quit'/'q') to cancel editing.")

    try:
        # Work on a copy to avoid partial updates when validation fails midway.
        updated_profile = profile.copy()

        name = read_text(f"Name [{profile.get('name', '')}]: ")
        if name:
            updated_profile["name"] = name

        surname = read_text(f"Surname [{profile.get('surname', '')}]: ")
        if surname:
            updated_profile["surname"] = surname

        email = read_text(f"Email [{profile.get('email', '')}]: ")
        if email:
            if not is_valid_email(email):
                print("Invalid email format. Example: name@example.com")
                return
            updated_profile["email"] = email

        country = read_text(f"Country [{profile.get('country', '')}]: ")
        if country:
            updated_profile["country"] = country

        city = read_text(f"City [{profile.get('city', '')}]: ")
        if city:
            updated_profile["city"] = city

        gender = read_text(f"Gender (male/female) [{profile.get('gender', '')}]: ")
        if gender:
            normalized_gender = gender.lower()
            if normalized_gender not in ("male", "female"):
                print("Please enter 'male' or 'female'.")
                return
            updated_profile["gender"] = normalized_gender

        birth_date = read_text(
            f"Birth date (YYYY-MM-DD) [{profile.get('birth_date', '')}]: "
        )
        if birth_date:
            if not is_valid_birth_date(birth_date):
                print("Invalid date. Use YYYY-MM-DD between 1900-01-01 and today.")
                return
            updated_profile["birth_date"] = birth_date

        profiles[username] = updated_profile
        try:
            save_profile(username, updated_profile)
        except DataFileError:
            profiles[username] = profile
            print("Could not save profile changes. Please try again.")
            logger.exception("Failed to save profile updates for '%s'.", username)
            return
        print("Profile updated successfully.")
        logger.info("Updated profile for user '%s'.", username)
    except CancelOperation:
        print("Profile editing canceled.")


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
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    configure_console()
    try:
        # Startup order matters:
        # 1) ensure schema exists
        # 2) import legacy JSON once (if DB is empty)
        # 3) load in-memory working sets
        init_storage()
        maybe_migrate_json_data()
        users = load_users()
        profiles = load_profiles()
    except DataFileError as error:
        print(f"Startup error: {error}")
        print("Fix the database/data files or restore from backup before continuing.")
        logger.exception("Startup failed.")
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
