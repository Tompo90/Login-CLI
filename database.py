import json
import sqlite3
from pathlib import Path


DEFAULT_DB_FILE = Path(__file__).parent / "app.db"


class DataStoreError(Exception):
    """Raised when persistent storage cannot be initialized or read."""


def _connect(db_file):
    try:
        conn = sqlite3.connect(db_file)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except sqlite3.Error as error:
        raise DataStoreError(f"Could not open database '{Path(db_file).name}': {error}") from error


def _profiles_has_users_fk(conn):
    rows = conn.execute("PRAGMA foreign_key_list(profiles)").fetchall()
    for row in rows:
        # pragma columns: id, seq, table, from, to, on_update, on_delete, match
        if row[2] == "users" and row[3] == "username" and row[4] == "username":
            return True
    return False


def _rebuild_profiles_with_fk(conn):
    conn.execute("ALTER TABLE profiles RENAME TO profiles_old")
    conn.execute(
        """
        CREATE TABLE profiles (
            username TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            surname TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            gender TEXT NOT NULL DEFAULT '',
            birth_date TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        INSERT INTO profiles (username, name, surname, email, country, city, gender, birth_date)
        SELECT p.username, p.name, p.surname, p.email, p.country, p.city, p.gender, p.birth_date
        FROM profiles_old p
        WHERE EXISTS (SELECT 1 FROM users u WHERE u.username = p.username)
        """
    )
    conn.execute("DROP TABLE profiles_old")


def init_db(db_file=DEFAULT_DB_FILE):
    """Create database schema and apply lightweight migrations."""
    try:
        with _connect(db_file) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt TEXT,
                    password_hash TEXT,
                    iterations INTEGER CHECK (iterations IS NULL OR iterations > 0),
                    legacy_password TEXT,
                    CHECK (
                        (salt IS NOT NULL AND password_hash IS NOT NULL)
                        OR legacy_password IS NOT NULL
                    )
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS profiles (
                    username TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    surname TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    country TEXT NOT NULL DEFAULT '',
                    city TEXT NOT NULL DEFAULT '',
                    gender TEXT NOT NULL DEFAULT '',
                    birth_date TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
                """
            )
            users_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "iterations" not in users_columns:
                conn.execute("ALTER TABLE users ADD COLUMN iterations INTEGER")
            if "legacy_password" not in users_columns:
                conn.execute("ALTER TABLE users ADD COLUMN legacy_password TEXT")

            existing_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(profiles)").fetchall()
            }
            required_profile_columns = (
                "name",
                "surname",
                "email",
                "country",
                "city",
                "gender",
                "birth_date",
            )
            for column_name in required_profile_columns:
                if column_name not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE profiles ADD COLUMN {column_name} TEXT NOT NULL DEFAULT ''"
                    )

            if not _profiles_has_users_fk(conn):
                _rebuild_profiles_with_fk(conn)
            conn.commit()
    except sqlite3.Error as error:
        raise DataStoreError(
            f"Could not initialize database '{Path(db_file).name}': {error}"
        ) from error


def _load_json(path):
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        raise DataStoreError(f"Could not read '{path.name}': {error}") from error
    if not isinstance(data, dict):
        raise DataStoreError(f"Invalid format in '{path.name}': root JSON value must be an object.")
    return data


def maybe_migrate_json_data(users_file, profiles_file, db_file=DEFAULT_DB_FILE):
    """Import legacy JSON files once when both tables are empty."""
    try:
        with _connect(db_file) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            profile_count = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
    except sqlite3.Error as error:
        raise DataStoreError(f"Could not read database '{Path(db_file).name}': {error}") from error

    if user_count or profile_count:
        return

    users = _load_json(users_file)
    profiles = _load_json(profiles_file)
    if not users and not profiles:
        return

    try:
        with _connect(db_file) as conn:
            for username, user_record in users.items():
                if not isinstance(user_record, dict):
                    raise DataStoreError("Could not migrate users: invalid account record.")
                conn.execute(
                    """
                    INSERT INTO users (username, salt, password_hash, iterations, legacy_password)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        salt=excluded.salt,
                        password_hash=excluded.password_hash,
                        iterations=excluded.iterations,
                        legacy_password=excluded.legacy_password
                    """,
                    (
                        username,
                        user_record.get("salt"),
                        user_record.get("password_hash"),
                        user_record.get("iterations"),
                        user_record.get("password"),
                    ),
                )

            for username, profile in profiles.items():
                if not isinstance(profile, dict):
                    raise DataStoreError("Could not migrate profiles: invalid profile record.")
                conn.execute(
                    """
                    INSERT INTO profiles
                    (username, name, surname, email, country, city, gender, birth_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        name=excluded.name,
                        surname=excluded.surname,
                        email=excluded.email,
                        country=excluded.country,
                        city=excluded.city,
                        gender=excluded.gender,
                        birth_date=excluded.birth_date
                    """,
                    (
                        username,
                        profile.get("name") or "",
                        profile.get("surname") or "",
                        profile.get("email") or "",
                        profile.get("country") or "",
                        profile.get("city") or "",
                        profile.get("gender") or "",
                        profile.get("birth_date") or "",
                    ),
                )
            conn.commit()
    except sqlite3.Error as error:
        raise DataStoreError(
            f"Could not migrate JSON data into '{Path(db_file).name}': {error}"
        ) from error


def load_users(db_file=DEFAULT_DB_FILE):
    try:
        with _connect(db_file) as conn:
            rows = conn.execute(
                "SELECT username, salt, password_hash, iterations, legacy_password FROM users"
            ).fetchall()
    except sqlite3.Error as error:
        raise DataStoreError(f"Could not load users from '{Path(db_file).name}': {error}") from error

    users = {}
    for username, salt, password_hash, iterations, legacy_password in rows:
        if salt is not None and password_hash is not None:
            record = {"salt": salt, "password_hash": password_hash}
            if iterations is not None:
                record["iterations"] = iterations
            users[username] = record
        elif legacy_password is not None:
            users[username] = {"password": legacy_password}
        else:
            users[username] = {}
    return users


def load_profiles(db_file=DEFAULT_DB_FILE):
    try:
        with _connect(db_file) as conn:
            rows = conn.execute(
                "SELECT username, name, surname, email, country, city, gender, birth_date FROM profiles"
            ).fetchall()
    except sqlite3.Error as error:
        raise DataStoreError(
            f"Could not load profiles from '{Path(db_file).name}': {error}"
        ) from error

    return {
        username: {
            "name": name or "",
            "surname": surname or "",
            "email": email or "",
            "country": country or "",
            "city": city or "",
            "gender": gender or "",
            "birth_date": birth_date or "",
        }
        for username, name, surname, email, country, city, gender, birth_date in rows
    }


def upsert_user(username, user_record, db_file=DEFAULT_DB_FILE):
    if not isinstance(user_record, dict):
        raise OSError("Could not save user: invalid account record.")

    try:
        with _connect(db_file) as conn:
            conn.execute(
                """
                INSERT INTO users (username, salt, password_hash, iterations, legacy_password)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    salt=excluded.salt,
                    password_hash=excluded.password_hash,
                    iterations=excluded.iterations,
                    legacy_password=excluded.legacy_password
                """,
                (
                    username,
                    user_record.get("salt"),
                    user_record.get("password_hash"),
                    user_record.get("iterations"),
                    user_record.get("password"),
                ),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise OSError(f"Could not save user to '{Path(db_file).name}': {error}") from error


def delete_user(username, db_file=DEFAULT_DB_FILE):
    try:
        with _connect(db_file) as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
    except sqlite3.Error as error:
        raise OSError(f"Could not delete user from '{Path(db_file).name}': {error}") from error


def upsert_profile(username, profile_record, db_file=DEFAULT_DB_FILE):
    if not isinstance(profile_record, dict):
        raise OSError("Could not save profile: invalid profile record.")

    try:
        with _connect(db_file) as conn:
            conn.execute(
                """
                INSERT INTO profiles
                (username, name, surname, email, country, city, gender, birth_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    name=excluded.name,
                    surname=excluded.surname,
                    email=excluded.email,
                    country=excluded.country,
                    city=excluded.city,
                    gender=excluded.gender,
                    birth_date=excluded.birth_date
                """,
                (
                    username,
                    profile_record.get("name") or "",
                    profile_record.get("surname") or "",
                    profile_record.get("email") or "",
                    profile_record.get("country") or "",
                    profile_record.get("city") or "",
                    profile_record.get("gender") or "",
                    profile_record.get("birth_date") or "",
                ),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise OSError(
            f"Could not save profile to '{Path(db_file).name}': {error}"
        ) from error


def upsert_user_and_profile(username, user_record, profile_record, db_file=DEFAULT_DB_FILE):
    if not isinstance(user_record, dict):
        raise OSError("Could not save account: invalid account record.")
    if not isinstance(profile_record, dict):
        raise OSError("Could not save account: invalid profile record.")

    try:
        with _connect(db_file) as conn:
            conn.execute(
                """
                INSERT INTO users (username, salt, password_hash, iterations, legacy_password)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    salt=excluded.salt,
                    password_hash=excluded.password_hash,
                    iterations=excluded.iterations,
                    legacy_password=excluded.legacy_password
                """,
                (
                    username,
                    user_record.get("salt"),
                    user_record.get("password_hash"),
                    user_record.get("iterations"),
                    user_record.get("password"),
                ),
            )
            conn.execute(
                """
                INSERT INTO profiles
                (username, name, surname, email, country, city, gender, birth_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    name=excluded.name,
                    surname=excluded.surname,
                    email=excluded.email,
                    country=excluded.country,
                    city=excluded.city,
                    gender=excluded.gender,
                    birth_date=excluded.birth_date
                """,
                (
                    username,
                    profile_record.get("name") or "",
                    profile_record.get("surname") or "",
                    profile_record.get("email") or "",
                    profile_record.get("country") or "",
                    profile_record.get("city") or "",
                    profile_record.get("gender") or "",
                    profile_record.get("birth_date") or "",
                ),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise OSError(f"Could not save account to '{Path(db_file).name}': {error}") from error


def delete_profile(username, db_file=DEFAULT_DB_FILE):
    try:
        with _connect(db_file) as conn:
            conn.execute("DELETE FROM profiles WHERE username = ?", (username,))
            conn.commit()
    except sqlite3.Error as error:
        raise OSError(
            f"Could not delete profile from '{Path(db_file).name}': {error}"
        ) from error
