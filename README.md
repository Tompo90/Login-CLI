# Login CLI (Python)

A simple, secure command-line login and profile management application built with Python.

## Features

- User registration and login
- Password hashing with PBKDF2-HMAC-SHA256 and per-user salt
- Backward-compatible support for legacy password records
- Login retry backoff and max-attempt protection
- Profile viewing and profile editing after login
- Input validation for:
  - Email format
  - Gender (`male` / `female`)
  - Birth date (`YYYY-MM-DD`, valid range)
- SQLite database storage (`app.db`)
- Automatic one-time import from legacy JSON files (`users.json`, `profiles.json`)
- Basic automated tests

## Project Structure

```text
.
|- login_cli_bg.py              # Main application
|- app.db                       # SQLite database (users + profiles)
|- users.json                   # Optional legacy import source
|- profiles.json                # Optional legacy import source
|- tests/
|  |- test_login_cli_bg.py      # Unit tests
|- pytest.ini                   # Pytest configuration
```

## Requirements

- Python 3.10+ (project currently runs on Python 3.14)
- `pytest` (for running tests)

## Setup

```powershell
git clone <your-repo-url>
cd <your-repo-folder>
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install pytest
```

## Run the App

```powershell
python login_cli_bg.py
```

## Run Tests

```powershell
python -m pytest -v
```

## How Data Is Stored

- `app.db` contains:
  - `users` table:
  - `salt` (hex)
  - `password_hash` (hex)
  - `iterations` (PBKDF2 rounds)
  - `profiles` table:
  - `email`, `country`, `city`, `gender`, `birth_date`
- Legacy `users.json` / `profiles.json` are auto-imported once if the database is empty.

## Security Notes

- Passwords are never stored in plain text.
- Password prompts use hidden input in both Windows and fallback terminals.
- Password comparison uses `hmac.compare_digest`.
- Iteration count is validated to avoid malformed hash records.

## Known Limitations

- Single local SQLite file (not a remote multi-user server).
- Interactive CLI is focused on Windows terminal behavior.

## License

Free to use
