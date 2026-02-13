# Login CLI (Python)

A simple, secure command-line login and profile management application built with Python.

## Features

- User registration and login
- Password hashing with PBKDF2-HMAC-SHA256 and per-user salt
- Backward-compatible support for legacy password records
- Profile viewing and profile editing after login
- Input validation for:
  - Email format
  - Gender (`male` / `female`)
  - Birth date (`YYYY-MM-DD`, valid range)
- Safe JSON writes using temporary-file replace
- Basic automated tests

## Project Structure

```text
.
|- login_cli_bg.py              # Main application
|- users.json                   # Credential storage (hashed)
|- profiles.json                # Profile storage
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

- `users.json` stores:
  - `salt` (hex)
  - `password_hash` (hex)
  - `iterations` (PBKDF2 rounds)
- `profiles.json` stores:
  - `email`, `country`, `city`, `gender`, `birth_date`

## Security Notes

- Passwords are never stored in plain text.
- Password comparison uses `hmac.compare_digest`.
- Iteration count is validated to avoid malformed hash records.

## Known Limitations

- Data is file-based JSON (not a database).
- No multi-user locking for concurrent writes.
- Interactive CLI is focused on Windows terminal behavior.

## License

Free to use
