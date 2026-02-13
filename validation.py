import datetime
import re


def normalize_username(username):
    """Normalize username for case-insensitive comparisons."""
    return username.strip().casefold()


def is_valid_email(email):
    """Basic email format validation."""
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email))


def is_valid_birth_date(value):
    """Validate birth date format and sensible date bounds."""
    try:
        birth_date = datetime.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return False

    today = datetime.date.today()
    return datetime.date(1900, 1, 1) <= birth_date <= today


def password_strength_errors(password):
    """Return unmet password requirements."""
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
