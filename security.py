import binascii
import hashlib
import hmac
import os


def hash_password_record(password, iterations, min_iterations, max_iterations):
    """Create a PBKDF2 password record with salt/hash/iterations."""
    if not isinstance(iterations, int) or not (min_iterations <= iterations <= max_iterations):
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


def verify_password_hash(
    password,
    salt_hex,
    stored_hash_hex,
    iterations,
    min_iterations,
    max_iterations,
):
    """Validate password against a stored PBKDF2 hash record."""
    try:
        if not isinstance(password, str):
            return False
        if not isinstance(salt_hex, str) or not isinstance(stored_hash_hex, str):
            return False
        if not isinstance(iterations, int):
            return False
        if not (min_iterations <= iterations <= max_iterations):
            return False
        salt = binascii.unhexlify(salt_hex.encode("utf-8"))
        stored_hash = binascii.unhexlify(stored_hash_hex.encode("utf-8"))
    except (AttributeError, ValueError, TypeError, binascii.Error):
        return False

    entered_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(entered_hash, stored_hash)
