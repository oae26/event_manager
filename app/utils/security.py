import secrets
import bcrypt
from logging import getLogger

# Set up logging
logger = getLogger(__name__)

def validate_password_length(password: str):
    """
    Validates the length of a password.

    Args:
        password (str): The plain text password to validate.

    Raises:
        ValueError: If the password does not meet length requirements.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 64:
        raise ValueError("Password must not exceed 64 characters.")

def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hashes a password using bcrypt with a specified cost factor.

    Args:
        password (str): The plain text password to hash.
        rounds (int): The cost factor that determines the computational cost of hashing.

    Returns:
        str: The hashed password.

    Raises:
        ValueError: If hashing the password fails.
    """
    try:
        validate_password_length(password)  # Enforce length validation before hashing
        salt = bcrypt.gensalt(rounds=rounds)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    except ValueError as e:
        logger.error("Password validation failed: %s", e)
        raise ValueError(str(e)) from e  # Keep original message
    except Exception as e:
        logger.error("Failed to hash password: %s", e)
        raise ValueError("Failed to hash password") from e

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against a hashed password.

    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The bcrypt hashed password.

    Returns:
        bool: True if the password is correct, False otherwise.

    Raises:
        ValueError: If the hashed password format is incorrect or the function fails to verify.
    """
    try:
        if not isinstance(plain_password, str):
            raise ValueError("Password must be a string.")
        if not isinstance(hashed_password, str) or not hashed_password.startswith("$2b$"):
            raise ValueError("Invalid bcrypt hash format.")
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError as e:
        raise e  # Preserve error messages for tests
    except Exception as e:
        logger.error("Error verifying password: %s", e)
        raise ValueError("Authentication process encountered an unexpected error") from e

def generate_verification_token():
    """
    Generates a secure URL-safe verification token.

    Returns:
        str: A 16-byte URL-safe token.
    """
    return secrets.token_urlsafe(16)