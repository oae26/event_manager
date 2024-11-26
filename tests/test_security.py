import pytest
from app.utils.security import hash_password, verify_password

def test_hash_password():
    """Test that hashing a password returns a valid bcrypt hashed string."""
    password = "secure_password"
    hashed = hash_password(password)
    assert hashed is not None, "Hashing should not return None"
    assert isinstance(hashed, str), "Hash should be a string"
    assert hashed.startswith('$2b$'), "Hash should start with bcrypt prefix '$2b$'"

@pytest.mark.parametrize("rounds", [4, 10, 12])
def test_hash_password_with_different_rounds(rounds):
    """Test hashing with different cost factors."""
    password = "secure_password"
    hashed = hash_password(password, rounds)
    assert hashed.startswith('$2b$'), "Hash should start with bcrypt prefix '$2b$'"
    assert len(hashed) > 0, "Hash should not be empty"

def test_verify_password_correct():
    """Test that verifying the correct password works."""
    password = "secure_password"
    hashed = hash_password(password)
    assert verify_password(password, hashed), "Correct password should return True"

def test_verify_password_incorrect():
    """Test that verifying an incorrect password fails."""
    password = "secure_password"
    hashed = hash_password(password)
    wrong_password = "incorrect_password"
    assert not verify_password(wrong_password, hashed), "Incorrect password should return False"

def test_verify_password_invalid_hash():
    """Test that verifying a password against an invalid hash raises an error."""
    invalid_hash = "invalid_hash_format"
    with pytest.raises(ValueError, match="Invalid bcrypt hash format"):
        verify_password("secure_password", invalid_hash)

@pytest.mark.parametrize("password", [
    "",              # Empty password
    "short",         # Too short
    "a" * 65         # Too long
])
def test_hash_password_invalid_length(password):
    """Test that hashing passwords with invalid lengths raises an error."""
    with pytest.raises(ValueError, match="Password must be at least|must not exceed"):
        hash_password(password)

@pytest.mark.parametrize("password", [
    " ",             # Single whitespace
    "short",         # Short password
    "differentpass", # Completely different password
])
def test_verify_password_edge_cases(password):
    """Test verifying edge case passwords against valid hashes."""
    correct_password = "secure_password"
    hashed = hash_password(correct_password)
    assert not verify_password(password, hashed), f"Password '{password}' should not match the hash"

def test_hash_password_internal_error(monkeypatch):
    """Test proper error handling when an internal bcrypt error occurs."""
    def mock_gensalt(rounds):
        raise RuntimeError("Simulated internal error")

    # Correctly patch bcrypt.gensalt
    monkeypatch.setattr("app.utils.security.bcrypt.gensalt", mock_gensalt)
    
    with pytest.raises(ValueError, match="Failed to hash password"):
        hash_password("test_password")

@pytest.mark.parametrize("password, hash_value", [
    ("password", None),
    ("password", 12345),
    ("password", ""),
    ("password", {}),
])
def test_verify_password_invalid_inputs(password, hash_value):
    """Test that invalid inputs for password verification raise errors."""
    with pytest.raises(ValueError, match="Invalid bcrypt hash format"):
        verify_password(password, hash_value)
@pytest.mark.parametrize("invalid_input", [
    None,
    12345,
    [],
    {},
    False
])
def test_hash_password_invalid_input(invalid_input):
    """Test that invalid inputs for password hashing raise errors."""
    with pytest.raises(ValueError, match="Password must be a string"):
        hash_password(invalid_input)

@pytest.mark.parametrize("password, hash_value", [
    ("password", None),
    ("password", 12345),
    ("password", ""),
    ("password", {}),
])
def test_verify_password_invalid_inputs(password, hash_value):
    """Test that invalid inputs for password verification raise errors."""
    with pytest.raises(ValueError, match="Invalid bcrypt hash format"):
        verify_password(password, hash_value)

def test_hash_password_and_verify_consistency():
    """Ensure hashed passwords can be verified consistently."""
    password = "secure_password"
    hashed = hash_password(password)
    assert verify_password(password, hashed), "Password should match its hash"
    assert not verify_password("wrong_password", hashed), "Wrong password should not match the hash"