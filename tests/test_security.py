import pytest
from app.api.auth import hash_password, verify_password

def test_password_hashing():
    raw = "SuperSecret123!"
    hashed, salt = hash_password(raw)

    assert hashed != raw
    assert len(salt) > 10
    assert verify_password(raw, hashed, salt) is True
    assert verify_password("WrongPassword", hashed, salt) is False
