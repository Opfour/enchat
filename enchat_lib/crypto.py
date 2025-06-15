import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def gen_key(pw: str) -> bytes:
    """Generates a key from a password using PBKDF2HMAC."""
    salt = hashlib.sha256(b"enchat_v3_static_salt").digest()[:16]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def encrypt(m: str, f: Fernet) -> str:
    """Encrypts a message."""
    return f.encrypt(m.encode()).decode()

def decrypt(tok: str, f: Fernet) -> str:
    """Decrypts a message, returns empty string on failure."""
    try:
        return f.decrypt(tok.encode()).decode()
    except InvalidToken:
        return ""
