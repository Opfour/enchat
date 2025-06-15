import os
from .constants import CONF_FILE, DEFAULT_NTFY, KEYRING_AVAILABLE

if KEYRING_AVAILABLE:
    import keyring

def save_passphrase_keychain(room: str, secret: str):
    """Saves a passphrase to the system keychain."""
    if KEYRING_AVAILABLE:
        try:
            keyring.set_password("enchat", f"room_{room}", secret)
        except Exception:
            pass

def load_passphrase_keychain(room: str) -> str:
    """Loads a passphrase from the system keychain."""
    if KEYRING_AVAILABLE:
        try:
            return keyring.get_password("enchat", f"room_{room}") or ""
        except Exception:
            pass
    return ""

def save_conf(room: str, nick: str, secret: str, server: str):
    """Saves the configuration to a file."""
    with open(CONF_FILE, "w", encoding="utf-8") as f:
        f.write(f"{room}\n{nick}\n{secret}\n{server}\n")
    try:
        os.chmod(CONF_FILE, 0o600)
    except Exception:
        pass

def load_conf():
    """Loads the configuration from a file."""
    if not os.path.exists(CONF_FILE):
        return None, None, None, None
    try:
        with open(CONF_FILE, encoding="utf-8") as f:
            room, nick, secret, *rest = [l.strip() for l in f.readlines()]
        server = rest[0] if rest else DEFAULT_NTFY
        if not secret:
            secret = load_passphrase_keychain(room)
        return room, nick, secret, server
    except Exception:
        return None, None, None, None
