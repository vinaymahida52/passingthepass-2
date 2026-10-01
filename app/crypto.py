from pathlib import Path
from cryptography.fernet import Fernet

KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "secret.key"


def _load_or_create_key() -> bytes:
    KEY_PATH.parent.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> bytes:
    return _fernet.encrypt(plaintext.encode("utf-8"))


def decrypt(token: bytes) -> str:
    return _fernet.decrypt(token).decode("utf-8")
