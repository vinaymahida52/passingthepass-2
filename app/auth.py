import secrets
import time
from pathlib import Path

import jwt
import pyotp
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

JWT_SECRET_PATH = Path(__file__).resolve().parent.parent / "data" / "jwt.key"
JWT_ALGO = "HS256"
SESSION_COOKIE = "ptp_session"
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


def _load_or_create_jwt_secret() -> str:
    JWT_SECRET_PATH.parent.mkdir(exist_ok=True)
    if JWT_SECRET_PATH.exists():
        return JWT_SECRET_PATH.read_text()
    secret = secrets.token_hex(32)
    JWT_SECRET_PATH.write_text(secret)
    return secret


JWT_SECRET = _load_or_create_jwt_secret()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_token(user_id: int, team_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "team_id": team_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="PassingThePass")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def new_invite_code() -> str:
    return secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8].upper()
