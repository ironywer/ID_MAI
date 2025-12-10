import json
import json
import os
from pathlib import Path
from threading import Lock
from typing import Dict, Optional, List
import base64
import hmac
import hashlib
import struct
import time
import os

from app.crypto import streebog


DATA_DIR = Path("app/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"


class UserStore:
    """Very small JSON-backed user storage for demo purposes."""

    def __init__(self, path: Path = USERS_FILE) -> None:
        self.path = path
        self.lock = Lock()
        if not self.path.exists():
            self._write({})

    def _read(self) -> Dict[str, Dict[str, str]]:
        with self.lock:
            if not self.path.exists():
                return {}
            try:
                with self.path.open("r", encoding="utf-8") as fh:
                    return json.load(fh)
            except json.JSONDecodeError:
                # Corrupted file: start fresh to avoid crashes.
                return {}

    def _write(self, data: Dict[str, Dict[str, str]]) -> None:
        with self.lock:
            with self.path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)

    def create_user(self, username: str, password: str, role: str = "user", email: Optional[str] = None) -> bool:
        users = self._read()
        if username in users:
            return False
        users[username] = {
            "password": hash_password(password),
            "role": role,
            "email": email,
            "totp_secret": None,
        }
        self._write(users)
        return True

    def verify_user(self, username: str, password: str) -> bool:
        users = self._read()
        entry = users.get(username)
        if not entry:
            return False
        return entry.get("password") == hash_password(password)

    def get_user(self, username: str) -> Optional[Dict[str, str]]:
        users = self._read()
        return users.get(username)

    def get_user_by_email(self, email: str) -> Optional[Dict[str, str]]:
        data = self._read()
        for username, info in data.items():
            if info.get("email") == email:
                return {"username": username, **info}
        return None

    def list_users(self) -> List[Dict[str, str]]:
        data = self._read()
        return [
            {
                "username": user,
                "password": info.get("password"),
                "role": info.get("role", "user"),
                "email": info.get("email"),
            }
            for user, info in data.items()
        ]

    def delete_user(self, username: str) -> bool:
        users = self._read()
        if username not in users:
            return False
        users.pop(username)
        self._write(users)
        return True

    def set_totp_secret(self, username: str, secret: str) -> bool:
        users = self._read()
        if username not in users:
            return False
        users[username]["totp_secret"] = secret
        self._write(users)
        return True

    def get_totp_secret(self, username: str) -> Optional[str]:
        users = self._read()
        entry = users.get(username)
        if not entry:
            return None
        return entry.get("totp_secret")


def hash_password(password: str) -> str:
    """Hash a password using Streebog (GOST R 34.11-2012)."""
    hasher = streebog.new(64)
    hasher.update(password.encode("utf-8"))
    return hasher.hexdigest()


def generate_totp_secret(length: int = 20) -> str:
    """Generate a base32 secret without padding for TOTP apps."""
    return base64.b32encode(os.urandom(length)).decode("utf-8").rstrip("=")


def _totp_counter(timestep: int = 30) -> int:
    return int(time.time()) // timestep


def verify_totp(secret_b32: str, code: str, timestep: int = 30, digits: int = 6, window: int = 1) -> bool:
    """Verify TOTP code with small time window tolerance."""
    if not secret_b32 or not code or not code.isdigit():
        return False
    try:
        key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8), casefold=True)
    except Exception:
        return False
    counter = _totp_counter(timestep)
    for offset in range(-window, window + 1):
        c = counter + offset
        msg = struct.pack(">Q", c)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 0x0F
        binary = ((h[o] & 0x7F) << 24) | ((h[o + 1] & 0xFF) << 16) | ((h[o + 2] & 0xFF) << 8) | (h[o + 3] & 0xFF)
        totp = binary % (10 ** digits)
        if f"{totp:0{digits}d}" == code:
            return True
    return False


store = UserStore()

__all__ = ["hash_password", "store", "UserStore", "generate_totp_secret", "verify_totp"]
