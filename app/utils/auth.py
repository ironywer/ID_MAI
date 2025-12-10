import json
import json
import os
from pathlib import Path
from threading import Lock
from typing import Dict, Optional, List

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


def hash_password(password: str) -> str:
    """Hash a password using Streebog (GOST R 34.11-2012)."""
    hasher = streebog.new(64)
    hasher.update(password.encode("utf-8"))
    return hasher.hexdigest()


store = UserStore()

__all__ = ["hash_password", "store", "UserStore"]
