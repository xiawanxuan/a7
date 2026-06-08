import hashlib
import os
import json
from pathlib import Path


class PasswordManager:
    SALT_SIZE = 32
    HASH_ITERATIONS = 100000

    def __init__(self, storage_path: str = None):
        if storage_path is None:
            storage_path = str(Path.home() / ".file_crypto" / "passwords.json")
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._passwords = self._load_passwords()

    def _load_passwords(self) -> dict:
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_passwords(self) -> None:
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self._passwords, f, indent=2)

    def _hash_password(self, password: str, salt: bytes) -> str:
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.HASH_ITERATIONS,
        )
        return dk.hex()

    def set_password(self, file_id: str, password: str) -> None:
        salt = os.urandom(self.SALT_SIZE)
        password_hash = self._hash_password(password, salt)
        self._passwords[file_id] = {
            "salt": salt.hex(),
            "hash": password_hash,
            "iterations": self.HASH_ITERATIONS,
        }
        self._save_passwords()

    def verify_password(self, file_id: str, password: str) -> bool:
        if file_id not in self._passwords:
            return False
        stored = self._passwords[file_id]
        salt = bytes.fromhex(stored["salt"])
        stored_hash = stored["hash"]
        computed_hash = self._hash_password(password, salt)
        return stored_hash == computed_hash

    def has_password(self, file_id: str) -> bool:
        return file_id in self._passwords

    def remove_password(self, file_id: str) -> None:
        if file_id in self._passwords:
            del self._passwords[file_id]
            self._save_passwords()

    @staticmethod
    def generate_file_id(file_path: str) -> str:
        path = Path(file_path).resolve()
        return hashlib.sha256(str(path).encode("utf-8")).hexdigest()
