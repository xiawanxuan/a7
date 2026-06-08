import os
import json
import uuid
import secrets
import hashlib
import string
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from crypto import AESCrypto


class ShareManager:
    SHARES_DIR_NAME = "shares"
    SHARE_INDEX_FILE = "shares_index.json"
    DEFAULT_EXPIRY_HOURS = 24

    def __init__(self, storage_dir: str = None):
        if storage_dir is None:
            storage_dir = str(Path.home() / ".file_crypto" / "shares")
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.shares_dir = self.storage_dir / self.SHARES_DIR_NAME
        self.shares_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.storage_dir / self.SHARE_INDEX_FILE
        self._index = self._load_index()

    def _load_index(self) -> Dict[str, Any]:
        if self.index_path.exists():
            try:
                with open(self.index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {"shares": {}}
        return {"shares": {}}

    def _save_index(self) -> None:
        import tempfile
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(self.storage_dir),
            suffix=".tmp"
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(self._index, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if os.name == "nt":
                try:
                    os.replace(temp_path, str(self.index_path))
                except OSError:
                    if os.path.exists(str(self.index_path)):
                        os.unlink(str(self.index_path))
                    os.rename(temp_path, str(self.index_path))
            else:
                os.replace(temp_path, str(self.index_path))
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

    def _generate_share_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def _generate_share_password(self, length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _get_share_file_path(self, share_id: str) -> Path:
        return self.shares_dir / f"{share_id}.enc"

    def create_share(
        self,
        encrypted_file_path: str,
        share_password: Optional[str] = None,
        expiry_hours: int = DEFAULT_EXPIRY_HOURS,
        description: str = "",
        original_password: str = "",
    ) -> Dict[str, Any]:
        enc_path = Path(encrypted_file_path)
        if not enc_path.exists():
            raise ValueError("加密文件不存在")

        share_id = self._generate_share_id()

        if share_password is None:
            share_password = self._generate_share_password()

        share_crypto = AESCrypto(share_password)
        share_file = self._get_share_file_path(share_id)

        with open(encrypted_file_path, "rb") as f:
            original_data = f.read()

        share_data = share_crypto.encrypt_data(original_data)

        with open(share_file, "wb") as f:
            f.write(share_data)

        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=expiry_hours)

        file_hash = hashlib.sha256(original_data).hexdigest()

        share_info = {
            "share_id": share_id,
            "original_file": str(enc_path.resolve()),
            "original_name": enc_path.name,
            "original_size": len(original_data),
            "share_file": str(share_file),
            "share_size": len(share_data),
            "description": description,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expiry_hours": expiry_hours,
            "file_hash": file_hash,
            "share_password_hash": hashlib.sha256(share_password.encode()).hexdigest(),
            "download_count": 0,
            "max_downloads": 0,
            "is_active": True,
        }

        self._index["shares"][share_id] = share_info
        self._save_index()

        return {
            "share_id": share_id,
            "share_password": share_password,
            "share_file": str(share_file),
            "original_name": enc_path.name,
            "original_size": enc_path.stat().st_size,
            "expires_at": expires_at.isoformat(),
            "expiry_hours": expiry_hours,
            "description": description,
        }

    def get_share_info(self, share_id: str) -> Optional[Dict[str, Any]]:
        if share_id not in self._index["shares"]:
            return None
        share = self._index["shares"][share_id]
        if self._is_expired(share):
            share["is_active"] = False
            self._save_index()
        return dict(share)

    def _is_expired(self, share_info: Dict[str, Any]) -> bool:
        if not share_info.get("is_active", True):
            return True
        expires_at = datetime.fromisoformat(share_info["expires_at"])
        return datetime.now() > expires_at

    def is_share_valid(self, share_id: str) -> bool:
        share = self.get_share_info(share_id)
        if share is None:
            return False
        return share["is_active"] and not self._is_expired(share)

    def verify_share_password(self, share_id: str, password: str) -> bool:
        share = self.get_share_info(share_id)
        if share is None:
            return False
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == share["share_password_hash"]

    def decrypt_share(
        self,
        share_id: str,
        share_password: str,
        output_path: str,
    ) -> Optional[str]:
        share = self.get_share_info(share_id)
        if share is None:
            return None

        if not share["is_active"] or self._is_expired(share):
            return None

        if not self.verify_share_password(share_id, share_password):
            return None

        share_file = Path(share["share_file"])
        if not share_file.exists():
            return None

        share_crypto = AESCrypto(share_password)

        try:
            with open(share_file, "rb") as f:
                share_data = f.read()

            original_data = share_crypto.decrypt_data(share_data)

            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(original_data)

            share["download_count"] = share.get("download_count", 0) + 1
            if share.get("max_downloads", 0) > 0 and share["download_count"] >= share["max_downloads"]:
                share["is_active"] = False
            self._save_index()

            return output_path
        except Exception:
            return None

    def list_shares(self, include_expired: bool = False) -> List[Dict[str, Any]]:
        shares = []
        for share_id, share in self._index["shares"].items():
            if not include_expired and (self._is_expired(share) or not share.get("is_active", True)):
                continue
            shares.append(dict(share))
        shares.sort(key=lambda x: x["created_at"], reverse=True)
        return shares

    def revoke_share(self, share_id: str) -> bool:
        if share_id not in self._index["shares"]:
            return False

        share = self._index["shares"][share_id]
        share["is_active"] = False
        self._save_index()

        share_file = Path(share["share_file"])
        if share_file.exists():
            try:
                share_file.unlink()
            except OSError:
                pass

        return True

    def delete_share(self, share_id: str) -> bool:
        if share_id not in self._index["shares"]:
            return False

        share = self._index["shares"][share_id]
        share_file = Path(share["share_file"])
        if share_file.exists():
            try:
                share_file.unlink()
            except OSError:
                pass

        del self._index["shares"][share_id]
        self._save_index()
        return True

    def cleanup_expired(self) -> int:
        expired_ids = []
        for share_id, share in self._index["shares"].items():
            if self._is_expired(share) or not share.get("is_active", True):
                expired_ids.append(share_id)

        for share_id in expired_ids:
            self.delete_share(share_id)

        return len(expired_ids)

    def get_share_link(self, share_id: str) -> str:
        return f"file-crypto://share/{share_id}"

    def export_share_file(self, share_id: str, export_path: str) -> bool:
        share = self.get_share_info(share_id)
        if share is None:
            return False

        share_file = Path(share["share_file"])
        if not share_file.exists():
            return False

        export_file = Path(export_path)
        export_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.copy2(str(share_file), str(export_file))
            return True
        except Exception:
            return False
