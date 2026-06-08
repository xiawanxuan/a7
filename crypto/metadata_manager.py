import json
import os
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any


class MetadataManager:
    METADATA_EXT = ".meta"
    ENCRYPTED_EXT = ".enc"

    def __init__(self, storage_dir: str = None):
        if storage_dir is None:
            storage_dir = str(Path.home() / ".file_crypto" / "metadata")
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_metadata_path(self, encrypted_path: str) -> Path:
        file_id = self._get_file_id(encrypted_path)
        return self.storage_dir / f"{file_id}{self.METADATA_EXT}"

    @staticmethod
    def _get_file_id(file_path: str) -> str:
        import hashlib

        path = Path(file_path).resolve()
        return hashlib.sha256(str(path).encode("utf-8")).hexdigest()

    def save_metadata(
        self,
        encrypted_path: str,
        original_path: str,
        original_size: int,
        password_hash: str,
        encryption_time: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if encryption_time is None:
            encryption_time = datetime.now().isoformat()

        metadata = {
            "encrypted_path": str(Path(encrypted_path).resolve()),
            "original_path": str(Path(original_path).resolve()),
            "original_name": Path(original_path).name,
            "original_size": original_size,
            "encrypted_size": os.path.getsize(encrypted_path),
            "password_hash": password_hash,
            "encryption_time": encryption_time,
            "algorithm": "AES-256-CBC",
            "extra": extra or {},
        }

        meta_path = self._get_metadata_path(encrypted_path)
        self._safe_write_json(meta_path, metadata)

    def load_metadata(self, encrypted_path: str) -> Optional[Dict[str, Any]]:
        meta_path = self._get_metadata_path(encrypted_path)
        if not meta_path.exists():
            return None
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def update_metadata(self, encrypted_path: str, **kwargs) -> bool:
        metadata = self.load_metadata(encrypted_path)
        if metadata is None:
            return False
        metadata.update(kwargs)
        meta_path = self._get_metadata_path(encrypted_path)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        return True

    def delete_metadata(self, encrypted_path: str) -> bool:
        meta_path = self._get_metadata_path(encrypted_path)
        if meta_path.exists():
            meta_path.unlink()
            return True
        return False

    def _safe_write_json(self, file_path: Path, data: Dict[str, Any]) -> None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(file_path.parent),
            suffix=".tmp"
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if os.name == "nt":
                try:
                    os.replace(temp_path, str(file_path))
                except OSError:
                    os.unlink(str(file_path))
                    os.rename(temp_path, str(file_path))
            else:
                os.replace(temp_path, str(file_path))
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

    def list_all_metadata(self) -> list:
        metadata_list = []
        for meta_file in self.storage_dir.glob(f"*{self.METADATA_EXT}"):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                    metadata_list.append(metadata)
            except (json.JSONDecodeError, IOError):
                continue
        return metadata_list

    def get_encrypted_ext(self) -> str:
        return self.ENCRYPTED_EXT

    @staticmethod
    def format_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
