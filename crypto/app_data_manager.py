import json
import os
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any


class AppDataManager:
    APP_DIR_NAME = ".file_crypto"
    CONFIG_FILE = "config.json"
    HISTORY_FILE = "history.json"

    def __init__(self):
        self.app_dir = Path.home() / self.APP_DIR_NAME
        self.app_dir.mkdir(parents=True, exist_ok=True)

        self.config_path = self.app_dir / self.CONFIG_FILE
        self.history_path = self.app_dir / self.HISTORY_FILE

        self._config = self._load_config()
        self._history = self._load_history()

    def _load_config(self) -> Dict[str, Any]:
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return self._default_config()
        return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "output_dir": "",
            "output_same_dir": True,
            "show_password": False,
            "window_geometry": None,
            "last_encrypt_dir": "",
            "last_decrypt_dir": "",
        }

    def _save_config(self) -> None:
        self._safe_write_json(self.config_path, self._config)

    def _load_history(self) -> List[Dict[str, Any]]:
        if self.history_path.exists():
            try:
                with open(self.history_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save_history(self) -> None:
        self._safe_write_json(self.history_path, self._history)

    def _safe_write_json(self, file_path: Path, data: Any) -> None:
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
                    if os.path.exists(str(file_path)):
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

    def get_config(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        self._config[key] = value
        self._save_config()

    def get_all_config(self) -> Dict[str, Any]:
        return dict(self._config)

    def add_history_item(self, item: Dict[str, Any]) -> None:
        encrypted_path = item.get("encrypted_path", "")
        for i, hist in enumerate(self._history):
            if hist.get("encrypted_path") == encrypted_path:
                self._history[i] = item
                self._save_history()
                return
        self._history.append(item)
        if len(self._history) > 100:
            self._history = self._history[-100:]
        self._save_history()

    def remove_history_item(self, encrypted_path: str) -> None:
        self._history = [
            h for h in self._history if h.get("encrypted_path") != encrypted_path
        ]
        self._save_history()

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history = []
        self._save_history()

    def get_app_dir(self) -> Path:
        return self.app_dir
