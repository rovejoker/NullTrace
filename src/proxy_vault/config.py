import os
import yaml
from pathlib import Path
from typing import Any


class Config:
    def __init__(self, path: str | None = None):
        if path is None:
            path = os.environ.get("PROXY_VAULT_CONFIG", "config.yaml")
        self._path = Path(path)
        self._data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self._path.exists():
            with open(self._path, encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}

    def save(self) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            yaml.safe_dump(self._data, f, default_flow_style=False)

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        keys = key.split(".")
        d = self._data
        for k in keys[:-1]:
            if k not in d:
                d[k] = {}
            d = d[k]
        d[keys[-1]] = value

    @property
    def proxy_host(self) -> str:
        return self.get("proxy.host", "127.0.0.1")

    @property
    def proxy_port(self) -> int:
        return self.get("proxy.port", 1080)

    @property
    def webui_port(self) -> int:
        return self.get("webui.port", 8080)

    @property
    def data(self) -> dict:
        return self._data


config = Config()
