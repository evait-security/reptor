import json
import os
import pathlib
import time


class TokenStore:
    def __init__(self, path: pathlib.Path = None):
        from reptor.oauth import config

        self.path = pathlib.Path(path) if path else config.token_file()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    def save(self, data: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def clear(self):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def is_expired(data: dict, margin: int = 30) -> bool:
        expires = data.get("access_expires_at")
        if not expires:
            return False
        return int(expires) - margin <= int(time.time())
