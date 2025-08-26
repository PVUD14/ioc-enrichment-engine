import json
import os
import hashlib
from typing import Optional

class Cache:
    def __init__(self, root: str = ".cache"):
        self.root = root
        os.makedirs(self.root, exist_ok=True)

    def _key(self, provider: str, indicator: str) -> str:
        h = hashlib.sha256(f"{provider}:{indicator}".encode()).hexdigest()
        return os.path.join(self.root, f"{h}.json")

    def get(self, provider: str, indicator: str) -> Optional[dict]:
        path = self._key(provider, indicator)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def set(self, provider: str, indicator: str, data: dict):
        path = self._key(provider, indicator)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
