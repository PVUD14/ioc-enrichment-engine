import time
import requests
from typing import Dict, Optional

class Http:
    def __init__(self, timeout: int = 15, retries: int = 3, backoff: float = 1.5):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff

    def get(self, url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None):
        last_err = None
        for attempt in range(self.retries):
            try:
                r = requests.get(url, headers=headers, params=params, timeout=self.timeout)
                if r.status_code == 429:  # rate limit
                    time.sleep(self.backoff * (attempt + 1))
                    continue
                r.raise_for_status()
                return r.json()
            except Exception as e:
                last_err = e
                time.sleep(self.backoff * (attempt + 1))
        raise last_err
