from typing import Optional, Dict
from ..utils.http import Http
from ..utils.cache import Cache
from . import provider_name

ABUSE_BASE = "https://api.abuseipdb.com/api/v2/check"

@provider_name("abuseipdb")
def enrich(indicator: str, ioc_type: str, api_key: Optional[str], http: Http, cache: Cache) -> Optional[Dict]:
    if ioc_type != "ip" or not api_key:
        return None
    cached = cache.get("abuseipdb", indicator)
    if cached:
        return cached
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": indicator, "maxAgeInDays": 90}
    try:
        data = http.get(ABUSE_BASE, headers=headers, params=params)
        cache.set("abuseipdb", indicator, data)
        return data
    except Exception:
        return None
