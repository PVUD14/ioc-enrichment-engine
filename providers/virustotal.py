from typing import Optional, Dict
from utils.http import Http
from utils.cache import Cache
from . import provider_name

VT_BASE = "https://www.virustotal.com/api/v3"
SUPPORTED = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}

@provider_name("virustotal")
def enrich(indicator: str, ioc_type: str, api_key: Optional[str], http: Http, cache: Cache) -> Optional[Dict]:
    if not api_key or ioc_type not in SUPPORTED:
        return None
    cached = cache.get("virustotal", indicator)
    if cached:
        return cached
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE}/{SUPPORTED[ioc_type]}/{indicator}"
    try:
        data = http.get(url, headers=headers)
        cache.set("virustotal", indicator, data)
        return data
    except Exception:
        return None
