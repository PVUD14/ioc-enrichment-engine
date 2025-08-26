from typing import Optional, Dict
from ..utils.http import Http
from ..utils.cache import Cache
from . import provider_name

OTX_BASE = "https://otx.alienvault.com/api/v1"

@provider_name("otx")
def enrich(indicator: str, ioc_type: str, api_key: Optional[str], http: Http, cache: Cache) -> Optional[Dict]:
    cached = cache.get("otx", indicator)
    if cached:
        return cached

    if ioc_type == "ip":
        url = f"{OTX_BASE}/indicators/IPv4/{indicator}/general"
    elif ioc_type == "domain":
        url = f"{OTX_BASE}/indicators/domain/{indicator}/general"
    elif ioc_type == "url":
        url = f"{OTX_BASE}/indicators/url/{indicator}/general"
    elif ioc_type == "hash":
        url = f"{OTX_BASE}/indicators/file/{indicator}/general"
    else:
        return None

    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    try:
        data = http.get(url, headers=headers)
        cache.set("otx", indicator, data)
        return data
    except Exception:
        return None
