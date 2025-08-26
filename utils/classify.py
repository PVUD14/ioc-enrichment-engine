import re

def classify_ioc(value: str) -> str:
    v = value.strip()
    ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    domain = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
    url = re.compile(r"^(?:https?://)[^\s]+$")
    sha256 = re.compile(r"^[A-Fa-f0-9]{64}$")
    sha1 = re.compile(r"^[A-Fa-f0-9]{40}$")
    md5 = re.compile(r"^[A-Fa-f0-9]{32}$")

    if url.match(v):
        return "url"
    if ipv4.match(v):
        return "ip"
    if sha256.match(v) or sha1.match(v) or md5.match(v):
        return "hash"
    if domain.match(v):
        return "domain"
    return "unknown"
