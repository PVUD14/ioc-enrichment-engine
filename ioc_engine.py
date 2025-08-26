import argparse
import csv
import json
import os
from datetime import datetime
from typing import List, Dict

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib   # fallback for <=3.10

from utils.classify import classify_ioc
from utils.http import Http
from utils.cache import Cache
from providers import get_provider
from schemas import ProviderFinding, EnrichedIOC, EngineReport

SUPPORTED_PROVIDERS = ["virustotal", "otx", "abuseipdb"]


def load_config() -> Dict:
    """Load config.toml if present; otherwise return sane defaults."""
    cfg = {
        "providers": {p: True for p in SUPPORTED_PROVIDERS},
        "api_keys": {p: "" for p in SUPPORTED_PROVIDERS},
        "network": {
            "timeout_seconds": 15,
            "retries": 3,
            "backoff_seconds": 1.5,
        },
    }
    if os.path.exists("config.toml"):
        with open("config.toml", "rb") as f:
            user = tomllib.load(f)
        # shallow merge
        for k, v in user.items():
            if isinstance(v, dict) and k in cfg:
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def read_iocs(path: str) -> List[str]:
    """Read indicators from CSV (single column) or JSON ([..] or {"indicators": [...]})"""
    if path.lower().endswith(".csv"):
        with open(path, newline="", encoding="utf-8") as f:
            return [row[0].strip() for row in csv.reader(f) if row and row[0].strip()]
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()]
    return [str(x).strip() for x in data.get("indicators", []) if str(x).strip()]


def normalize_score(raw_score: float | int | None, max_val: float = 100.0) -> float | None:
    if raw_score is None:
        return None
    try:
        v = float(raw_score)
        if v <= 1.0:
            return v * 100.0
        if v <= max_val:
            return v
        return min(100.0, (v / max_val) * 100.0)
    except Exception:
        return None


def map_vt(payload: Dict | None) -> ProviderFinding:
    if not payload:
        return ProviderFinding(provider="virustotal")
    d = payload.get("data") or {}
    attrs = d.get("attributes", {})
    rep = "malicious" if (attrs.get("last_analysis_stats", {}).get("malicious", 0) > 0) else "clean"
    score = normalize_score(attrs.get("reputation"))
    refs = []
    link = d.get("links", {}).get("self")
    if link:
        refs.append(link)
    return ProviderFinding(provider="virustotal", reputation=rep, score=score, categories=[], references=refs, raw=payload)


def map_otx(payload: Dict | None) -> ProviderFinding:
    if not payload:
        return ProviderFinding(provider="otx")
    pulses = payload.get("pulse_info", {}).get("pulses", [])
    rep = "malicious" if pulses else "unknown"
    refs = [p.get("reference") for p in pulses if p.get("reference")]
    cats = sorted({t for p in pulses for t in p.get("tags", [])})
    return ProviderFinding(provider="otx", reputation=rep, score=None, categories=list(cats), references=refs, raw=payload)


def map_abuse(payload: Dict | None) -> ProviderFinding:
    if not payload:
        return ProviderFinding(provider="abuseipdb")
    d = payload.get("data", {})
    score = d.get("abuseConfidenceScore")
    rep = "malicious" if (isinstance(score, (int, float)) and score >= 25) else "unknown"
    refs = [f"https://www.abuseipdb.com/check/{d.get('ipAddress','')}"] if d.get("ipAddress") else []
    cats = d.get("usageType")
    return ProviderFinding(provider="abuseipdb", reputation=rep, score=normalize_score(score), categories=[cats] if cats else [], references=refs, raw=payload)


MAPPERS = {
    "virustotal": map_vt,
    "otx": map_otx,
    "abuseipdb": map_abuse,
}


def enrich_indicator(indicator: str, providers: List[str], cfg: Dict, http: Http, cache: Cache) -> EnrichedIOC:
    ioc_type = classify_ioc(indicator)
    findings: List[ProviderFinding] = []
    for p in providers:
        if not cfg["providers"].get(p, True):
            continue
        api_key = cfg["api_keys"].get(p, "")
        try:
            data = get_provider(p)(indicator, ioc_type, api_key, http, cache)
        except KeyError:
            data = None
        mapped = MAPPERS[p](data)
        findings.append(mapped)
    return EnrichedIOC(indicator=indicator, ioc_type=ioc_type, findings=findings)


def to_markdown(report: EngineReport) -> str:
    lines: List[str] = []
    lines.append(f"# IOC Enrichment Report

Generated: {report.generated_at.isoformat()}
")
    lines.append(f"Total: {report.total} | By Type: {report.by_type}
")
    for e in report.enrichments:
        lines.append(f"## {e.indicator} ({e.ioc_type})")
        for f in e.findings:
            rep = f.reputation or "n/a"
            score = f.score if f.score is not None else "n/a"
            lines.append(f"- **{f.provider}** → rep: {rep}, score: {score}")
            if f.references:
                for r in f.references[:3]:
                    lines.append(f"  - ref: {r}")
        lines.append("")
    return "
".join(lines)


def ensure_parent(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="IOC Enrichment Engine")
    ap.add_argument("--input", required=True, help="CSV or JSON of indicators")
    ap.add_argument("--providers", default=",".join(SUPPORTED_PROVIDERS), help="Comma-separated providers")
    ap.add_argument("--out-json", default="out/enriched.json")
    ap.add_argument("--out-md", default="out/summary.md")
    ap.add_argument("--cache", default=".cache")
    args = ap.parse_args()

    cfg = load_config()
    http = Http(timeout=cfg["network"]["timeout_seconds"], retries=cfg["network"]["retries"], backoff=cfg["network"]["backoff_seconds"])
    cache = Cache(args.cache)

    ensure_parent(args.out_json)
    ensure_parent(args.out_md)

    indicators = read_iocs(args.input)
    provs = [p.strip() for p in args.providers.split(",") if p.strip()]

    enrichments: List[EnrichedIOC] = []
    by_type: Dict[str, int] = {}

    for ind in indicators:
        e = enrich_indicator(ind, provs, cfg, http, cache)
        by_type[e.ioc_type] = by_type.get(e.ioc_type, 0) + 1
        enrichments.append(e)

    report = EngineReport(
        generated_at=datetime.utcnow(),
        total=len(indicators),
        by_type=by_type,
        enrichments=enrichments,
    )

    with open(args.out_json, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(to_markdown(report))

    print(f"Saved → {args.out_json}
Saved → {args.out_md}")


if __name__ == "__main__":
    main()
