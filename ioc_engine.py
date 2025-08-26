import argparse
import csv
import json
import tomllib
from pathlib import Path
from datetime import datetime
from typing import List, Dict

from rich.console import Console
from rich.table import Table

from utils.classify import classify_ioc
from utils.http import Http
from utils.cache import Cache
from schemas import EnrichedIOC, EngineReport, ProviderFinding
from providers import get_provider, all_providers

console = Console()


def load_iocs(path: Path) -> List[str]:
    if path.suffix == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            return [row[0].strip() for row in csv.reader(f) if row]
    elif path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("indicators", [])
    else:
        raise ValueError("Unsupported input format. Use CSV or JSON.")


def summarize(report: EngineReport, out_md: Path):
    table = Table(title="IOC Enrichment Summary")
    table.add_column("Indicator")
    table.add_column("Type")
    table.add_column("Providers")
    table.add_column("Tags")

    lines = ["# IOC Enrichment Summary\n"]
    for e in report.enrichments:
        provs = ", ".join([f.provider for f in e.findings])
        tags = ", ".join(e.tags)
        table.add_row(e.indicator, e.ioc_type, provs, tags)
        lines.append(f"- **{e.indicator}** ({e.ioc_type}) – Providers: {provs}")

    console.print(table)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def run_engine(iocs: List[str], providers: List[str], config: Dict, out_json: Path, out_md: Path):
    http = Http(
        timeout=config.get("engine", {}).get("timeout", 15),
        retries=config.get("engine", {}).get("retries", 3),
        backoff=config.get("engine", {}).get("backoff", 1.5),
    )
    cache = Cache()

    enrichments = []
    for i in iocs:
        ioc_type = classify_ioc(i)
        findings = []
        for pname in providers:
            if pname not in all_providers():
                continue
            fn = get_provider(pname)
            api_key = config.get("providers", {}).get(pname)
            data = fn(i, ioc_type, api_key, http, cache)
            if data:
                findings.append(ProviderFinding(provider=pname, raw=data))
        enrichments.append(EnrichedIOC(indicator=i, ioc_type=ioc_type, findings=findings))

    report = EngineReport(
        generated_at=datetime.utcnow(),
        total=len(enrichments),
        by_type={},
        enrichments=enrichments,
    )
    # Count by type
    for e in enrichments:
        report.by_type[e.ioc_type] = report.by_type.get(e.ioc_type, 0) + 1

    # Save JSON
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(), f, indent=2, default=str)

    # Save Markdown
    summarize(report, out_md)


def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Engine")
    parser.add_argument("--input", required=True, help="Path to input file (CSV/JSON)")
    parser.add_argument("--providers", required=False, default="", help="Comma-separated providers")
    parser.add_argument("--config", default="config.toml", help="Path to config.toml")
    parser.add_argument("--out-json", default="out/enriched.json", help="Path to output JSON")
    parser.add_argument("--out-md", default="out/summary.md", help="Path to output Markdown")
    args = parser.parse_args()

    with open(args.config, "rb") as f:
        config = tomllib.load(f)

    iocs = load_iocs(Path(args.input))
    providers = [p.strip() for p in args.providers.split(",") if p.strip()] or all_providers()

    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)

    run_engine(iocs, providers, config, Path(args.out_json), Path(args.out_md))


if __name__ == "__main__":
    main()
