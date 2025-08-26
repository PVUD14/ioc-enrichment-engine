# IOC Enrichment Engine

## Overview
A lightweight Python-based engine to enrich Indicators of Compromise (IOCs) via multiple providers (VirusTotal, OTX, AbuseIPDB). Results are normalized into JSON + Markdown reports.

## Features
- Supports multiple IOC types: IP, Domain, URL, Hash
- Pluggable providers with caching layer
- Outputs in JSON and Markdown
- CI-ready with GitHub Actions workflow
- Example IOC files included (CSV & JSON)
- Config-driven API keys (TOML)

## Quickstart
```bash
# 1. Clone repo
 git clone https://github.com/<your-user>/ioc-enrichment-engine.git
 cd ioc-enrichment-engine

# 2. Install deps
 pip install -r requirements.txt

# 3. Copy config and add your API keys
 cp config.example.toml config.toml

# 4. Run enrichment
 python ioc_engine.py --input examples/iocs.csv --providers virustotal,otx,abuseipdb \
   --out-json out/enriched.json --out-md out/summary.md
