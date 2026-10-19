[Castellano](README.md) · **English**

> **Translated version.** This README was translated from the Spanish original, which is the reference version: [read it in Spanish](README.md).

# OSINT Infrastructure Mapping · NoName057(16) / DDoSia

> **TLP:CLEAR** · Infrastructure reconstruction and actor profile built from **open sources** and **passive lookups**. No interaction with the actor or with live infrastructure.

Passive pivoting tool and threat intelligence profile of the pro-Russian hacktivist group **NoName057(16)** (the **DDoSia** project). It reconstructs the **publicly documented** C2, management and attack topology by correlating indicators already published by vendors and law enforcement, and enriches it with passive lookups. The value is not discovering live infrastructure, but **validating, deduplicating and reasoning** about what has been documented, and rejecting noise transparently.

> **Process document (PDF, in Spanish):** [`docs/proceso_v1.pdf`](docs/proceso_v1.pdf) · how I built the report, step by step.

**Full report:** [`report/noname057_ddosia_profile.md`](report/noname057_ddosia_profile.md) (ES: [`report/noname057-ddosia.es.md`](report/noname057-ddosia.es.md))
**Portfolio:** https://iraitzaristi.github.io

## Methodology

- **Open sources and passive lookups only.** Every data point comes from third-party caches, scanners or databases: Certificate Transparency (crt.sh), passive DNS (VirusTotal, AlienVault OTX), RDAP/WHOIS, RIPEstat (ASN/BGP), Shodan InternetDB and abuse.ch feeds (ThreatFox, URLhaus), plus published reporting.
- **Zero interaction.** At no point are the actor's names resolved, its hosts scanned or its infrastructure contacted. This is a deliberate methodological boundary, not a limitation.
- **Documented actor.** The seeds are already published indicators (Team Cymru, building on SentinelLabs, and 2026 ThreatFox sightings). The management topology derived from network telemetry, which a passive tool cannot rediscover, is stated as analyst-curated relations, each with its source and confidence level.
- **Snapshot, not a live view.** The operational C2 rotates on a scale of days, so the analysis is pinned to a documented snapshot of the 2022 to 2026 period.

## Repository layout

```
.
├── osint_pivot.py              # passive pivoting tool
├── build_report_artifacts.py   # builds graphs and bundles from the outputs
├── seeds.txt                   # seeds (documented IOCs)
├── relations_teamcymru.csv     # analyst-curated relations (from reporting)
├── outputs/                    # example run (nodes, edges, graph, STIX, MISP)
├── report/
│   ├── noname057_ddosia_profile.md   # report (EN)
│   ├── noname057-ddosia.es.md        # report (ES)
│   ├── figures/                      # topology (graphviz, drawio, maltego)
│   └── screenshots/                  # process evidence
├── docs/                       # MALTEGO.md, process narrative
├── .env.example                # key template (all optional)
└── LICENSE
```

## Setup and usage

Requires Python 3. Minimal dependencies (`requests`, and optionally `python-dotenv`):

```bash
pip install -r requirements.txt
```

**API keys are optional**: the tool works with the keyless sources (crt.sh, RDAP, RIPEstat, Shodan InternetDB, SSLBL feeds) and uses whichever keys are configured. To add VirusTotal or abuse.ch, copy `.env.example` to `.env` and fill in what you have.

Typical run:

```bash
python osint_pivot.py --seeds seeds.txt --depth 2 \
    --snapshot "pre-Eastwood-2025-07" --out ./outputs
```

Or with individual seeds:

```bash
python osint_pivot.py --seed-domain example.tld --seed-ip 203.0.113.10 --depth 1
```

## Outputs

In `outputs/`: nodes and edges (`nodes.csv/json`, `edges.csv/json`), the graph (`graph.dot`, `graph.html`), the IOCs in machine-readable formats (**STIX 2.1** in `iocs.stix.json`, **MISP** in `iocs.misp.json`) and a `run_manifest.json` with the run trace. The topology figures are in `report/figures/`.

## Development and authorship

The pivoting tool (`osint_pivot.py`) was **developed with AI assistance** as a programming aid. The code was then **reviewed, fixed, improved and simplified by me**: I adjusted the pivoting and enrichment logic, the exclusions (parking/CDN ranges, high fan-out hosts, provider PTRs, bogon addresses), the time filtering by snapshot window and the output format. I understand and stand behind every part of the code.

I removed the Validin provider, which was included in an early version: I could not verify its API route and authentication on the free tier and did not use it in the example run, so I chose not to keep untested code. The screenshots in the process document (v1) show the original `.env.example`, which still included Validin.

The **report analysis**, the **methodological decisions** (what to pivot, what to freeze, what to reject and why, such as the `flotaero.info` candidate discarded by date) and the **confidence-rated assessments** are entirely my own.

## License

The code (the tool, the scripts and the artifacts) is released under the [MIT License](LICENSE).

The analysis report and the written documentation (`report/`, `docs/`) are © 2026 Iraitz Aristi Lucambio and are released under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/): you may share and adapt them as long as you credit the author.

## Disclaimer

**Defensive** intelligence work based solely on open sources, for research and detection purposes. No interaction with the actor or its live infrastructure. Indicators are published defanged. **TLP:CLEAR.**
