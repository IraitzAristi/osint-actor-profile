# OSINT ACTOR PROFILE - snapshot based OSINT infrastructure reconstruction

Passive, open-source reconstruction of a rotating-C2 threat actor's known infrastructure, built as an intelligence-analysis exercise, not an investigation. **Case study: NoName057(16) / DDoSia.**

The pipeline takes published seed indicators, pivots them through free-tier passive sources, merges analyst-curated (report-sourced) relationships, scores every link by confidence, aggressively filters shared/benign infrastructure, and exports an interactive graph plus **STIX 2.1** and **MISP** bundles.

> **The point of this project is not a big graph.** It is *disciplined* pivoting: automated validation and de-duplication of a documented topology, with transparent, reproducible rejection of noise. On this actor the honest result is **zero newly-confirmed infrastructure** beyond what vendors already published - and the repo shows exactly what was filtered and why. What the pipeline *rejects* is as important as what it keeps.

**Scope:** open sources + passive queries only. Every lookup hits a third-party cache/scanner/database (Certificate Transparency, passive DNS, RDAP/WHOIS, RIPEstat, Shodan InternetDB). The tooling never resolves the actor's names, scans its hosts, or contacts its infrastructure. `TLP:CLEAR`.

---

## Why it's interesting

- **Confidence is per-relationship, not per-graph.** Cert reuse / SAN siblings / public-feed hits = *strong*, passive-DNS co-resolution = *moderate*, shared ASN = *weak / context only*. A node is only "confirmed" with ≥1 strong or ≥2 independent moderate edges.
- **Noise control is in code, not prose.** Fan-out caps (an IP tied to many domains, or a cert with many SANs = shared/parked), parking/CDN ranges, provider reverse-DNS, bogons, and a **snapshot time-window** are all enforced by the pivoter and visible in the outputs.
- **Analyst-curated intelligence is merged with provenance.** Telemetry-based links a passive tool can't rediscover (e.g. Team Cymru's netflow topology) are asserted from a CSV, each edge carrying its source and confidence.
- **A worked "negative space" example.** The one candidate the automated pivot surfaced (`flotaero[.]info`) is rejected on temporal grounds - its passive-DNS record predates the actor - and dropped automatically by the snapshot window.

## What it produces

| File | What |
| --- | --- |
| `outputs/graph.html` | Interactive relationship graph (domain -> IP -> service -> ASN), colour-coded by status/confidence |
| `outputs/graph.dot` | Same graph in Graphviz (`dot -Tpng graph.dot -o graph.png`) |
| `outputs/iocs.stix.json` | STIX 2.1 bundle (SCOs, indicators, infrastructure, intrusion-set, relationships) |
| `outputs/iocs.misp.json` | MISP event (attributes with `to_ids`, TLP tag) |
| `outputs/nodes.* / edges.*` | Normalized graph as JSON and CSV |
| `outputs/run_manifest.json` | Run metadata: seeds, window, providers, counts, scope statement |
| `report/noname057_ddosia_profile.md` | Full threat-actor profile (executive summary, key judgments, attribution, ATT&CK, infrastructure, timeline, assessment, defensive recommendations, graded sources) |

## Repository layout

```
osint-actor-profile/
├── osint_pivot.py            # collection + pivoting + filtering + confidence
├── build_report_artifacts.py # graph.html / graph.dot / STIX / MISP from the graph
├── seeds.txt                 # seed indicators (documented C2 + 2026 sightings)
├── relations_teamcymru.csv   # analyst-curated topology (source + confidence per edge)
├── attack_infrastructure.csv # attack ASNs/netblocks (report table, not pivotable)
├── report/                   # the written intelligence product
├── outputs/                  # generated artifacts (committed as an example run)
├── requirements.txt
├── .env.example
└── .gitignore
```

## Setup

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows PowerShell   (Linux/mac: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env               # then fill in free-tier API keys
```

All keys are free tier and **optional** - the tool degrades gracefully and uses whatever is present. Keyless sources (crt.sh, RDAP, RIPEstat, Shodan InternetDB, abuse.ch SSLBL feeds) always work.

| Env var | Provider | Where |
| --- | --- | --- |
| `ABUSECH_AUTH_KEY` | ThreatFox + URLhaus | https://auth.abuse.ch |
| `VT_API_KEY` | VirusTotal (public) | account -> API key |
| `OTX_API_KEY` | AlienVault OTX | Settings -> API Integration |
| `VALIDIN_API_KEY` | Validin Community (optional) | account -> Manage API keys |

## Reproduce the example run

```bash
python osint_pivot.py --seeds seeds.txt --relations relations_teamcymru.csv --freeze 31.13.195.87 --since 2022-01-01 --depth 2 --snapshot "C2-documented-2022-2026" --out ./outputs

python build_report_artifacts.py --in ./outputs --out ./outputs --actor "NoName057(16)" --aliases DDoSia Dosia --snapshot "C2-documented-2022-2026" --producer "Iraitz Aristi"
```

- `--freeze 31.13.195.87` — enrich the publicly-outed C2 but don't pivot its polluted passive DNS.
- `--since 2022-01-01` — snapshot window, drops passive-DNS records predating the actor (this is what removes the `flotaero[.]info` previous-tenant branch).

**Expected result:** a small, clean graph (17 nodes / 24 edges), **0 newly-confirmed** actor nodes, the documented topology intact and all shared/benign infrastructure demoted to *context*. Exact counts are written to `outputs/run_manifest.json`. Responses are cached under `.cache/` (git-ignored, regenerable), so re-runs are fast.


## Methodology (summary)

1. **Seeds** from published reporting (Team Cymru 2023, via SentinelLabs) and public feeds (abuse.ch ThreatFox, 2026).
2. **Curated relations** for the netflow-documented management topology, merged with per-edge source/confidence.
3. **Passive pivoting** via crt.sh (CT), VirusTotal/OTX passive DNS, RIPEstat (ASN), Shodan InternetDB, with fan-out caps, parking/CDN/bogon filters, provider-rDNS filter, node freezing, and the snapshot window.
4. **Confidence resolution** promotes/demotes nodes from edge evidence, shared/parked/bogon infrastructure is never promoted.
5. **Export** to an interactive graph and interchange formats (STIX 2.1 / MISP).

The written product maps the actor's tradecraft to MITRE ATT&CK, uses estimative language with explicit confidence, and grades sources on the Admiralty scale.

## Limitations

Passive and snapshot-bound: DDoSia's C2 rotates on a scale of days, so this is a documented reconstruction, not a live map. Historically documented IPs may since be reassigned, sinkholed, or under law-enforcement control. Public feeds decay (e.g. ThreatFox's ~6-month window), so historical coverage relies on dated vendor reporting.

## Key sources

Team Cymru, *A Blog with NoName* (2023), Europol/Eurojust, Operation Eastwood (2025), abuse.ch ThreatFox, Sekoia TDR, Recorded Future / Insikt, Censys. Full graded list in the report.

---

*Analysis based solely on open-source reporting. No interaction with the actor or its live infrastructure. `TLP:CLEAR`.*
