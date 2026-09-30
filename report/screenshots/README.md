# Screenshots

Drop your own run screenshots here — they are your proof of authorship and the
backbone of the long write-up. Suggested filenames, grouped by the section of
the report/presentation they belong to (RedPi-style: show the process AND the
errors). You don't need every one; the ★ are the high-value ones.

## 00 — Setup
- `00_venv_install.png`      — venv + `pip install -r requirements.txt`
- `00_env_keys.png`         — `.env` with the free-tier keys filled (blur the values)
- `00_providers_enabled.png`— the log line `providers enabled: ... threatfox, virustotal, otx`

## 01 — Raw material (seeds)
- `01_threatfox_search.png` — ThreatFox `malware:DDoSia` results (the 2 C2 IPs)
- `01_seeds_txt.png`        — your seeds.txt contents

## 02 — Passive pivoting
- `02_run_command.png`      — the full osint_pivot.py command
- ★ `02_wrote_17_nodes.png` — the final `INFO wrote 17 nodes (0 confirmed, 3 feed-attributed)` line

## 03 — The graph
- `03_graph_html.png`       — graph.html open in the browser

## 04 — Errors & negative space (YOUR BIGGEST ASSET — show these)
- ★ `04a_606_nodes_explosion.png` — a run WITHOUT filters (`--max-nodes 700`, no --freeze/--since): the noise blow-up
- ★ `04b_skip_pdns_lines.png`     — the `skip pDNS: NNN domains (shared/parked IP)` log lines (filters working)
- ★ `04c_freeze_31.13.195.87.png` — before/after freezing the contaminated C2
- ★ `04d_8888_confirmed_bug.png`  — 8.8.8.8 / Cloudflare wrongly "confirmed" in the old MISP, then the fix
- ★ `04e_flotaero_2021.png`       — the flotaero.info 2021 pDNS record in edges.csv → the --since window drop

## 05 — Interchange artifacts
- `05_stix.png`  — iocs.stix.json (in an editor, or imported into OpenCTI/a STIX viewer)
- `05_misp.png`  — iocs.misp.json (or imported as a MISP event)

## 06 — Maltego
- `06_maltego.png` — already provided as report/figures/topology_maltego.png (move/copy here if you prefer)
