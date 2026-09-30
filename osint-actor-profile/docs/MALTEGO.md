# Viewing the graph in Maltego CE

Maltego is used here as a **presentation / exploration layer**, not as the
collection engine — the passive pivoting, filtering and confidence scoring all
happen in `osint_pivot.py`. Importing the result into Maltego gives an
interactive canvas (and a good screenshot for a report).

## Import the graph

1. Run the pipeline so `outputs/nodes.csv` and `outputs/edges.csv` exist.
2. In Maltego CE: **Import → Import Graph from Table** (CSV).
3. Map columns:
   - `nodes.csv`: `value` → the matching entity type by `type`
     (`ipv4`→IPv4Address, `domain`→Domain, `asn`→AS, `certificate`→Certificate).
   - `edges.csv`: `src` → source entity, `dst` → target entity, `rel` → link label.
4. Optionally weight/colour links by the `weight` column (strong / moderate / weak)
   to mirror the confidence model.

## Passive discipline in Maltego

Maltego's built-in DNS transforms (e.g. "Resolve to IP") perform **live**
resolution and would break the passive rule. Keep them disabled against actor
nodes; for extra pivoting use transforms backed by third-party data only
(crt.sh, PassiveTotal, OTX, Shodan) — never live resolution of the actor's names.

## What to capture

A screenshot of the imported graph makes good evidence of authorship for a
portfolio. Frame the documented core topology (DDNS → C2 → mirror → management
stack) rather than the context/noise nodes.
