#!/usr/bin/env python3
"""
build_report_artifacts.py -- Phase 4: turn the pivot graph into deliverables.

Reads nodes.json / edges.json (produced by osint_pivot.py) and emits:
  graph.html       interactive graph (vis-network via CDN; opens in a browser)
  graph.dot        Graphviz DOT  (render:  dot -Tpng graph.dot -o graph.png)
  iocs.stix.json   STIX 2.1 bundle (SCOs + indicators + infrastructure + SROs)
  iocs.misp.json   MISP event

Dependency-free (Python stdlib only). This step only transforms local files,
it contacts no infrastructure. Open-source / passive provenance is preserved.

USAGE
  python build_report_artifacts.py --in ./outputs --out ./outputs \
      --actor "NoName057(16)" --aliases DDoSia Dosia \
      --snapshot 2026-07 --producer "Iraitz Aristi"
"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from pathlib import Path

# Namespace for deterministic STIX 2.1 SCO ids (UUIDv5).
STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

WEIGHT_CONFIDENCE = {"strong": 85, "moderate": 60, "weak": 30}

# node type -> (STIX SCO type, MISP attribute type)
NODE_MAP = {
    "ipv4":        ("ipv4-addr",       "ip-dst"),
    "domain":      ("domain-name",     "domain"),
    "certificate": ("x509-certificate","x509-fingerprint-sha256"),
    "asn":         ("autonomous-system","AS"),
}

# edge rel -> STIX relationship_type (for the SRO layer)
REL_STIX = {
    "pdns_coresolve":   "resolves-to",
    "cert_san_sibling": "related-to",
    "shodan_hostname":  "related-to",
    "same_asn":         "belongs-to",
    "shared_hosting":   "related-to",
    "whois_registrant": "related-to",
    "crawl_fingerprint":"related-to",
    "cert_reuse":       "related-to",
    "reported_c2":          "related-to",
    "resolves_to_reported": "resolves-to",
    "mirror_of":            "related-to",
    "communicates_with":    "communicates-with",
}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _isodate(v) -> str | None:
    """Extract a STIX timestamp (YYYY-MM-DDT00:00:00.000Z) from any date-ish
    value (ISO date, epoch, 'YYYY-MM-DD HH:MM:SS UTC'). None if unparseable."""
    if not v:
        return None
    s = str(v)
    m = re.search(r"\d{4}-\d{2}-\d{2}", s)
    if m:
        return f"{m.group(0)}T00:00:00.000Z"
    if re.fullmatch(r"\d{9,10}", s):
        return time.strftime("%Y-%m-%dT00:00:00.000Z", time.gmtime(int(s)))
    return None


def sco_id(sco_type: str, value: str) -> str:
    return f"{sco_type}--{uuid.uuid5(STIX_NS, f'{sco_type}:{value.lower()}')}"


def sdo_id(sdo_type: str) -> str:
    return f"{sdo_type}--{uuid.uuid4()}"


def load_graph(in_dir: Path):
    nodes = json.loads((in_dir / "nodes.json").read_text())
    edges = json.loads((in_dir / "edges.json").read_text())
    manifest = {}
    mf = in_dir / "run_manifest.json"
    if mf.exists():
        manifest = json.loads(mf.read_text())
    return nodes, edges, manifest


def feed_attributed_ids(edges) -> set:
    return {e["dst"] for e in edges if e["rel"] == "ioc_feed"}


# 1) Interactive HTML (vis-network)                                           
NODE_COLOR = {
    "seed":      "#2563eb",  # blue
    "confirmed": "#16a34a",  # green
    "candidate": "#9ca3af",  # grey
    "context":   "#d1d5db",  # light grey
}
EDGE_STYLE = {           # (color, dashes)
    "strong":   ("#111827", False),
    "moderate": ("#6b7280", True),
    "weak":     ("#d1d5db", [2, 6]),
}


def build_html(nodes, edges, attributed, meta) -> str:
    vis_nodes, vis_edges = [], []
    for n in nodes:
        label = n["value"]
        badge = "  [feed]" if n["id"] in attributed else ""
        title = (f"{n['type']} | status: {n['status']}"
                 f" | sources: {', '.join(n.get('sources', []))}")
        if n.get("attrs"):
            title += " | " + "; ".join(f"{k}={v}" for k, v in n["attrs"].items())
        vis_nodes.append({
            "id": n["id"],
            "label": label + badge,
            "title": title,
            "color": NODE_COLOR.get(n["status"], "#9ca3af"),
            "shape": {"ipv4": "dot", "domain": "box",
                      "certificate": "diamond", "asn": "hexagon"}.get(n["type"], "dot"),
            "font": {"color": "#111827"},
        })
    for e in edges:
        if e["src"] == e["dst"]:
            continue # self-edges (feed attribution) shown as node badge instead
        color, dashes = EDGE_STYLE.get(e["weight"], ("#6b7280", True))
        etitle = f"{e['rel']} ({e['weight']}) via {e['source']}"
        if e.get("note"):
            etitle += f" — {e['note']}"
        if e.get("first_seen"):
            etitle += f" [{e['first_seen']}]"
        vis_edges.append({
            "from": e["src"], "to": e["dst"], "label": e["rel"],
            "color": {"color": color}, "dashes": dashes,
            "arrows": "to", "font": {"size": 10, "align": "middle"},
            "title": etitle,
        })
    legend = ("Nodes: blue=seed, green=confirmed, grey=candidate, light=context. "
              "Edges: solid=strong, dashed=moderate, dotted=weak. [feed]=in a public IOC feed.")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{meta['actor']} - infrastructure graph ({meta['snapshot']})</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#fff;color:#111827}}
 header{{padding:14px 18px;border-bottom:1px solid #e5e7eb}}
 h1{{font-size:16px;margin:0 0 4px}} .sub{{color:#6b7280;font-size:12px}}
 #net{{height:80vh}} .legend{{padding:10px 18px;font-size:12px;color:#374151;border-top:1px solid #e5e7eb}}
</style></head><body>
<header>
 <h1>{meta['actor']} - reconstructed infrastructure (open-source, passive)</h1>
 <div class="sub">Snapshot {meta['snapshot']} | {len(vis_nodes)} nodes, {len(vis_edges)} edges |
  Analysis based solely on open-source reporting; no interaction with the actor's infrastructure.</div>
</header>
<div id="net"></div>
<div class="legend">{legend}</div>
<script>
 const nodes=new vis.DataSet({json.dumps(vis_nodes)});
 const edges=new vis.DataSet({json.dumps(vis_edges)});
 new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
   physics:{{stabilization:true,barnesHut:{{springLength:160}}}},
   interaction:{{hover:true}}}});
</script></body></html>"""


# 2) Graphviz DOT                                                              
def build_dot(nodes, edges, attributed, meta) -> str:
    def esc(s): return str(s).replace('"', '\\"')
    lines = [f'digraph "{esc(meta["actor"])}" {{', '  rankdir=LR; node [style=filled,fontname="Helvetica"];']
    for n in nodes:
        fill = {"seed": "#2563eb", "confirmed": "#16a34a",
                "candidate": "#e5e7eb", "context": "#f3f4f6"}.get(n["status"], "#e5e7eb")
        fc = "white" if n["status"] in ("seed", "confirmed") else "black"
        shape = {"ipv4": "ellipse", "domain": "box",
                 "certificate": "diamond", "asn": "hexagon"}.get(n["type"], "ellipse")
        lbl = esc(n["value"]) + (" [feed]" if n["id"] in attributed else "")
        lines.append(f'  "{esc(n["id"])}" [label="{lbl}",shape={shape},'
                     f'fillcolor="{fill}",fontcolor="{fc}"];')
    for e in edges:
        if e["src"] == e["dst"]:
            continue
        style = {"strong": "solid", "moderate": "dashed", "weak": "dotted"}.get(e["weight"], "dashed")
        lines.append(f'  "{esc(e["src"])}" -> "{esc(e["dst"])}" '
                     f'[label="{esc(e["rel"])}",style={style}];')
    lines.append("}")
    return "\n".join(lines)


# 3) STIX 2.1 bundle                                                           
def build_stix(nodes, edges, attributed, meta) -> dict:
    ts = now()
    objects = []

    marking = {
        "type": "marking-definition", "spec_version": "2.1",
        "id": sdo_id("marking-definition"), "created": ts,
        "definition_type": "statement",
        "definition": {"statement": "TLP:CLEAR - open-source, passive analysis."},
    }
    identity = {
        "type": "identity", "spec_version": "2.1", "id": sdo_id("identity"),
        "created": ts, "modified": ts, "name": meta["producer"],
        "identity_class": "individual",
    }
    intrusion = {
        "type": "intrusion-set", "spec_version": "2.1", "id": sdo_id("intrusion-set"),
        "created": ts, "modified": ts, "name": meta["actor"],
        "aliases": meta["aliases"],
        "created_by_ref": identity["id"],
    }
    infra = {
        "type": "infrastructure", "spec_version": "2.1", "id": sdo_id("infrastructure"),
        "created": ts, "modified": ts,
        "name": f"{meta['actor']} C2 (snapshot {meta['snapshot']})",
        "infrastructure_types": ["command-and-control"],
        "created_by_ref": identity["id"],
        "object_marking_refs": [marking["id"]],
    }
    objects += [marking, identity, intrusion, infra]

    # earliest observed date per node (from edge first_seen) for indicator valid_from
    node_earliest = {}
    for e in edges:
        d = _isodate(e.get("first_seen"))
        if not d:
            continue
        for endpoint in (e["src"], e["dst"]):
            if endpoint not in node_earliest or d < node_earliest[endpoint]:
                node_earliest[endpoint] = d

    node_to_sco = {}
    for n in nodes:
        if n["type"] not in NODE_MAP:
            continue
        stype = NODE_MAP[n["type"]][0]
        sid = sco_id(stype, n["value"])
        node_to_sco[n["id"]] = sid
        sco = {"type": stype, "id": sid, "spec_version": "2.1"}
        if stype == "ipv4-addr" or stype == "domain-name":
            sco["value"] = n["value"]
        elif stype == "x509-certificate":
            sco["hashes"] = {"SHA-256": n["value"]}
        elif stype == "autonomous-system":
            sco["number"] = int(str(n["value"]).lstrip("ASas") or 0)
        objects.append(sco)

        # indicator for attributed / confirmed / seed nodes (not for ASNs)
        if stype != "autonomous-system" and (
                n["id"] in attributed or n["status"] in ("seed", "confirmed")):
            pattern = {
                "ipv4-addr":   f"[ipv4-addr:value = '{n['value']}']",
                "domain-name": f"[domain-name:value = '{n['value']}']",
                "x509-certificate": f"[x509-certificate:hashes.'SHA-256' = '{n['value']}']",
            }[stype]
            conf = 85 if n["id"] in attributed else 60
            objects.append({
                "type": "indicator", "spec_version": "2.1", "id": sdo_id("indicator"),
                "created": ts, "modified": ts,
                "name": f"{meta['actor']} - {n['value']}",
                "description": f"Open-source reconstructed {n['type']} "
                               f"(status: {n['status']}; sources: {', '.join(n.get('sources', []))}).",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern, "pattern_type": "stix",
                "valid_from": node_earliest.get(n["id"], ts), "confidence": conf,
                "created_by_ref": identity["id"],
                "object_marking_refs": [marking["id"]],
            })

    def rel(src, tgt, rtype, conf, desc):
        objects.append({
            "type": "relationship", "spec_version": "2.1", "id": sdo_id("relationship"),
            "created": ts, "modified": ts, "relationship_type": rtype,
            "source_ref": src, "target_ref": tgt, "confidence": conf,
            "description": desc, "created_by_ref": identity["id"],
        })

    # intrusion-set uses infrastructure
    rel(intrusion["id"], infra["id"], "uses", 80, "actor operates this infrastructure")
    # infrastructure consists-of each SCO
    for sid in node_to_sco.values():
        rel(infra["id"], sid, "consists-of", 70, "component of the reconstructed C2 set")
    # edges -> SROs
    for e in edges:
        if e["src"] == e["dst"]:
            continue
        s, t = node_to_sco.get(e["src"]), node_to_sco.get(e["dst"])
        if s and t:
            rel(s, t, REL_STIX.get(e["rel"], "related-to"),
                WEIGHT_CONFIDENCE.get(e["weight"], 30),
                f"{e['rel']} observed via {e['source']}")

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# 4) MISP event                
def build_misp(nodes, edges, attributed, meta) -> dict:
    attrs = []
    for n in nodes:
        if n["type"] not in NODE_MAP:
            continue
        mtype = NODE_MAP[n["type"]][1]
        value = f"AS{str(n['value']).lstrip('ASas')}" if n["type"] == "asn" else n["value"]
        to_ids = (n["id"] in attributed) or n["status"] == "confirmed"
        attrs.append({
            "type": mtype, "category": "Network activity", "value": value,
            "to_ids": to_ids, "distribution": "0",
            "comment": f"status={n['status']}; sources={', '.join(n.get('sources', []))}"
                       f"{'; feed-attributed' if n['id'] in attributed else ''}",
        })
    return {"Event": {
        "info": f"{meta['actor']} - reconstructed C2 infrastructure (open-source, snapshot {meta['snapshot']})",
        "date": time.strftime("%Y-%m-%d"),
        "threat_level_id": "2", "analysis": "2", "distribution": "0",
        "Orgc": {"name": meta["producer"]},
        "Tag": [{"name": "tlp:clear"}] + [{"name": a} for a in ([meta["actor"]] + meta["aliases"])],
        "Attribute": attrs,
    }}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Phase 4: graph + STIX/MISP from the pivot output.")
    ap.add_argument("--in", dest="in_dir", default="./outputs")
    ap.add_argument("--out", default="./outputs")
    ap.add_argument("--actor", default="NoName057(16)")
    ap.add_argument("--aliases", nargs="*", default=["DDoSia", "Dosia"])
    ap.add_argument("--snapshot", default="unlabeled")
    ap.add_argument("--producer", default="analyst")
    args = ap.parse_args(argv)

    in_dir, out_dir = Path(args.in_dir), Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    nodes, edges, manifest = load_graph(in_dir)
    if manifest.get("snapshot_label") and args.snapshot == "unlabeled":
        args.snapshot = manifest["snapshot_label"]
    meta = {"actor": args.actor, "aliases": args.aliases,
            "snapshot": args.snapshot, "producer": args.producer}
    attributed = feed_attributed_ids(edges)

    (out_dir / "graph.html").write_text(build_html(nodes, edges, attributed, meta), encoding="utf-8")
    (out_dir / "graph.dot").write_text(build_dot(nodes, edges, attributed, meta), encoding="utf-8")
    (out_dir / "iocs.stix.json").write_text(
        json.dumps(build_stix(nodes, edges, attributed, meta), indent=2), encoding="utf-8")
    (out_dir / "iocs.misp.json").write_text(
        json.dumps(build_misp(nodes, edges, attributed, meta), indent=2), encoding="utf-8")

    print(f"OK  {len(nodes)} nodes / {len(edges)} edges -> "
          f"graph.html, graph.dot, iocs.stix.json, iocs.misp.json in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
