#!/usr/bin/env python3
"""
osint_pivot.py -- Passive infrastructure pivoting for OSINT actor profiling.

Project : OSINT Infrastructure Mapping (snapshot-based actor profile)
Author  : IraitzAristi
License : MIT

WHAT IT DOES
------------
Given seed indicators (domains / IPv4 / certificate SHA-256), it enriches and
pivots them through FREE-TIER, third-party intelligence providers, assigns a
confidence weight to every relationship using the Phase-2 rubric, filters out
shared/benign infrastructure (CDN, cloud, dynamic-DNS), and writes a normalized
graph (nodes + edges, JSON and CSV) ready for Phase 4 (graph render + STIX/MISP).

SCOPE / PASSIVITY (read this)
-----------------------------
Open sources and PASSIVE queries only. Every lookup hits a third-party cache,
scanner or database. This tool does NOT, at any point:
  * resolve, dig or nslookup the actor's names,
  * scan ports or send any request to actor infrastructure,
  * fetch or execute any sample.
If a datum can only be obtained by touching the actor's live infra, it is out of
scope by design. This mirrors the report's "open-source only / zero-interaction"
disclaimer -- it is a deliberate methodological boundary, not a limitation.

GRACEFUL DEGRADATION
--------------------
A provider is used only if its key (env var) is present. With zero keys you still
get crt.sh + RDAP + RIPEstat + Shodan InternetDB. Add keys to widen coverage.

ENV VARS (see .env.example)
  ABUSECH_AUTH_KEY   ThreatFox + URLhaus (one key, get it at auth.abuse.ch)
  VT_API_KEY         VirusTotal public API
  OTX_API_KEY        AlienVault OTX
  VALIDIN_API_KEY    Validin Community (limited API)  [verify route/auth in docs]

USAGE
  python osint_pivot.py --seeds seeds.txt --depth 2 --snapshot "pre-Eastwood-2025-07" \
      --out ./outputs
  # seeds.txt: one indicator per line (domain, IPv4 or 64-hex cert sha256); '#' comments allowed
  python osint_pivot.py --seed-domain example.tld --seed-ip 203.0.113.10 --depth 1
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

import requests

try:
    from dotenv import load_dotenv  # optional convenience
    load_dotenv()
except Exception:  # dotenv is optional
    pass

LOG = logging.getLogger("osint_pivot")

# --------------------------------------------------------------------------- #
# Confidence rubric (Phase 2). Every edge carries one of these weights.        #
# A discovered node is CONFIRMED only with >=1 STRONG or >=2 independent        #
# MODERATE edges. WEAK edges are context only and never attribute on their own. #
# --------------------------------------------------------------------------- #
STRONG, MODERATE, WEAK = "strong", "moderate", "weak"

REL_WEIGHT = {
    "ioc_feed":            STRONG,    # already attributed in a public IOC feed
    "cert_san_sibling":    STRONG,    # shares a certificate (same SAN set) with a seed
    "cert_reuse":          STRONG,    # same certificate fingerprint served on multiple hosts
    "sslbl_listed":        STRONG,    # certificate blacklisted by abuse.ch SSLBL
    "pdns_coresolve":      MODERATE,  # historical A-record link (passive DNS) within window
    "whois_registrant":    MODERATE,  # shared, non-generic registrant email/org
    "crawl_fingerprint":   MODERATE,  # shared favicon/body hash (Validin crawl)
    "shodan_hostname":     MODERATE,  # PTR/hostname observed on the IP by Shodan
    "same_asn":            WEAK,      # same autonomous system  -> context only
    "shared_hosting":      WEAK,      # same netblock/provider  -> context only
    # analyst-curated / vendor-report-sourced relations (from --relations file):
    "reported_c2":         STRONG,    # named as C2 in a vendor report
    "resolves_to_reported":STRONG,    # domain->IP link asserted in a report
    "mirror_of":           STRONG,    # published C2 mirrors an upstream server
    "communicates_with":   STRONG,    # server-to-server link documented via telemetry
}

CONFIDENCE_RANK = {WEAK: 0, MODERATE: 1, STRONG: 2}

# --------------------------------------------------------------------------- #
# Shared-infrastructure filters. Nodes/edges touching these are demoted to     #
# context so a CDN IP or a dynamic-DNS apex never pulls the graph off-course.   #
# --------------------------------------------------------------------------- #
CDN_CLOUD_ASNS = {
    13335,   # Cloudflare
    16509, 14618,  # Amazon
    15169, 396982,  # Google
    8075,    # Microsoft
    20940, 16625,  # Akamai
    54113,   # Fastly
    13414,   # Twitter/X
    32934,   # Meta
}

# Registrable apexes of shared dynamic-DNS providers. Only the full subdomain is
# meaningful; the apex itself is shared by thousands of unrelated users.
DYNAMIC_DNS_APEXES = {
    "myftp.org", "no-ip.org", "no-ip.com", "hopto.org", "zapto.org",
    "ddns.net", "serveftp.com", "servebeer.com", "sytes.net", "redirectme.net",
    "duckdns.org", "dynu.com", "dynu.net", "freedns.afraid.org", "chickenkiller.com",
    "myddns.me", "gotdns.ch",
}

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")

# Data model                                                                   #
@dataclass
class Node:
    id: str
    type: str                 # domain | ipv4 | certificate | asn | registrant
    value: str
    sources: set = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None
    attrs: dict = field(default_factory=dict)
    status: str = "candidate"  # seed | confirmed | candidate | context

    def to_json(self) -> dict:
        d = asdict(self)
        d["sources"] = sorted(self.sources)
        return d


@dataclass
class Edge:
    src: str
    dst: str
    rel: str
    source: str
    weight: str
    observed_at: str
    first_seen: str | None = None
    last_seen: str | None = None
    note: str | None = None

    @property
    def key(self) -> tuple:
        return (self.src, self.dst, self.rel, self.source)


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple, Edge] = {}

    def add_node(self, ntype: str, value: str, source: str,
                 status: str | None = None, **attrs) -> Node:
        nid = f"{ntype}:{value.lower()}"
        node = self.nodes.get(nid)
        if node is None:
            node = Node(id=nid, type=ntype, value=value)
            self.nodes[nid] = node
        node.sources.add(source)
        for k, v in attrs.items():
            if v is not None:
                node.attrs.setdefault(k, v)
        if status and (status == "seed" or node.status == "candidate"):
            node.status = status
        return node

    def add_edge(self, src: Node, dst: Node, rel: str, source: str,
                 first_seen=None, last_seen=None, weight=None, note=None) -> None:
        weight = weight or REL_WEIGHT.get(rel, WEAK)
        e = Edge(src=src.id, dst=dst.id, rel=rel, source=source, weight=weight,
                 observed_at=now_iso(), first_seen=first_seen, last_seen=last_seen,
                 note=note)
        self.edges.setdefault(e.key, e)

    def resolve_confidence(self) -> None:
        """Promote nodes to 'confirmed'/'context' from incoming edge evidence."""
        incoming: dict[str, list[Edge]] = {}
        for e in self.edges.values():
            incoming.setdefault(e.dst, []).append(e)
        for nid, node in self.nodes.items():
            if node.status == "seed":
                continue
            # shared / parked / bogon infrastructure is context, never confirmed
            if node.attrs.get("shared_infra"):
                node.status = "context"
                continue
            if node.type == "ipv4":
                try:
                    if not ipaddress.ip_address(node.value).is_global:
                        node.status = "context"
                        continue
                except ValueError:
                    node.status = "context"
                    continue
            ev = incoming.get(nid, [])
            strong = sum(1 for e in ev if e.weight == STRONG)
            # count moderate evidence from *distinct* sources (independence)
            moderate_sources = {e.source for e in ev if e.weight == MODERATE}
            if strong >= 1 or len(moderate_sources) >= 2:
                node.status = "confirmed"
            elif ev and all(e.weight == WEAK for e in ev):
                node.status = "context"


# HTTP client: retries, per-host min interval, on-disk cache (snapshot-safe). 
class Http:
    def __init__(self, cache_dir: Path, min_interval: float = 1.0) -> None:
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "osint-pivot/1.0 (passive; research)"})
        self.cache = cache_dir
        self.cache.mkdir(parents=True, exist_ok=True)
        self.min_interval = min_interval
        self._last: dict[str, float] = {}

    def _throttle(self, host: str, override: float | None = None) -> None:
        gap = override if override is not None else self.min_interval
        wait = gap - (time.time() - self._last.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        self._last[host] = time.time()

    def get_json(self, url, headers=None, params=None, rate=None, host_key=None):
        return self._request("GET", url, headers=headers, params=params,
                             rate=rate, host_key=host_key)

    def post_json(self, url, headers=None, json_body=None, data=None,
                  rate=None, host_key=None):
        return self._request("POST", url, headers=headers, json_body=json_body,
                             data=data, rate=rate, host_key=host_key)

    def _request(self, method, url, headers=None, params=None, json_body=None,
                 data=None, rate=None, host_key=None):
        ck = hashlib.sha1(
            f"{method}{url}{params}{json_body}{data}".encode()
        ).hexdigest()
        cpath = self.cache / f"{ck}.json"
        if cpath.exists():
            try:
                return json.loads(cpath.read_text())
            except Exception:
                pass
        host = host_key or requests.utils.urlparse(url).netloc
        self._throttle(host, rate)
        for attempt in range(3):
            try:
                r = self.s.request(method, url, headers=headers, params=params,
                                   json=json_body, data=data, timeout=30)
                if r.status_code == 429:
                    time.sleep(5 * (attempt + 1))
                    continue
                if r.status_code >= 400:
                    LOG.debug("%s %s -> HTTP %s", method, url, r.status_code)
                    return None
                try:
                    payload = r.json()
                except ValueError:
                    payload = {"_raw": r.text}
                cpath.write_text(json.dumps(payload))
                return payload
            except requests.RequestException as ex:
                LOG.debug("request error (%s): %s", attempt, ex)
                time.sleep(2 * (attempt + 1))
        return None

    def get_text(self, url, rate=None):
        host = requests.utils.urlparse(url).netloc
        self._throttle(host, rate)
        try:
            r = self.s.get(url, timeout=30)
            return r.text if r.ok else None
        except requests.RequestException:
            return None


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_date(v) -> str | None:
    """Normalize a date to 'YYYY-MM-DD'. Handles epoch seconds (VT), ISO strings
    (OTX) and 'YYYY-MM-DD HH:MM:SS UTC' (ThreatFox). Returns None if unparseable."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    if re.fullmatch(r"\d{9,10}(\.\d+)?", s): # epoch seconds
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(float(s)))
        except (ValueError, OverflowError, OSError):
            return None
    m = re.match(r"(\d{4}-\d{2}-\d{2})", s) # leading ISO date
    return m.group(1) if m else None


# Helpers                                                                       
def classify_seed(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if HEX64.match(value):
        return "certificate"
    try:
        ipaddress.IPv4Address(value)
        return "ipv4"
    except ValueError:
        pass
    if "." in value and " " not in value:
        return "domain"
    return None


def registrable_apex(domain: str) -> str:
    # Lightweight apex heuristic (no external PSL dependency): last two labels,
    # or last three when the 2nd-to-last is a known 2-label suffix.
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    two_label_suffixes = {"co.uk", "org.uk", "gov.uk", "com.au", "co.jp"}
    if ".".join(parts[-2:]) in two_label_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_dynamic_dns_apex(domain: str) -> bool:
    return registrable_apex(domain) in DYNAMIC_DNS_APEXES


def is_cdn_cloud_asn(asn: int | str | None) -> bool:
    try:
        return int(str(asn).lstrip("AS")) in CDN_CLOUD_ASNS
    except (TypeError, ValueError):
        return False


# Fan-out caps: a single IP tied to many domains (or a cert carrying many SANs)
# is shared / multi-tenant / parked infrastructure, not the actor's. High fan-out
# is the #1 source of passive-DNS false positives, so we refuse to pivot through it.
SAN_FANOUT_MAX = 12 # distinct SAN siblings on a domain's certificates
PDNS_IP_FANOUT_MAX = 15 # distinct domains historically resolving to one IP
DOMAIN_IP_FANOUT_MAX = 15 # distinct IPs one domain has resolved to

# Known parking / sinkhole ranges: co-resolution here is noise, not attribution.
PARKING_NETWORKS = [ipaddress.ip_network(n) for n in (
    "91.195.240.0/24", # Sedo parking
    "208.91.197.0/24", # Sedo / Above.com
    "199.59.242.0/23", # Bodis
    "198.54.117.0/24", # Namecheap parking
    "15.197.128.0/17", # AWS Route53 domain parking / Global Accelerator
    "13.248.128.0/17", # AWS Global Accelerator (parking)
    "76.223.0.0/17", # AWS Global Accelerator (parking)
    "3.33.128.0/17", # AWS Route53 domain parking
)]


def is_parking_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PARKING_NETWORKS)


def is_provider_rdns(hostname: str, ip: str) -> bool:
    """True if hostname is the hosting provider's reverse-DNS for this IP
    (e.g. 136.78.76.185.static.edisglobal.com) -- context, not actor infra."""
    h = hostname.lower()
    octets = ip.split(".")
    joins = (".".join(octets), ".".join(reversed(octets)),
             "-".join(octets), "-".join(reversed(octets)))
    if any(j in h for j in joins):
        return True
    tokens = ("static", "dynamic", "dyn", "pool", "dsl", "broadband",
              "vps", "cust", "customer", "client", "in-addr", "hosted")
    return all(o in h for o in octets) and any(t in h for t in tokens)


# Providers. Each returns lightweight observations; the orchestrator turns      
# them into nodes/edges. All are PASSIVE (third-party data only).               
class Providers:
    def __init__(self, http: Http) -> None:
        self.http = http
        self.abusech = os.getenv("ABUSECH_AUTH_KEY")
        self.vt = os.getenv("VT_API_KEY")
        self.otx = os.getenv("OTX_API_KEY")
        self.validin = os.getenv("VALIDIN_API_KEY")
        # Validin: confirm exact route + auth scheme at docs.validin.com/reference
        # (Community tier = limited API). Defaults below are best-known values.
        self.validin_base = os.getenv("VALIDIN_BASE", "https://api.validin.com")
        self._sslbl_sha1: set[str] | None = None

    def enabled(self) -> list[str]:
        on = ["crt.sh", "rdap", "ripestat", "shodan-internetdb", "sslbl"]
        if self.abusech:
            on += ["threatfox", "urlhaus"]
        if self.vt:
            on.append("virustotal")
        if self.otx:
            on.append("otx")
        if self.validin:
            on.append("validin")
        return on

    # crt.sh (Certificate Transparency): domain -> SAN siblings
    def crtsh_sans(self, domain: str) -> list[dict]:
        out = []
        data = self.http.get_json(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            rate=2.0, host_key="crt.sh")
        for row in data or []:
            names = (row.get("name_value") or "").split("\n")
            for n in names:
                n = n.strip().lower().lstrip("*.")
                if n and n != domain and "." in n:
                    out.append({"name": n,
                                "not_before": row.get("not_before"),
                                "not_after": row.get("not_after")})
        return out

    # abuse.ch ThreatFox: is this indicator attributed?
    def threatfox(self, ioc: str) -> list[dict]:
        if not self.abusech:
            return []
        data = self.http.post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": self.abusech},
            json_body={"query": "search_ioc", "search_term": ioc},
            rate=1.0, host_key="threatfox")
        if not data or data.get("query_status") != "ok":
            return []
        return data.get("data", []) or []

    # abuse.ch URLhaus: malware URLs seen on a host
    def urlhaus_host(self, host: str) -> dict | None:
        if not self.abusech:
            return None
        data = self.http.post_json(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": self.abusech},
            data={"host": host}, rate=1.0, host_key="urlhaus")
        if not data or data.get("query_status") != "ok":
            return None
        return data

    # abuse.ch SSLBL: blacklisted certificate SHA-1s (feed, no key)
    def sslbl_sha1_set(self) -> set[str]:
        if self._sslbl_sha1 is not None:
            return self._sslbl_sha1
        self._sslbl_sha1 = set()
        text = self.http.get_text(
            "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", rate=5.0)
        for line in (text or "").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) >= 2 and HEX40.match(parts[1].strip()):
                self._sslbl_sha1.add(parts[1].strip().lower())
        return self._sslbl_sha1

    # VirusTotal: passive resolutions
    def vt_domain_resolutions(self, domain: str) -> list[dict]:
        if not self.vt:
            return []
        data = self.http.get_json(
            f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
            headers={"x-apikey": self.vt}, rate=16.0, host_key="virustotal") # ~4/min
        out = []
        for row in (data or {}).get("data", []):
            a = row.get("attributes", {})
            if a.get("ip_address"):
                out.append({"ip": a["ip_address"], "date": a.get("date")})
        return out

    def vt_ip_resolutions(self, ip: str) -> list[dict]:
        if not self.vt:
            return []
        data = self.http.get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
            headers={"x-apikey": self.vt}, rate=16.0, host_key="virustotal")
        out = []
        for row in (data or {}).get("data", []):
            a = row.get("attributes", {})
            if a.get("host_name"):
                out.append({"domain": a["host_name"], "date": a.get("date")})
        return out

    # AlienVault OTX: passive DNS
    def otx_pdns(self, kind: str, value: str) -> list[dict]:
        if not self.otx:
            return []
        seg = "domain" if kind == "domain" else "IPv4"
        data = self.http.get_json(
            f"https://otx.alienvault.com/api/v1/indicators/{seg}/{value}/passive_dns",
            headers={"X-OTX-API-KEY": self.otx}, rate=2.0, host_key="otx")
        return (data or {}).get("passive_dns", []) or []

    # Validin: historical passive DNS (Community = limited)
    def validin_pdns(self, kind: str, value: str) -> list[dict]:
        if not self.validin:
            return []
        # NOTE: confirm the exact path + auth header at docs.validin.com/reference.
        seg = "domains" if kind == "domain" else "ips"
        url = f"{self.validin_base}/api/axon/{seg}/{value}/dns/history"
        data = self.http.get_json(
            url, headers={"Authorization": f"Bearer {self.validin}"},
            rate=2.0, host_key="validin")
        # Best-effort normalization; adapt to the documented response shape.
        recs = (data or {}).get("records") or (data or {}).get("data") or []
        return recs if isinstance(recs, list) else []

    # Shodan InternetDB: keyless IP enrichment
    def internetdb(self, ip: str) -> dict | None:
        return self.http.get_json(
            f"https://internetdb.shodan.io/{ip}", rate=1.0, host_key="internetdb")

    # RDAP: registration + network org (no key)
    def rdap_domain(self, domain: str) -> dict | None:
        return self.http.get_json(f"https://rdap.org/domain/{domain}",
                                  rate=1.0, host_key="rdap")

    # RIPEstat: ASN for an IP (no key)
    def ripestat_asn(self, ip: str) -> dict | None:
        data = self.http.get_json(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip}, rate=1.0, host_key="ripestat")
        d = (data or {}).get("data", {})
        asns = d.get("asns") or []
        return {"asn": asns[0], "prefix": d.get("prefix")} if asns else None


# Orchestration: breadth-first pivot from the seeds.                            

class Pivoter:
    def __init__(self, providers: Providers, graph: Graph,
                 max_nodes: int = 400, freeze: set | None = None,
                 since: str | None = None, until: str | None = None) -> None:
        self.p = providers
        self.g = graph
        self.max_nodes = max_nodes
        self.visited: set[str] = set()
        # "frozen" values are enriched (attribution + ASN) but NEVER pivoted --
        # use for known-contaminated nodes (e.g. a publicly-outed C2 whose passive
        # DNS is polluted with unrelated domains).
        self.freeze: set[str] = {f.lower() for f in (freeze or set())}
        # snapshot window: drop dated passive-DNS observations outside it, so a
        # record predating the actor (e.g. a previous tenant of an IP) never enters.
        self.since = since
        self.until = until

    def _in_window(self, d: str | None) -> bool:
        if d is None:
            return True # dateless observation: cannot judge -> keep
        if self.since and d < self.since:
            return False
        if self.until and d > self.until:
            return False
        return True

    def run(self, seeds: list[tuple[str, str]], depth: int) -> None:
        frontier = []
        for ntype, value in seeds:
            n = self.g.add_node(ntype, value, source="seed", status="seed")
            frontier.append((n, 0))
        while frontier:
            node, d = frontier.pop(0)
            if node.id in self.visited or d > depth:
                continue
            if len(self.g.nodes) > self.max_nodes:
                LOG.warning("max-nodes (%s) reached; stopping expansion", self.max_nodes)
                break
            self.visited.add(node.id)
            LOG.info("pivot [d=%s] %s", d, node.id)
            new = self._expand(node)
            for child in new:
                if child.id not in self.visited:
                    frontier.append((child, d + 1))

    def _expand(self, node: Node) -> list[Node]:
        frozen = node.value.lower() in self.freeze
        if frozen:
            node.attrs["frozen"] = True
        if node.type == "domain":
            return self._expand_domain(node, frozen)
        if node.type == "ipv4":
            return self._expand_ip(node, frozen)
        return []

    def _expand_domain(self, node: Node, frozen: bool = False) -> list[Node]:
        dom, out = node.value, []

        # attribution check (feed) -- strengthens the seed itself
        for hit in self.p.threatfox(dom):
            node.attrs.setdefault("malware", hit.get("malware_printable"))
            node.attrs.setdefault("threatfox_tags", hit.get("tags"))
            self.g.add_edge(node, node, "ioc_feed", "threatfox",
                            first_seen=hit.get("first_seen"))

        uh = self.p.urlhaus_host(dom)
        if uh and uh.get("urls"):
            self.g.add_edge(node, node, "ioc_feed", "urlhaus")

        if frozen:
            return out # enrich-only: do not pivot a frozen (contaminated) node

        # CT logs: SAN siblings share a certificate -> STRONG, unless it is a
        # multi-tenant / shared cert with a large SAN set (that is noise).
        sans = [s for s in self.p.crtsh_sans(dom)
                if s["name"] != dom and not is_dynamic_dns_apex(s["name"])]
        distinct = {s["name"] for s in sans}
        if len(distinct) > SAN_FANOUT_MAX:
            node.attrs["shared_cert_sans"] = len(distinct)
            LOG.info("  skip crt.sh: %s SAN siblings (shared cert) for %s",
                     len(distinct), dom)
        else:
            for san in sans:
                child = self.g.add_node("domain", san["name"], source="crt.sh")
                self.g.add_edge(node, child, "cert_san_sibling", "crt.sh",
                                first_seen=san.get("not_before"),
                                last_seen=san.get("not_after"))
                out.append(child)

        # passive DNS: domain -> historical IPs (MODERATE)
        ip_hits = []
        for r in self.p.vt_domain_resolutions(dom):
            ip_hits.append((r["ip"], "virustotal", r.get("date")))
        for r in self.p.otx_pdns("domain", dom):
            if r.get("address"):
                ip_hits.append((r["address"], "otx", r.get("first")))
        for r in self.p.validin_pdns("domain", dom):
            ip = r.get("value") or r.get("ip")
            if ip:
                ip_hits.append((ip, "validin", r.get("first_seen")))
        distinct_ips = {ip for ip, _, _ in ip_hits}
        if len(distinct_ips) > DOMAIN_IP_FANOUT_MAX:
            node.attrs["ip_fanout"] = len(distinct_ips)
            LOG.info("  skip pDNS: %s IPs (CDN/parking churn) for %s",
                     len(distinct_ips), dom)
        else:
            for ip, src, when in ip_hits:
                if not is_parking_ip(ip):
                    out += self._link_ip(node, ip, src, when)

        # registration (context / registrant pivoting)
        self._annotate_rdap_domain(node)
        return out

    def _expand_ip(self, node: Node, frozen: bool = False) -> list[Node]:
        ip, out = node.value, []

        # attribution check (feed) -- confirms a known IOC and records context
        for hit in self.p.threatfox(ip):
            node.attrs.setdefault("malware", hit.get("malware_printable"))
            node.attrs.setdefault("threatfox_tags", hit.get("tags"))
            self.g.add_edge(node, node, "ioc_feed", "threatfox",
                            first_seen=hit.get("first_seen"))
        uh = self.p.urlhaus_host(ip)
        if uh and uh.get("urls"):
            self.g.add_edge(node, node, "ioc_feed", "urlhaus")

        # ASN / hosting (WEAK, context only)
        asn_info = self.p.ripestat_asn(ip)
        if asn_info:
            asn = asn_info["asn"]
            node.attrs["asn"] = asn
            node.attrs["prefix"] = asn_info.get("prefix")
            asn_node = self.g.add_node("asn", f"AS{asn}", source="ripestat")
            if is_cdn_cloud_asn(asn):
                asn_node.status = "context"
                node.attrs["shared_infra"] = True
            self.g.add_edge(node, asn_node, "same_asn", "ripestat")

        # Shodan InternetDB: port/tag enrichment
        idb = self.p.internetdb(ip)
        if idb:
            node.attrs["ports"] = idb.get("ports")
            node.attrs["tags"] = idb.get("tags")

        if frozen:
            return out # enrich-only: do not pivot a frozen (contaminated) node

        # IP -> domains, from Shodan hostnames + passive DNS. Gather first, then
        # apply fan-out cap: an IP tied to many domains is shared/parked infra ->
        # record as context and do NOT pivot (this is what stopped the blow-up).
        dom_hits = []  # (domain, source, when)
        for h in (idb or {}).get("hostnames", []) or []:
            dom_hits.append((h.lstrip("*."), "shodan", None))
        if not node.attrs.get("shared_infra") and not is_parking_ip(ip):
            for r in self.p.vt_ip_resolutions(ip):
                dom_hits.append((r["domain"], "virustotal", r.get("date")))
            for r in self.p.otx_pdns("ip", ip):
                if r.get("hostname"):
                    dom_hits.append((r["hostname"], "otx", r.get("first")))
        clean = [(d.lower().strip("."), s, w) for d, s, w in dom_hits
                 if "." in d and not is_dynamic_dns_apex(d)
                 and not is_provider_rdns(d, ip)]
        distinct_doms = {d for d, _, _ in clean}
        if node.attrs.get("shared_infra") or len(distinct_doms) > PDNS_IP_FANOUT_MAX:
            node.attrs["domain_fanout"] = len(distinct_doms)
            node.attrs["shared_infra"] = True
            LOG.info("  skip pDNS: %s domains (shared/parked IP) for %s",
                     len(distinct_doms), ip)
        else:
            for d, s, w in clean:
                dt = parse_date(w)
                if not self._in_window(dt):
                    continue # observation outside the snapshot window -> drop
                rel = "shodan_hostname" if s == "shodan" else "pdns_coresolve"
                dn = self.g.add_node("domain", d, source=s)
                self.g.add_edge(node, dn, rel, s, first_seen=dt, last_seen=dt)
                out.append(dn)
        return out

    # small linkers
    def _link_ip(self, dom_node: Node, ip: str, source: str, when) -> list[Node]:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return []
        if not addr.is_global: # drop bogons (0.0.0.0, private, reserved, etc.)
            return []
        dt = parse_date(when)
        if not self._in_window(dt): # drop observations outside the snapshot window
            return []
        ipn = self.g.add_node("ipv4", ip, source=source)
        self.g.add_edge(dom_node, ipn, "pdns_coresolve", source,
                        first_seen=dt, last_seen=dt)
        return [ipn]

    def _link_domain(self, ip_node: Node, domain: str, source: str, when) -> list[Node]:
        domain = domain.lower().strip(".")
        if "." not in domain or is_dynamic_dns_apex(domain):
            return []
        dn = self.g.add_node("domain", domain, source=source)
        self.g.add_edge(ip_node, dn, "pdns_coresolve", source,
                        first_seen=when, last_seen=when)
        return [dn]

    def _annotate_rdap_domain(self, node: Node) -> None:
        data = self.p.rdap_domain(node.value)
        if not data:
            return
        events = {e.get("eventAction"): e.get("eventDate")
                  for e in data.get("events", []) if isinstance(e, dict)}
        node.attrs.setdefault("registered", events.get("registration"))
        node.attrs.setdefault("registrar", _rdap_registrar(data))


def _rdap_registrar(data: dict) -> str | None:
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", [])
        if "registrar" in roles:
            for item in ent.get("vcardArray", [None, []])[1]:
                if item and item[0] == "fn":
                    return item[3]
    return None


# Output
def write_outputs(graph: Graph, out_dir: Path, manifest: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "nodes.json").write_text(
        json.dumps([n.to_json() for n in graph.nodes.values()], indent=2))
    (out_dir / "edges.json").write_text(
        json.dumps([asdict(e) for e in graph.edges.values()], indent=2))

    with (out_dir / "nodes.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "type", "value", "status", "sources",
                    "first_seen", "last_seen"])
        for n in graph.nodes.values():
            w.writerow([n.id, n.type, n.value, n.status,
                        "|".join(sorted(n.sources)), n.first_seen, n.last_seen])

    with (out_dir / "edges.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src", "dst", "rel", "weight", "source",
                    "first_seen", "last_seen", "note"])
        for e in graph.edges.values():
            w.writerow([e.src, e.dst, e.rel, e.weight, e.source,
                        e.first_seen, e.last_seen, e.note or ""])

    (out_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2))

    confirmed = sum(1 for n in graph.nodes.values() if n.status == "confirmed")
    attributed = len({e.dst for e in graph.edges.values() if e.rel == "ioc_feed"})
    LOG.info("wrote %s nodes (%s confirmed, %s feed-attributed) and %s edges to %s",
             len(graph.nodes), confirmed, attributed, len(graph.edges), out_dir)


def load_relations(path: str, graph: Graph) -> int:
    """Merge analyst-curated, report-sourced relations into the graph.

    CSV columns: src_type,src_value,rel,dst_type,dst_value,source,weight,note
    Each endpoint becomes a node; the edge carries the given source/weight so its
    provenance and confidence travel with it (e.g. a vendor's telemetry-based link
    that passive tooling cannot rediscover). '#'-prefixed lines are ignored.
    """
    added = 0
    text = Path(path).read_text(encoding="utf-8-sig")
    reader = csv.DictReader(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    for row in reader:
        try:
            src = graph.add_node(row["src_type"].strip(), row["src_value"].strip(),
                                 source=row["source"].strip())
            dst = graph.add_node(row["dst_type"].strip(), row["dst_value"].strip(),
                                 source=row["source"].strip())
        except (KeyError, AttributeError):
            LOG.warning("skipping malformed relation row: %r", row)
            continue
        note = (row.get("note") or "").strip() or None
        graph.add_edge(src, dst, row["rel"].strip(), row["source"].strip(),
                       weight=(row.get("weight") or "").strip() or None, note=note)
        added += 1
    LOG.info("merged %s analyst-curated relations from %s", added, path)
    return added


def load_seeds(args) -> list[tuple[str, str]]:
    raw: list[str] = []
    if args.seeds:
        # utf-8-sig transparently strips a BOM if PowerShell's Set-Content added one
        for line in Path(args.seeds).read_text(encoding="utf-8-sig").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                raw.append(line)
    raw += args.seed_domain or []
    raw += args.seed_ip or []
    raw += args.seed_cert or []
    seeds = []
    for value in raw:
        t = classify_seed(value)
        if t:
            seeds.append((t, value))
        else:
            LOG.warning("could not classify seed: %r (skipped)", value)
    return seeds


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Passive OSINT infrastructure pivoting (snapshot-based).")
    ap.add_argument("--seeds", help="file with one indicator per line")
    ap.add_argument("--seed-domain", action="append", help="add a domain seed")
    ap.add_argument("--seed-ip", action="append", help="add an IPv4 seed")
    ap.add_argument("--seed-cert", action="append", help="add a cert SHA-256 seed")
    ap.add_argument("--relations", help="CSV of analyst-curated relations to merge")
    ap.add_argument("--freeze", nargs="*", default=[],
                    help="IPs/domains to enrich but NOT pivot (contaminated nodes)")
    ap.add_argument("--since", help="drop passive-DNS observations before this date (YYYY-MM-DD)")
    ap.add_argument("--until", help="drop passive-DNS observations after this date (YYYY-MM-DD)")
    ap.add_argument("--depth", type=int, default=2, help="pivot depth (default 2)")
    ap.add_argument("--max-nodes", type=int, default=400)
    ap.add_argument("--snapshot", default="unlabeled",
                    help="label for the temporal snapshot, e.g. pre-Eastwood-2025-07")
    ap.add_argument("--out", default="./outputs")
    ap.add_argument("--cache", default="./.cache")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s")

    seeds = load_seeds(args)
    if not seeds:
        ap.error("no valid seeds provided (use --seeds / --seed-domain / --seed-ip)")

    http = Http(Path(args.cache))
    providers = Providers(http)
    LOG.info("providers enabled: %s", ", ".join(providers.enabled()))

    graph = Graph()
    pivoter = Pivoter(providers, graph, max_nodes=args.max_nodes,
                      freeze=set(args.freeze), since=args.since, until=args.until)
    pivoter.run(seeds, depth=args.depth)
    relations = load_relations(args.relations, graph) if args.relations else 0
    graph.resolve_confidence()

    manifest = {
        "generated_at": now_iso(),
        "snapshot_label": args.snapshot,
        "depth": args.depth,
        "window": {"since": args.since, "until": args.until},
        "seeds": [f"{t}:{v}" for t, v in seeds],
        "curated_relations": relations,
        "providers_enabled": providers.enabled(),
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "scope": "open-source, passive only; no interaction with actor infrastructure",
    }
    write_outputs(graph, Path(args.out), manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
