# NoName057(16), Threat Actor Profile

> **TLP:CLEAR** · **Report date:** 2026-09-24 · **Analyst:** Iraitz Aristi · **Version:** 1.0
> **Data cutoff (snapshot):** 2026-09-20 · **Collection window:** documented C2 & management infrastructure, 2022 to 2026

**Aliases:** DDoSia, Dosia (ThreatFox family label) · **First seen:** March 2022 · **Origin / attribution:** pro Russia hacktivist collective, management infrastructure hosted in Russia · **Motivation:** hacktivism (pro Russia ideological / geopolitical)

<!-- Profile reconstructed ENTIRELY from open source reporting and passive queries.
 No interaction with the actor or any live infrastructure. See Scope & methodology. -->

## Scope & methodology

This profile reconstructs the **known** command and control (C2), management and attack infrastructure of NoName057(16) from open sources only, using exclusively passive queries. Every datum comes from third party caches, scanners or databases, Certificate Transparency (crt.sh), passive DNS (VirusTotal, AlienVault OTX), RDAP/WHOIS, RIPEstat (ASN/BGP) and Shodan InternetDB, plus published vendor and law enforcement reporting, at no point were the actor's names resolved, its hosts scanned, or its infrastructure contacted. Because DDoSia's operational C2 rotates rapidly (control servers have averaged a lifespan of days), the analysis is fixed to a **documented snapshot** spanning 2022 to 2026 rather than a live view: indicators are reported with the window in which sources observed them. "Reconstructed" here means correlating already published indicators and asserting the topology those sources documented, not discovering live infrastructure.

## Executive summary

NoName057(16) is a pro Russia hacktivist operation that has run sustained distributed denial of service (DDoS) campaigns against Ukraine and NATO/EU aligned states since March 2022, using a crowdsourced attack tool called DDoSia in which paid "volunteers" contribute attack capacity coordinated through Telegram. Its management back end has been documented as a multi tier stack hosted largely in Russia, while attack traffic concentrates in a small number of Western hosting providers. In July 2025, Europol's Operation Eastwood disrupted the group, but reporting and fresh indicators through 2026 show the infrastructure reconstituting. This profile consolidates the publicly documented C2/management topology, the attack infrastructure footprint, and the group's tradecraft, with a defensive focus.

### Key judgments

- **NoName057(16) is almost certainly a Russia nexus hacktivist operation.** Its management infrastructure is hosted on Russian networks and its C2 targeting instructions are timestamped in Moscow Standard Time (UTC+3), a consistent Russia nexus indicator. *(confidence: high)*
- **The operation is very likely operator run rather than genuinely crowd driven at the infrastructure layer.** A large majority of attack traffic has originated from a handful of netblocks at two interlinked providers (Stark Industries, MIRhosting), which is inconsistent with a broad, organically distributed volunteer base. *(confidence: moderate)*
- **The group is resilient to law enforcement disruption.** Despite Operation Eastwood (July 2025), fresh C2 indicators attributed to DDoSia appear in public feeds in 2026, indicating reconstitution rather than dismantlement. *(confidence: high)*
- **The concentration of attack infrastructure is a genuine defensive opportunity.** Because so much traffic originates from a limited, identifiable set of /24s, targeted blocking materially reduces attack impact. *(confidence: moderate)*
- **Automated passive pivoting did not reveal confirmed new actor infrastructure beyond what is already documented.** The reconstruction rests on published reporting, the single candidate the pipeline surfaced (`flotaero[.]info`) was rejected on temporal grounds (see Pivot rationale). *(confidence: high, as a statement about this collection)*

## Attribution & origin

Open source reporting consistently attributes NoName057(16) to a pro Russia hacktivist collective active since March 2022, targeting states and organisations it perceives as anti Russia. Two open source indicators anchor the Russia nexus. First, the management infrastructure documented by Team Cymru sits on Russian networks (CLOUDASSETS, RU, AS212441 / AS216071). Second, the attack tasking entries served from the C2 carry start times that resolve to UTC+3: a target scheduled for "10:00" in the C2 task list was observed beginning at 07:00 UTC, i.e. Moscow Standard Time, a behavioural tell of the operators' working timezone.

On the human actor layer, Europol's Operation Eastwood (July 2025) produced two arrests (France and Spain), seven European arrest warrants (six issued by Germany, one by Spain, six against individuals believed to be in Russia, two of them assessed as the group's main operators), 24 house searches, and criminal liability notifications to the project's supporters and administrators. Reported figures differ slightly across the official releases, Europol's cites over 1,000 supporters and 15 administrators, Eurojust's cites 1,100 and 17, so the range is given rather than a single number. This is the strongest law enforcement grade attribution available in open sources and confirms the operation is run by identifiable individuals rather than being purely nominal. *(attribution confidence: high for the Russia nexus and the operation's existence/roles, individual naming remains partly sealed in open sources.)*

## Motivation & ideology

The group is ideologically motivated: it frames its DDoS activity as retaliation against countries and organisations supporting Ukraine or perceived as hostile to Russia. Coordination and recruitment run through Telegram, where a rewards mechanism pays contributors in cryptocurrency, layering a modest financial incentive over the ideological core to sustain participation. Notoriety is also a driver: attacks are publicly claimed to project reach and effect.

## Targeting

- **Sectors:** government and military, finance, transportation/freight, media, public utilities, tourism.
- **Geographies:** Ukraine and NATO/EU member states. Documented targets include entities hosted in Czechia, Denmark, Estonia, Germany, Slovakia and Slovenia, a specific documented case is an Estonian government ministry (a `*.ministeerium.ee` service), which displayed a maintenance page during the attack window, indicating temporary disruption.

## TTPs (MITRE ATT&CK)

No dedicated ATT&CK group entry existed for NoName057(16) as of the data cutoff, the techniques below are mapped from open source reporting, each with its evidence.

| Tactic | Technique | ID | Procedure / evidence (OSINT) |
| --- | --- | --- | --- |
| Resource Development | Develop Capabilities: Malware | T1587.001 | Custom "DDoSia" attack client developed and distributed to participants (Sekoia, Gen, Team Cymru). |
| Resource Development | Acquire Infrastructure: Server | T1583.004 | Control/management servers on VPS at NETERRA (BG) and CLOUDASSETS (RU), attack capacity on Stark/MIRhosting VPS (Team Cymru). |
| Resource Development | Acquire Infrastructure: Dynamic DNS | T1583.001 | NoIP dynamic DNS domains (`*.myftp.org`) used as C2 front for target distribution (Team Cymru). |
| Command and Control | Application Layer Protocol: Web | T1071.001 | DDoSia client fetches target lists from `/client/get_targets` over HTTP/80 (Team Cymru). |
| Command and Control | Web Service: Bidirectional | T1102.002 | Telegram channels/bot (`@noname05716`, `@nn05716chat`) for tasking, recruitment and payments, server side traffic to `api.telegram[.]org` (Team Cymru). |
| Impact | Network Denial of Service | T1498 | Sustained volumetric DDoS against victim web services (multiple vendors, Europol). |
| Impact | Endpoint Denial of Service | T1499 | Application layer floods (HTTP/TCP) targeting specific hosts/subdomains per C2 tasking (Team Cymru). |

## Infrastructure (reconstructed from open sources)

### Reconstructed infrastructure

Roles reflect the documented multi tier design: a public/mirror C2 that distributes targets, an upstream that fronts an operator management stack, and the crowdsourced attack layer.

| Indicator | Type | Role | Window | Source | Confidence |
| --- | --- | --- | --- | --- | --- |
| 31.13.195.87 | IPv4 | Published C2 (NETERRA, BG, AS34224) | operational 2022-12-19 → | Team Cymru / SentinelLabs | high |
| 87.121.52.9 | IPv4 | Upstream / mirror C2, TCP/5001 (NETERRA, BG) | 2023 | Team Cymru | high |
| 77.91.122.69 | IPv4 | Previous C2 (retired 2022-12-16) | pre-2022-12-16 | Team Cymru | high |
| 109.107.184.11 | IPv4 | Management: MongoDB data store, TCP/27017 (CLOUDASSETS, RU) | 2023 | Team Cymru | high |
| 185.173.37.220 | IPv4 | Management: RabbitMQ/Redis operator bus, TCP/5672,6379 (CLOUDASSETS, RU) | 2023 | Team Cymru | high |
| 91.142.79.201 | IPv4 | Management: monitoring (Node Exporter, TCP/9100) (CLOUDASSETS, RU) | 2023 | Team Cymru | high |
| tom56gaz6poh13f28.myftp.org | Domain | DDNS C2 front (NoIP) → 31.13.195.87 | 2023 | Team Cymru | high |
| zig35m48zur14nel40.myftp.org | Domain | DDNS C2 front (NoIP) → 31.13.195.87 | 2023 | Team Cymru | high |
| 185.122.187.217 | IPv4 | C2 sighting (AS9009), ThreatFox family "Dosia", tags noname057/DDoS | 2026-07 | abuse.ch ThreatFox | high (feed) |
| 185.76.78.136 | IPv4 | C2 sighting (AS9009), ports 22/80, ThreatFox tags noname057/c2 | 2026-07 | abuse.ch ThreatFox | high (feed) |
| api.telegram.org | Domain | Legitimate Telegram API used as bot channel, **context, not actor owned** | 2023 | Team Cymru | n/a (context) |

**Attack infrastructure (crowdsourced layer).** A large majority of attack traffic has concentrated in two interlinked providers. Top observed origin ASNs: Stark Industries (GB) and MIRHOSTING (NL) dominate, followed by SERVERASTRA AS (HU), ESERVER SK AS (SK), LEASEWEB (NL), VIRTUALDC (RU) and others. The heaviest /24 netblocks (Team Cymru, 2023) include:

| Netblock | Provider | Relative volume |
| --- | --- | --- |
| 5.182.39.0/24 | Stark Industries, GB | very high |
| 94.131.109.0/24 | MIRHOSTING, NL | high |
| 94.131.102.0/24 | Stark Industries, GB | high |
| 5.182.37.0/24 | Stark Industries, GB | high |
| 185.248.144.0/24 | Stark Industries, GB | moderate |
| 45.159.251.0/24 | Stark Industries, GB | moderate |
| 45.67.34.0/24 | Stark Industries, GB | moderate |
| 94.131.110.0/24 | MIRHOSTING, NL | moderate |
| 5.182.38.0/24 | SERVERASTRA AS, HU | moderate |
| 45.142.214.0/24 | Stark Industries, GB | moderate |

Additional published /24s: 94.131.106.0/24, 94.131.99.0/24, 5.182.36.0/24, 80.92.204.0/24, 45.8.147.0/24.

> **Aging caveat:** these netblocks reflect 2023 observations. Team Cymru later reported working with Stark Industries and a marked decrease in abuse of that IP space, and the 2026 C2 sightings sit on a different provider (AS9009 / M247). Treat the table as a historical baseline for detection engineering, not a current live blocklist, validate against present telemetry before enforcing.

### Pivot rationale

Seeds were the documented C2/management IPs and DDNS domains (Team Cymru, 2023, building on SentinelLabs) and two 2026 C2 sightings from ThreatFox. The management topology, which Team Cymru derived from **network telemetry (netflow)**, and which passive tooling cannot rediscover, was asserted as analyst curated relationships, each carrying its source and confidence. Automated passive pivoting (crt.sh, VirusTotal/OTX passive DNS, RIPEstat, InternetDB) then attempted to extend the graph.

Deliberate exclusions were as important as inclusions. The published C2 `31.13.195.87` was **frozen** (enriched but not pivoted) because, having been publicly outed, its passive DNS history is polluted with unrelated domains. High fan out hosts (an IP tied to many domains, or a certificate carrying many SANs), known parking/CDN ranges (Sedo, Bodis, Cloudflare, AWS accelerator), provider reverse DNS PTRs, and non routable/bogon addresses (e.g. `0.0.0.0`) were demoted to context or dropped, which removed algorithmically generated domains and internet scanner artefacts (e.g. Nessus Log4Shell probes) from the graph.

The single candidate the automated pivot surfaced was `flotaero.info`, from a passive DNS record on the operator bus IP `185.173.37.220`. It was **rejected on temporal grounds**: the A record is dated **2021-07-26**, roughly eight months before NoName057(16) emerged (March 2022) and some eighteen months before that IP was documented in an actor role (2023), so it is almost certainly a **previous tenant** of the address, not actor infrastructure. Enforcing the snapshot window (`--since 2022-01-01`) drops it automatically, it is reported here as an illustration of the temporal reasoning, not as a lead. Net result: automated pivoting produced **no confirmed new actor infrastructure**, the value of the exercise is the automated validation and deduplication of the documented topology, and the transparent rejection of noise.

### Relationship graph

Documented C2/management topology (core of the reconstructed graph). The interactive graph, the passive pivoting tool and the machine readable IOC bundles are available in the project repository: [osint-actor-profile](https://github.com/IraitzAristi/osint-actor-profile).

![Documented C2/management topology](intel/figures/topology.png)

*Figure 1. Documented C2 and management topology (core of the reconstructed graph).*

## Tooling & malware

The core capability is **DDoSia**, a purpose built DDoS client distributed to participants, who are rewarded in cryptocurrency. Clients pull target lists from `/client/get_targets` over HTTP/80 from the C2/DDNS fronts. Coordination, recruitment and payment run through Telegram (`@noname05716`, `@nn05716chat`), with server side calls to `api.telegram.org`. The management back end is a conventional application stack, MongoDB (data store), RabbitMQ + Redis (operator/message bus) and Prometheus Node Exporter (monitoring), indicating operators with legitimate systems engineering experience. Multiple vendors (Sekoia, Recorded Future, Censys) describe a multi tier control design in which short lived front servers, provided to members via Telegram bots, shield upstream tiers.

## Notable operations (timeline)

- **2022-03**, NoName057(16) emerges, begins DDoS campaigns against perceived anti Russia targets.
- **2022-12-16**, Previous C2 `77.91.122.69` retired.
- **2022-12-19**, C2 `31.13.195.87` becomes operational (NETERRA, BG).
- **2023-01-25**, Documented attack on an Estonian government ministry (`*.ministeerium.ee`), target displays a maintenance page during the attack window.
- **2023**, Team Cymru documents the management topology (mirror C2 → MongoDB / RabbitMQ/Redis / monitoring) via network telemetry.
- **2025-07-14/17**, Europol/Eurojust **Operation Eastwood** disrupts the group: 2 arrests, 7 EU arrest warrants, 24 searches, 100+ servers affected, abuse.ch and Shadowserver assist.
- **2026-07**, Fresh DDoSia C2 indicators appear in ThreatFox (`185.122.187.217`, `185.76.78.136`), indicating reconstitution.

## Current status & assessment

As an analytic judgment, NoName057(16) remains active but disrupted after Operation Eastwood (July 2025). The two 2026 C2 sightings are datable, ThreatFox records first_seen of 2026-07-14 and 2026-07-27 (reporter: Deepfield), roughly twelve months after the takedown, which supports continued activity (*confidence: high*) and is consistent with reconstitution (*confidence: moderate*). These sightings sit on AS9009 (M247), Western hosting, versus the Russian and Bulgarian infrastructure documented in 2022 to 2023. The shift to Western hosting is offered as a hypothesis, not a conclusion (*confidence: low to moderate*), for two reasons: (1) M247 is among the most common autonomous systems in European abuse infrastructure, so presence on M247 has a high base rate and discriminates weakly on its own, and (2) ThreatFox first_seen is the feed submission date, not the operational start date, so it dates public visibility rather than the move itself. Evidence that would raise it: dated passive DNS placing these hosts on M247 only after July 2025, or independent corroboration of the same westward pattern. The specific 2022 to 2023 C2 documented here is very likely dormant: the NoIP DDNS fronts now resolve to placeholder addresses (`0.0.0.0` / a public resolver), the behaviour NoIP shows when a dynamic host is offline (*confidence: moderate*). The operation's dependence on a concentrated set of Western hosting netblocks remains its most exploitable weakness (*confidence: moderate*).

![ThreatFox results for the Dosia family (query malware:DDoSia), showing the two 2026 C2 sightings](intel/figures/threatfox-ddosia.png)

*Figure 2. ThreatFox, Dosia family / noname057 tag. Query: `malware:DDoSia`. Consulted 2026-09-20. Source: abuse.ch. Indicators shown as they appear in the source.*

### Intelligence gaps & analytic caveats

- **Passive & snapshot bound.** The C2 rotates on a scale of days, this profile is a documented reconstruction, not a live map, and will drift from the operational picture.
- **Post takedown ambiguity.** Some historically documented IPs may since have been reassigned, sinkholed, or brought under law enforcement control, presence in a historical IOC set does not imply live actor ownership.
- **Rejected candidate (retained for transparency).** `flotaero.info` linked to the operator bus IP via a single passive DNS record dated 2021-07-26, predating the actor, it is assessed as a previous tenant and excluded by the snapshot window, not carried as a lead.
- **Dateless feed hit.** The URLhaus attribution on `87.121.52.9` carries no timestamp in the feed, so it is treated as historical corroboration of malicious use rather than a dated sighting.
- **Upstream opacity.** Reporting notes operator hosts likely sit beyond the RabbitMQ/Redis bus, but their geolocation prevents further open source visibility.
- **Feed decay.** Public IOC feeds expire older indicators (e.g. ThreatFox's ~6 month window), limiting API based coverage of the 2024 to 2025 period, historical seeds therefore rely on dated vendor reporting.

## Defensive recommendations

- **Block/monitor the concentrated attack netblocks.** Because a majority of attack volume has originated from a limited set of Stark Industries and MIRHOSTING /24s (see table), ASN- and netblock level filtering or rate limiting of those ranges yields disproportionate mitigation. Review periodically, as ranges shift.
- **Deploy standard volumetric DDoS controls.** Upstream scrubbing/CDN, rate limiting, connection/anomaly thresholds, and the ability to shed application layer floods on specific subdomains (the granularity DDoSia tasks at).
- **Hunt the management stack fingerprint.** For research/monitoring, the documented service combination, target distribution on TCP/5001, MongoDB 27017, RabbitMQ 5672 / Redis 6379, Node Exporter 9100, is a distinctive (if not unique) pattern, treat matches as leads requiring corroboration, never as standalone attribution.
- **Monitor for the client tasking pattern.** Outbound requests to `/client/get_targets` over HTTP/80 to dynamic DNS or short lived hosts can indicate a participating (possibly compromised or insider) endpoint on your network.
- **Track official reporting.** Follow Europol/national CERT advisories for post Eastwood updates and refreshed indicators rather than relying on decayed feeds.

## Indicators of Compromise (appendix)

IOCs are defanged for safe reading. Confidence is per indicator, treat "context" entries as benign/shared and "lead" entries as unverified.

| Indicator (defanged) | Type | Context | Confidence |
| --- | --- | --- | --- |
| 31.13.195.87 | IPv4 | Published C2 (2022 to 23), NETERRA BG | high |
| 87.121.52.9 | IPv4 | Upstream/mirror C2, TCP/5001 | high |
| 77.91.122.69 | IPv4 | Previous C2 (retired 2022-12-16) | high |
| 109.107.184.11 | IPv4 | Mgmt: MongoDB 27017 (CLOUDASSETS RU) | high |
| 185.173.37.220 | IPv4 | Mgmt: RabbitMQ/Redis (CLOUDASSETS RU) | high |
| 91.142.79.201 | IPv4 | Mgmt: monitoring 9100 (CLOUDASSETS RU) | high |
| tom56gaz6poh13f28.myftp.org | Domain | DDNS C2 front (NoIP) | high |
| zig35m48zur14nel40.myftp.org | Domain | DDNS C2 front (NoIP) | high |
| 185.122.187.217 | IPv4 | 2026 C2 sighting (ThreatFox, "Dosia") | high |
| 185.76.78.136 | IPv4 | 2026 C2 sighting (ThreatFox, "Dosia") | high |
| 5.182.39.0/24, 94.131.109[.]0/24, 94.131.102.0/24, … | Netblocks | Attack infrastructure (Stark/MIRhosting), see full table | high |
| api.telegram.org | Domain | Legitimate Telegram API (bot channel), do NOT block | context |

> Machine readable bundles (STIX 2.1 and MISP) and the passive pivoting tool are available in the project repository: [osint-actor-profile](https://github.com/IraitzAristi/osint-actor-profile).

## Analytic conventions

- **Confidence:** *low* (single source / heavy inference) · *moderate* (several sources or partial corroboration) · *high* (multiple independent, high quality sources).
- **Estimative language:** almost certainly / very likely / likely / plausible / unlikely, avoiding binary "is/is not".
- **Source grading (Admiralty/NATO):** source reliability `A` to `F`, information credibility `1` to `6`.

## Sources

1. Team Cymru, "A Blog with NoName" (2023), building on SentinelLabs, management topology, C2, timezone and attack infrastructure analysis. https://www.team-cymru.com/post/a-blog-with-noname *(grade: B2)*
2. Europol, "Global operation targets NoName057(16) pro Russia cybercrime network" (Operation Eastwood, July 2025). https://www.europol.europa.eu/media-press/newsroom/news/global-operation-targets-noname05716-pro-russian-cybercrime-network, see also Eurojust: https://www.eurojust.europa.eu/news/hacktivist-group-responsible-cyberattacks-critical-infrastructure-europe-taken-down *(grade: A1)*
3. abuse.ch, ThreatFox (family "Dosia" / tag noname057), 2026 C2 sightings. https://threatfox.abuse.ch *(grade: B2)*
4. Sekoia TDR, DDoSia project tracking series. https://blog.sekoia.io/noname05716-ddosia-project-2024-updates-and-behavioural-shifts/ *(grade: B2)*
5. Recorded Future / Insikt Group, "Inside DDoSia" (2025). https://www.recordedfuture.com/research/anatomy-of-ddosia *(grade: B2)*
6. Censys, "Investigating the Infrastructure Behind DDoSia's Attacks" (2026). https://censys.com/blog/ddosia-infrastructure/ *(grade: B2)*
7. Gen Digital (Avast), DDoSia analysis (2023). https://decoded.avast.io/ *(grade: B2)*

---
> Analysis based solely on open source reporting. No interaction with the actor or its live infrastructure. Snapshot as of 2026-09-20. **TLP:CLEAR**.
