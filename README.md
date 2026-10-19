**Castellano** · [English](README.en.md)

# OSINT Infrastructure Mapping · NoName057(16) / DDoSia

> **TLP:CLEAR** · Reconstrucción de infraestructura y perfil de actor a partir de **fuentes abiertas** y **consulta pasiva**. Sin interacción con el actor ni con infraestructura viva.

Herramienta de pivoting pasivo y perfil de inteligencia de amenazas del grupo hacktivista prorruso **NoName057(16)** (proyecto **DDoSia**). Reconstruye la topología de C2, gestión y ataque **documentada públicamente**, correlacionando indicadores ya publicados por vendors y fuerzas del orden, y la enriquece con consultas pasivas. El valor no es descubrir infraestructura viva, es **validar, deduplicar y razonar** sobre lo documentado, y rechazar el ruido de forma transparente.

> **Documento de proceso (PDF):** [`docs/proceso_v1.pdf`](docs/proceso_v1.pdf) · cómo construí el informe, paso a paso.

**Informe completo:** [`report/noname057_ddosia_profile.md`](report/noname057_ddosia_profile.md) (ES: [`report/noname057-ddosia.es.md`](report/noname057-ddosia.es.md))
**Portfolio:** https://iraitzaristi.github.io

## Metodología

- **Solo fuentes abiertas y consulta pasiva.** Cada dato procede de cachés, escáneres o bases de datos de terceros: Certificate Transparency (crt.sh), DNS pasivo (VirusTotal, AlienVault OTX), RDAP/WHOIS, RIPEstat (ASN/BGP), Shodan InternetDB y feeds de abuse.ch (ThreatFox, URLhaus), más reporting publicado.
- **Cero interacción.** En ningún momento se resuelven los nombres del actor, se escanean sus hosts ni se contacta con su infraestructura. Es una frontera metodológica deliberada, no una limitación.
- **Actor documentado.** Las semillas son indicadores ya publicados (Team Cymru sobre la base de SentinelLabs, y avistamientos de 2026 de ThreatFox). La topología de gestión derivada de telemetría de red, que una herramienta pasiva no puede redescubrir, se afirma como relaciones curadas por el analista, cada una con su fuente y su nivel de confianza.
- **Instantánea, no vista en vivo.** El C2 operativo rota en escala de días, así que el análisis se fija a una instantánea documentada del periodo 2022 a 2026.

## Estructura del repositorio

```
.
├── osint_pivot.py              # herramienta de pivoting pasivo
├── build_report_artifacts.py   # genera grafos y bundles a partir de las salidas
├── seeds.txt                   # semillas (IOCs documentados)
├── relations_teamcymru.csv     # relaciones curadas por el analista (de reporting)
├── outputs/                    # ejemplo de ejecución (nodos, aristas, grafo, STIX, MISP)
├── report/
│   ├── noname057_ddosia_profile.md   # informe (EN)
│   ├── noname057-ddosia.es.md        # informe (ES)
│   ├── figures/                      # topología (graphviz, drawio, maltego)
│   └── screenshots/                  # evidencias del proceso
├── docs/                       # MALTEGO.md, narrativa del proceso
├── .env.example                # plantilla de claves (todas opcionales)
└── LICENSE
```

## Instalación y uso

Requiere Python 3. Dependencias mínimas (`requests`, y `python-dotenv` opcional):

```bash
pip install -r requirements.txt
```

Las **claves de API son opcionales**: la herramienta funciona con las fuentes sin clave (crt.sh, RDAP, RIPEstat, Shodan InternetDB, feeds SSLBL) y usa las que haya configuradas. Para añadir VirusTotal o abuse.ch, copia `.env.example` a `.env` y rellena lo que tengas.

Ejecución típica:

```bash
python osint_pivot.py --seeds seeds.txt --depth 2 --snapshot "pre-Eastwood-2025-07" --out ./outputs
```

O con semillas sueltas:

```bash
python osint_pivot.py --seed-domain example.tld --seed-ip 203.0.113.10 --depth 1
```

## Salidas

En `outputs/`: nodos y aristas (`nodes.csv/json`, `edges.csv/json`), el grafo (`graph.dot`, `graph.html`), los IOCs en formato legible por máquina (**STIX 2.1** en `iocs.stix.json`, **MISP** en `iocs.misp.json`) y un `run_manifest.json` con la traza de la ejecución. Las figuras de topología están en `report/figures/`.

## Desarrollo y autoría

Los dos scripts del proyecto, la herramienta de pivoting (`osint_pivot.py`) y el generador de grafos y bundles STIX/MISP (`build_report_artifacts.py`), se **desarrollaron con ayuda de IA** como asistente de programación. El código fue después **revisado, corregido, mejorado y simplificado por mí**. En `osint_pivot.py` ajusté la lógica de pivoting y de enriquecimiento, las exclusiones (rangos de parking/CDN, hosts con alto fan out, PTR de proveedores, direcciones bogon), el filtrado temporal por ventana de instantánea y el formato de salida. Entiendo y respondo por cada parte del código.

Eliminé el proveedor Validin, que estaba incluido en una primera versión: no pude verificar la ruta ni la autenticación de su API en el plan gratuito y no lo usé en la ejecución de ejemplo, así que preferí no mantener código sin probar. Las capturas del documento de proceso (v1) muestran el `.env.example` original, que todavía incluía Validin.

El **análisis del informe**, las **decisiones metodológicas** (qué pivotar, qué congelar, qué rechazar y por qué, como el candidato `flotaero.info` descartado por fecha) y las **valoraciones con nivel de confianza** son íntegramente míos.

## Licencia

El código (la herramienta, los scripts y los artefactos) se publica bajo la [Licencia MIT](LICENSE).

El informe de análisis y la documentación escrita (`report/`, `docs/`) son © 2026 Iraitz Aristi Lucambio y se publican bajo [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/): puedes compartirlos y adaptarlos citando la autoría.

## Aviso

Trabajo de inteligencia **defensiva** basado únicamente en fuentes abiertas, con fines de investigación y detección. Sin interacción con el actor ni con su infraestructura viva. Los indicadores se publican defangeados. **TLP:CLEAR.**
