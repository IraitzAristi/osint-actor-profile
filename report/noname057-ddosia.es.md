# NoName057(16), perfil de actor de amenazas

> **TLP:CLEAR** · **Fecha del informe:** 2026-09-24 · **Analista:** Iraitz Aristi · **Versión:** 1.0
> **Corte de datos (instantánea):** 2026-09-20 · **Ventana de recolección:** infraestructura de C2 y gestión documentada, 2022 a 2026

**Alias:** DDoSia, Dosia (etiqueta de familia en ThreatFox) · **Primera aparición:** marzo de 2022 · **Origen / atribución:** colectivo hacktivista prorruso, infraestructura de gestión alojada en Rusia · **Motivación:** hacktivismo (ideológico / geopolítico prorruso)

<!-- Perfil reconstruido ENTERAMENTE a partir de reporting de fuentes abiertas y consultas pasivas.
 Sin interacción con el actor ni con ninguna infraestructura viva. Véase Alcance y metodología. -->

## Alcance y metodología

Este perfil reconstruye la infraestructura **conocida** de mando y control (C2), gestión y ataque de NoName057(16) solo a partir de fuentes abiertas, usando exclusivamente consultas pasivas. Cada dato procede de cachés, escáneres o bases de datos de terceros, Certificate Transparency (crt.sh), DNS pasivo (VirusTotal, AlienVault OTX), RDAP/WHOIS, RIPEstat (ASN/BGP) y Shodan InternetDB, más reporting publicado de vendors y de fuerzas del orden, en ningún momento se resolvieron los nombres del actor, se escanearon sus hosts ni se contactó con su infraestructura. Como el C2 operativo de DDoSia rota con rapidez (los servidores de control han tenido una vida media de días), el análisis se fija a una **instantánea documentada** del periodo 2022 a 2026 en lugar de a una vista en vivo: los indicadores se reportan con la ventana en la que las fuentes los observaron. Aquí "reconstruido" significa correlacionar indicadores ya publicados y afirmar la topología que esas fuentes documentaron, no descubrir infraestructura viva.

## Resumen ejecutivo

NoName057(16) es una operación hacktivista prorrusa que ejecuta campañas sostenidas de denegación de servicio distribuida (DDoS) contra Ucrania y estados alineados con la OTAN/UE desde marzo de 2022, usando una herramienta de ataque colaborativa llamada DDoSia en la que "voluntarios" remunerados aportan capacidad de ataque coordinados a través de Telegram. Su back end de gestión se ha documentado como una pila multinivel alojada en su mayoría en Rusia, mientras que el tráfico de ataque se concentra en un número reducido de proveedores de hosting occidentales. En julio de 2025, la Operación Eastwood de Europol desarticuló al grupo, pero el reporting y los indicadores nuevos hasta 2026 muestran que la infraestructura se está reconstituyendo. Este perfil consolida la topología de C2 y gestión documentada públicamente, la huella de la infraestructura de ataque y el modo de operar del grupo, con un enfoque defensivo.

### Valoraciones clave

- **NoName057(16) es casi con certeza una operación hacktivista con nexo ruso.** Su infraestructura de gestión está alojada en redes rusas y las instrucciones de objetivos de su C2 llevan marcas de tiempo en horario de Moscú (UTC+3), un indicador consistente de nexo ruso. *(confianza: alta)*
- **La operación es muy probablemente dirigida por operadores más que genuinamente colaborativa en la capa de infraestructura.** La gran mayoría del tráfico de ataque ha salido de un puñado de netblocks en dos proveedores interconectados (Stark Industries, MIRhosting), algo incoherente con una base de voluntarios amplia y distribuida de forma orgánica. *(confianza: moderada)*
- **El grupo es resiliente a la disrupción policial.** Pese a la Operación Eastwood (julio de 2025), en 2026 aparecen en feeds públicos indicadores de C2 nuevos atribuidos a DDoSia, lo que indica reconstitución más que desmantelamiento. *(confianza: alta)*
- **La concentración de la infraestructura de ataque es una oportunidad defensiva real.** Como tanto tráfico sale de un conjunto limitado e identificable de /24, el bloqueo dirigido reduce de forma material el impacto del ataque. *(confianza: moderada)*
- **El pivoting pasivo automatizado no reveló infraestructura nueva confirmada del actor más allá de lo ya documentado.** La reconstrucción se apoya en reporting publicado, el único candidato que la tubería sacó a la luz (`flotaero.info`) se rechazó por motivos temporales (véase Justificación del pivoting). *(confianza: alta, como afirmación sobre esta recolección)*

## Atribución y origen

El reporting de fuentes abiertas atribuye de forma consistente NoName057(16) a un colectivo hacktivista prorruso activo desde marzo de 2022, que ataca a estados y organizaciones que percibe como antirrusos. Dos indicadores de fuentes abiertas anclan el nexo ruso. Primero, la infraestructura de gestión documentada por Team Cymru se asienta en redes rusas (CLOUDASSETS, RU, AS212441 / AS216071). Segundo, las entradas de tareas de ataque servidas desde el C2 llevan horas de inicio que resuelven a UTC+3: un objetivo programado para las "10:00" en la lista de tareas del C2 se observó empezando a las 07:00 UTC, es decir, horario de Moscú, una señal conductual de la zona horaria de trabajo de los operadores.

En la capa del actor humano, la Operación Eastwood de Europol (julio de 2025) produjo dos detenciones (Francia y España), siete órdenes de detención europeas (seis emitidas por Alemania, una por España, seis contra personas que se cree que están en Rusia, dos de ellas valoradas como los operadores principales del grupo), 24 registros domiciliarios y notificaciones de responsabilidad penal a los seguidores y administradores del proyecto. Las cifras reportadas difieren ligeramente entre los comunicados oficiales, el de Europol cita más de 1.000 seguidores y 15 administradores, el de Eurojust cita 1.100 y 17, así que se da el rango en lugar de una única cifra. Esta es la atribución de nivel policial más sólida disponible en fuentes abiertas y confirma que la operación la dirigen individuos identificables y no es meramente nominal. *(confianza de atribución: alta para el nexo ruso y la existencia y roles de la operación, la identificación de individuos concretos sigue parcialmente sellada en fuentes abiertas.)*

## Motivación e ideología

El grupo tiene motivación ideológica: enmarca su actividad DDoS como represalia contra países y organizaciones que apoyan a Ucrania o que percibe como hostiles a Rusia. La coordinación y el reclutamiento discurren por Telegram, donde un mecanismo de recompensas paga a los contribuyentes en criptomoneda, superponiendo un incentivo económico modesto sobre el núcleo ideológico para sostener la participación. La notoriedad también es un motor: los ataques se reivindican públicamente para proyectar alcance y efecto.

## Objetivos

- **Sectores:** gobierno y ejército, finanzas, transporte y logística, medios, servicios públicos, turismo.
- **Geografías:** Ucrania y estados miembros de la OTAN y la UE. Entre los objetivos documentados hay entidades alojadas en Chequia, Dinamarca, Estonia, Alemania, Eslovaquia y Eslovenia, un caso concreto documentado es un ministerio del gobierno estonio (un servicio `*.ministeerium.ee`), que mostró una página de mantenimiento durante la ventana del ataque, lo que indica disrupción temporal.

## TTPs (MITRE ATT&CK)

En el momento del corte de datos no existía una entrada de grupo dedicada en ATT&CK para NoName057(16), las técnicas de abajo se mapean desde reporting de fuentes abiertas, cada una con su evidencia.

| Táctica | Técnica | ID | Procedimiento / evidencia (OSINT) |
| --- | --- | --- | --- |
| Resource Development | Develop Capabilities: Malware | T1587.001 | Cliente de ataque "DDoSia" propio, desarrollado y distribuido a los participantes (Sekoia, Gen, Team Cymru). |
| Resource Development | Acquire Infrastructure: Server | T1583.004 | Servidores de control y gestión en VPS de NETERRA (BG) y CLOUDASSETS (RU), capacidad de ataque en VPS de Stark/MIRhosting (Team Cymru). |
| Resource Development | Acquire Infrastructure: Dynamic DNS | T1583.001 | Dominios de DNS dinámico de NoIP (`*.myftp.org`) usados como fachada de C2 para la distribución de objetivos (Team Cymru). |
| Command and Control | Application Layer Protocol: Web | T1071.001 | El cliente DDoSia recupera listas de objetivos desde `/client/get_targets` por HTTP/80 (Team Cymru). |
| Command and Control | Web Service: Bidirectional | T1102.002 | Canales y bot de Telegram (`@noname05716`, `@nn05716chat`) para tareas, reclutamiento y pagos, tráfico del lado servidor hacia `api.telegram.org` (Team Cymru). |
| Impact | Network Denial of Service | T1498 | DDoS volumétrico sostenido contra servicios web de las víctimas (varios vendors, Europol). |
| Impact | Endpoint Denial of Service | T1499 | Inundaciones de capa de aplicación (HTTP/TCP) dirigidas a hosts y subdominios concretos según las tareas del C2 (Team Cymru). |

## Infraestructura (reconstruida a partir de fuentes abiertas)

### Infraestructura reconstruida

Los roles reflejan el diseño multinivel documentado: un C2 público o espejo que distribuye objetivos, un upstream que hace de fachada de una pila de gestión de los operadores, y la capa de ataque colaborativa.

| Indicador | Tipo | Rol | Ventana | Fuente | Confianza |
| --- | --- | --- | --- | --- | --- |
| 31.13.195.87 | IPv4 | C2 publicado (NETERRA, BG, AS34224) | operativo 2022-12-19 → | Team Cymru / SentinelLabs | alta |
| 87.121.52.9 | IPv4 | C2 upstream / espejo, TCP/5001 (NETERRA, BG) | 2023 | Team Cymru | alta |
| 77.91.122.69 | IPv4 | C2 anterior (retirado 2022-12-16) | pre-2022-12-16 | Team Cymru | alta |
| 109.107.184.11 | IPv4 | Gestión: almacén de datos MongoDB, TCP/27017 (CLOUDASSETS, RU) | 2023 | Team Cymru | alta |
| 185.173.37.220 | IPv4 | Gestión: bus de operadores RabbitMQ/Redis, TCP/5672,6379 (CLOUDASSETS, RU) | 2023 | Team Cymru | alta |
| 91.142.79.201 | IPv4 | Gestión: monitorización (Node Exporter, TCP/9100) (CLOUDASSETS, RU) | 2023 | Team Cymru | alta |
| tom56gaz6poh13f28.myftp.org | Dominio | Fachada de C2 por DDNS (NoIP) → 31.13.195.87 | 2023 | Team Cymru | alta |
| zig35m48zur14nel40.myftp.org | Dominio | Fachada de C2 por DDNS (NoIP) → 31.13.195.87 | 2023 | Team Cymru | alta |
| 185.122.187.217 | IPv4 | Avistamiento de C2 (AS9009), familia ThreatFox "Dosia", etiquetas noname057/DDoS | 2026-07 | abuse.ch ThreatFox | alta (feed) |
| 185.76.78.136 | IPv4 | Avistamiento de C2 (AS9009), puertos 22/80, etiquetas ThreatFox noname057/c2 | 2026-07 | abuse.ch ThreatFox | alta (feed) |
| api.telegram.org | Dominio | API legítima de Telegram usada como canal de bot, **contexto, no propiedad del actor** | 2023 | Team Cymru | n/d (contexto) |

**Infraestructura de ataque (capa colaborativa).** La gran mayoría del tráfico de ataque se ha concentrado en dos proveedores interconectados. Los ASN de origen más observados, Stark Industries (GB) y MIRHOSTING (NL), dominan, seguidos de SERVERASTRA AS (HU), ESERVER SK AS (SK), LEASEWEB (NL), VIRTUALDC (RU) y otros. Los /24 con más peso (Team Cymru, 2023) incluyen:

| Netblock | Proveedor | Volumen relativo |
| --- | --- | --- |
| 5.182.39.0/24 | Stark Industries, GB | muy alto |
| 94.131.109.0/24 | MIRHOSTING, NL | alto |
| 94.131.102.0/24 | Stark Industries, GB | alto |
| 5.182.37.0/24 | Stark Industries, GB | alto |
| 185.248.144.0/24 | Stark Industries, GB | moderado |
| 45.159.251.0/24 | Stark Industries, GB | moderado |
| 45.67.34.0/24 | Stark Industries, GB | moderado |
| 94.131.110.0/24 | MIRHOSTING, NL | moderado |
| 5.182.38.0/24 | SERVERASTRA AS, HU | moderado |
| 45.142.214.0/24 | Stark Industries, GB | moderado |

/24 publicados adicionales: 94.131.106.0/24, 94.131.99.0/24, 5.182.36.0/24, 80.92.204.0/24, 45.8.147.0/24.

> **Aviso de antigüedad:** estos netblocks reflejan observaciones de 2023. Team Cymru reportó más tarde que colaboraba con Stark Industries y una caída marcada del abuso de ese espacio de IP, y los avistamientos de C2 de 2026 están en un proveedor distinto (AS9009 / M247). Trata la tabla como una línea base histórica para ingeniería de detección, no como una lista de bloqueo viva, valídala contra la telemetría actual antes de aplicarla.

### Justificación del pivoting

Las semillas fueron las IP de C2 y gestión y los dominios DDNS documentados (Team Cymru, 2023, sobre la base de SentinelLabs) y dos avistamientos de C2 de 2026 de ThreatFox. La topología de gestión, que Team Cymru derivó de **telemetría de red (netflow)**, y que la herramienta pasiva no puede redescubrir, se afirmó como relaciones curadas por el analista, cada una con su fuente y su confianza. El pivoting pasivo automatizado (crt.sh, DNS pasivo de VirusTotal/OTX, RIPEstat, InternetDB) intentó después extender el grafo.

Las exclusiones deliberadas fueron tan importantes como las inclusiones. El C2 publicado `31.13.195.87` se **congeló** (enriquecido pero no pivotado) porque, tras haber sido expuesto públicamente, su historial de DNS pasivo está contaminado con dominios no relacionados. Los hosts con mucho fan out (una IP ligada a muchos dominios, o un certificado con muchos SAN), los rangos conocidos de parking o CDN (Sedo, Bodis, Cloudflare, AWS accelerator), los PTR de DNS inverso de proveedores y las direcciones no enrutables o bogon (por ejemplo `0.0.0.0`) se degradaron a contexto o se descartaron, lo que quitó del grafo dominios generados algorítmicamente y artefactos de escáneres de internet (por ejemplo, sondeos de Log4Shell de Nessus).

El único candidato que el pivoting automatizado sacó a la luz fue `flotaero.info`, a partir de un registro de DNS pasivo en la IP del bus de operadores `185.173.37.220`. Se **rechazó por motivos temporales**: el registro A tiene fecha de **2021-07-26**, unos ocho meses antes de que NoName057(16) surgiera (marzo de 2022) y unos dieciocho meses antes de que esa IP se documentara en un rol de actor (2023), así que casi con certeza es un **inquilino anterior** de la dirección, no infraestructura del actor. Aplicar la ventana de la instantánea (`--since 2022-01-01`) lo descarta automáticamente, se reporta aquí como ilustración del razonamiento temporal, no como pista. Resultado neto: el pivoting automatizado no produjo **ninguna infraestructura nueva confirmada** del actor, el valor del ejercicio es la validación y deduplicación automatizada de la topología documentada, y el rechazo transparente del ruido.

### Grafo de relaciones

Topología de C2 y gestión documentada (núcleo del grafo reconstruido). El grafo interactivo, la herramienta de pivoting pasivo y los paquetes de IOCs legibles por máquina están disponibles en el repositorio del proyecto: [osint-actor-profile](https://github.com/IraitzAristi/osint-actor-profile).

![Topología de C2 y gestión documentada](intel/figures/topology.png)

*Figura 1. Topología de C2 y gestión documentada (núcleo del grafo reconstruido).*

## Herramientas y malware

La capacidad principal es **DDoSia**, un cliente de DDoS creado a propósito y distribuido a los participantes, que reciben recompensa en criptomoneda. Los clientes recuperan listas de objetivos desde `/client/get_targets` por HTTP/80 desde las fachadas de C2 y DDNS. La coordinación, el reclutamiento y el pago discurren por Telegram (`@noname05716`, `@nn05716chat`), con llamadas del lado servidor a `api.telegram.org`. El back end de gestión es una pila de aplicación convencional, MongoDB (almacén de datos), RabbitMQ y Redis (bus de operadores y mensajes) y Prometheus Node Exporter (monitorización), lo que indica operadores con experiencia legítima en ingeniería de sistemas. Varios vendors (Sekoia, Recorded Future, Censys) describen un diseño de control multinivel en el que servidores de fachada de vida corta, provistos a los miembros vía bots de Telegram, protegen las capas superiores.

## Operaciones notables (cronología)

- **2022-03**, surge NoName057(16), empieza campañas DDoS contra objetivos que percibe como antirrusos.
- **2022-12-16**, se retira el C2 anterior `77.91.122.69`.
- **2022-12-19**, el C2 `31.13.195.87` entra en operación (NETERRA, BG).
- **2023-01-25**, ataque documentado a un ministerio del gobierno estonio (`*.ministeerium.ee`), el objetivo muestra una página de mantenimiento durante la ventana del ataque.
- **2023**, Team Cymru documenta la topología de gestión (C2 espejo → MongoDB / RabbitMQ/Redis / monitorización) vía telemetría de red.
- **2025-07-14/17**, Europol y Eurojust desarticulan al grupo con la **Operación Eastwood**: 2 detenciones, 7 órdenes de detención de la UE, 24 registros, más de 100 servidores afectados, con apoyo de abuse.ch y Shadowserver.
- **2026-07**, aparecen indicadores frescos de C2 de DDoSia en ThreatFox (`185.122.187.217`, `185.76.78.136`), lo que indica reconstitución.

## Estado actual y valoración

Como valoración de analista, NoName057(16) sigue activo pero disrumpido tras la Operación Eastwood (julio de 2025). Los dos avistamientos de C2 de 2026 son datables, ThreatFox registra first_seen de 2026-07-14 y 2026-07-27 (reporter: Deepfield), unos doce meses después del desmantelamiento, lo que respalda la actividad continuada (*confianza: alta*) y es consistente con una reconstitución (*confianza: moderada*). Esos avistamientos están en AS9009 (M247), hosting occidental, frente a la infraestructura rusa y búlgara documentada en 2022 a 2023. El desplazamiento a hosting occidental se ofrece como hipótesis, no como conclusión (*confianza: baja a moderada*), por dos razones: (1) M247 es de los sistemas autónomos más comunes en infraestructura de abuso europea, así que estar en M247 tiene una tasa base alta y discrimina poco por sí solo, y (2) el first_seen de ThreatFox es la fecha de envío al feed, no la fecha de inicio operativo, así que data la visibilidad pública y no el traslado en sí. Evidencia que lo elevaría: DNS pasivo fechado que sitúe estos hosts en M247 solo después de julio de 2025, o corroboración independiente del mismo patrón hacia el oeste. El C2 concreto de 2022 a 2023 documentado aquí está muy probablemente inactivo: las fachadas DDNS de NoIP ahora resuelven a direcciones de marcador de posición (`0.0.0.0` / un resolutor público), el comportamiento que NoIP muestra cuando un host dinámico está caído (*confianza: moderada*). La dependencia de la operación de un conjunto concentrado de netblocks de hosting occidental sigue siendo su debilidad más explotable (*confianza: moderada*).

![Resultados de ThreatFox para la familia Dosia (query malware:DDoSia), con los dos avistamientos de C2 de 2026](intel/figures/threatfox-ddosia.png)

*Figura 2. ThreatFox, familia Dosia / tag noname057. Query: `malware:DDoSia`. Consultado 2026-09-20. Fuente: abuse.ch. Indicadores mostrados tal como aparecen en la fuente.*

### Lagunas de inteligencia y salvedades analíticas

- **Pasivo y limitado a la instantánea.** El C2 rota en escala de días, este perfil es una reconstrucción documentada, no un mapa en vivo, y se desviará de la imagen operativa.
- **Ambigüedad posterior a la operación policial.** Algunas IP históricamente documentadas pueden haber sido reasignadas, sinkholeadas o puestas bajo control policial desde entonces, la presencia en un conjunto histórico de IOCs no implica propiedad viva del actor.
- **Candidato rechazado (retenido por transparencia).** `flotaero.info` se ligó a la IP del bus de operadores por un único registro de DNS pasivo con fecha 2021-07-26, anterior al actor, se valora como inquilino previo y se excluye por la ventana de la instantánea, no se arrastra como pista.
- **Hit de feed sin fecha.** La atribución de URLhaus sobre `87.121.52.9` no lleva marca de tiempo en el feed, así que se trata como corroboración histórica de uso malicioso, no como avistamiento fechado.
- **Opacidad del upstream.** El reporting señala que los hosts de operadores probablemente están más allá del bus RabbitMQ/Redis, pero su geolocalización impide más visibilidad por fuentes abiertas.
- **Decaimiento de feeds.** Los feeds públicos de IOCs expiran los indicadores antiguos (por ejemplo, la ventana de unos 6 meses de ThreatFox), lo que limita la cobertura por API del periodo 2024 a 2025, las semillas históricas se apoyan por tanto en reporting fechado de vendors.

## Recomendaciones defensivas

- **Bloquear o monitorizar los netblocks de ataque concentrados.** Como la mayoría del volumen de ataque ha salido de un conjunto limitado de /24 de Stark Industries y MIRHOSTING (véase la tabla), el filtrado o rate limiting a nivel de ASN y de netblock rinde una mitigación desproporcionada. Revísalo periódicamente, porque los rangos cambian.
- **Desplegar controles estándar de DDoS volumétrico.** Scrubbing o CDN upstream, rate limiting, umbrales de conexión y anomalía, y capacidad de absorber inundaciones de capa de aplicación en subdominios concretos (la granularidad a la que DDoSia asigna tareas).
- **Cazar la huella de la pila de gestión.** Para investigación o monitorización, la combinación de servicios documentada, distribución de objetivos en TCP/5001, MongoDB 27017, RabbitMQ 5672 / Redis 6379, Node Exporter 9100, es un patrón distintivo (aunque no único), trata las coincidencias como pistas que requieren corroboración, nunca como atribución por sí solas.
- **Monitorizar el patrón de tareas del cliente.** Las peticiones salientes a `/client/get_targets` por HTTP/80 hacia hosts de DNS dinámico o de vida corta pueden indicar un endpoint participante (posiblemente comprometido o interno) en tu red.
- **Seguir el reporting oficial.** Sigue los avisos de Europol y de los CERT nacionales para actualizaciones posteriores a Eastwood e indicadores refrescados, en lugar de confiar en feeds decaídos.

## Indicadores de compromiso (apéndice)

Los IOCs están defangeados para una lectura segura. La confianza es por indicador, trata las entradas de "contexto" como benignas o compartidas y las de "pista" como no verificadas.

| Indicador (defangeado) | Tipo | Contexto | Confianza |
| --- | --- | --- | --- |
| 31.13.195.87 | IPv4 | C2 publicado (2022 a 23), NETERRA BG | alta |
| 87.121.52.9 | IPv4 | C2 upstream/espejo, TCP/5001 | alta |
| 77.91.122.69 | IPv4 | C2 anterior (retirado 2022-12-16) | alta |
| 109.107.184.11 | IPv4 | Gestión: MongoDB 27017 (CLOUDASSETS RU) | alta |
| 185.173.37.220 | IPv4 | Gestión: RabbitMQ/Redis (CLOUDASSETS RU) | alta |
| 91.142.79.201 | IPv4 | Gestión: monitorización 9100 (CLOUDASSETS RU) | alta |
| tom56gaz6poh13f28.myftp.org | Dominio | Fachada de C2 por DDNS (NoIP) | alta |
| zig35m48zur14nel40.myftp.org | Dominio | Fachada de C2 por DDNS (NoIP) | alta |
| 185.122.187.217 | IPv4 | Avistamiento de C2 2026 (ThreatFox, "Dosia") | alta |
| 185.76.78.136 | IPv4 | Avistamiento de C2 2026 (ThreatFox, "Dosia") | alta |
| 5.182.39.0/24, 94.131.109.0/24, 94.131.102.0/24, … | Netblocks | Infraestructura de ataque (Stark/MIRhosting), véase la tabla completa | alta |
| api.telegram.org | Dominio | API legítima de Telegram (canal de bot), NO bloquear | contexto |

> Paquetes legibles por máquina (STIX 2.1 y MISP) y la herramienta de pivoting pasivo están disponibles en el repositorio del proyecto: [osint-actor-profile](https://github.com/IraitzAristi/osint-actor-profile).

## Convenciones analíticas

- **Confianza:** *baja* (fuente única o inferencia fuerte) · *moderada* (varias fuentes o corroboración parcial) · *alta* (múltiples fuentes independientes de alta calidad).
- **Lenguaje estimativo:** casi con certeza / muy probablemente / probablemente / plausible / improbable, evitando el binario "es / no es".
- **Gradación de fuentes (Admiralty/OTAN):** fiabilidad de la fuente de `A` a `F`, credibilidad de la información de `1` a `6`.

## Fuentes

1. Team Cymru, "A Blog with NoName" (2023), sobre la base de SentinelLabs, análisis de topología de gestión, C2, zona horaria e infraestructura de ataque. https://www.team-cymru.com/post/a-blog-with-noname *(grado: B2)*
2. Europol, "Global operation targets NoName057(16) pro-Russian cybercrime network" (Operación Eastwood, julio de 2025). https://www.europol.europa.eu/media-press/newsroom/news/global-operation-targets-noname05716-pro-russian-cybercrime-network, véase también Eurojust: https://www.eurojust.europa.eu/news/hacktivist-group-responsible-cyberattacks-critical-infrastructure-europe-taken-down *(grado: A1)*
3. abuse.ch, ThreatFox (familia "Dosia" / etiqueta noname057), avistamientos de C2 de 2026. https://threatfox.abuse.ch *(grado: B2)*
4. Sekoia TDR, serie de seguimiento del proyecto DDoSia. https://blog.sekoia.io/noname05716-ddosia-project-2024-updates-and-behavioural-shifts/ *(grado: B2)*
5. Recorded Future / Insikt Group, "Inside DDoSia" (2025). https://www.recordedfuture.com/research/anatomy-of-ddosia *(grado: B2)*
6. Censys, "Investigating the Infrastructure Behind DDoSia's Attacks" (2026). https://censys.com/blog/ddosia-infrastructure/ *(grado: B2)*
7. Gen Digital (Avast), análisis de DDoSia (2023). https://decoded.avast.io/ *(grado: B2)*

---
> Análisis basado únicamente en fuentes abiertas. Sin interacción con el actor ni con su infraestructura viva. Instantánea a fecha de 2026-09-20. **TLP:CLEAR**.
