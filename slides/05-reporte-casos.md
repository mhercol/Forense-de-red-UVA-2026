---


# Wireshark — Regex para detección de amenazas

<div class="cols">
<div>

```bash
# Archivos ejecutables descargados
http.request.uri matches
  "\.(exe|dll|ps1|bat|vbs)$"

# DGA - Dominios generados algorítmicamente
dns.qry.name matches
  "^[a-z]{15,}\.(com|net|org)$"

# Credenciales en texto claro
frame matches
  "(?i)(password|passwd|pwd)=.{3,}"
```

<div class="highlight-box">

`(?i)` = Case Insensitive — úsalo **siempre** en user-agents

</div>

</div>
<div>

```bash
# Tráfico de bots automatizados
http.user_agent matches
  "(?i)(bot|crawler|spider|scrapy)"

# SQL Injection en URLs
http.request.uri matches
  "(?i)(union|select|from|where)"

# Exfiltración Base64 vía DNS
dns.qry.name matches
  "^[A-Za-z0-9+/]{30,}="
```

</div>
</div>

---

# JA3/JA4 — TLS Client Fingerprinting

<div class="cols">
<div>

**¿Qué es JA3/JA4?**

<div class="list-item">Huella digital del <strong>TLS ClientHello</strong></div>
<div class="list-item">Basada en: versión, cipher suites, extensiones, curvas elípticas</div>
<div class="list-item">Identifica la implementación TLS del cliente</div>
<div class="list-item">Funciona <strong>sin descifrar el tráfico</strong></div>

**Malware conocido:**

<div class="list-item">Cobalt Strike: <code>e7d705a3286e19ea42f587b344ee6865</code></div>
<div class="list-item">Sliver C2: <code>51c64c77e60f3980eea90869b68c58a8</code></div>
<div class="list-item">Trickbot: <code>6734f37431670b3ab4292b8f60f29984</code></div>

</div>
<div>

<div class="highlight-box">

**Herramientas:**

<div class="list-item">ja3er.com — base de datos de hashes JA3</div>
<div class="list-item">Zeek con ja3.zeek script</div>
<div class="list-item">Arkime incluye JA3 en el SPI</div>
<div class="list-item">Wireshark muestra el ClientHello en detalle</div>

</div>

<div class="warn-box">

JA4 es la evolución de JA3 — más resistente a trivialidades como reordenar cipher suites

</div>

</div>
</div>

---

# Técnicas Modernas de Evasión (2025)

<div class="cols">
<div>

## Domain Fronting 2.0

<div class="list-item">SNI dice <code>cloudflare.com</code></div>
<div class="list-item">HTTP Host header apunta al C2</div>
<div class="list-item">El tráfico parece ir a Cloudflare</div>
<div class="list-item">Detección: Comparar SNI vs Host</div>

## DNS over HTTPS (DoH)

<div class="list-item">Resoluciones C2 vía <code>dns.google</code></div>
<div class="list-item">Parece tráfico HTTPS legítimo</div>
<div class="list-item">Imposible bloquear sin rompimiento TLS</div>

</div>
<div>

## Protocol Tunneling

<div class="list-item">SSH sobre HTTP</div>
<div class="list-item">VPN sobre ICMP</div>
<div class="list-item">C2 sobre DNS (DNS tunneling)</div>

## Time-based Evasion

<div class="list-item">Beaconing con <strong>jitter aleatorio</strong></div>
<div class="list-item">Evita la detección por intervalos fijos</div>
<div class="list-item">Solo el análisis estadístico lo detecta</div>

<div class="warn-box">

Todas estas técnicas abusan de protocolos legítimos — bloquear el protocolo bloquearía tráfico normal

</div>

</div>
</div>

---

# Detecting Lateral Movement

<div class="cols">
<div>

**Protocolos de movimiento lateral:**

<div class="list-item"><strong>SMB (445/tcp)</strong></div>
<div class="list-item-sub">Acceso a shares admin$, C$, IPC$</div>
<div class="list-item-sub">Transferencia de herramientas</div>

<div class="list-item"><strong>RDP (3389/tcp)</strong></div>
<div class="list-item-sub">Login desde servidor interno → sospechoso</div>

<div class="list-item"><strong>WMI (135/tcp)</strong></div>
<div class="list-item-sub">Remote command execution</div>

<div class="list-item"><strong>WinRM (5985/tcp)</strong></div>
<div class="list-item-sub">PowerShell remoting</div>

</div>
<div>

<div class="warn-box">

**Red Flag clásico:**

Servidor web → RDP → Domain Controller

Un servidor web **nunca** debería iniciar una sesión RDP hacia el DC

</div>

<div class="highlight-box">

**Detección en Wireshark:**

`tcp.port == 445 && smb2`

`tcp.port == 3389 && ip.src != [known admin IPs]`

</div>

</div>
</div>

---

# Movimiento Lateral — Qué buscar en el PCAP

<div class="cols">
<div>

## Autenticación sospechosa

```bash
# NTLM: quién se autenticó y desde dónde
ntlmssp.auth.username

# Kerberos: ticket solicitado para qué servicio
kerberos.CNameString
kerberos.sname

# Pass-the-Hash: NTLM sin Kerberos en dominio AD
# → señal de credencial robada o herramienta tipo Mimikatz
```

## RDP desde servidores

```bash
# Un servidor web nunca inicia RDP
ip.src == 10.0.1.50 && tcp.dstport == 3389
```

</div>
<div>

## SMB Admin Shares

```bash
# Acceso a shares de administración
smb2.filename contains "admin$"
smb2.filename contains "ADMIN$"
smb2.filename contains "C$"
smb2.filename contains "IPC$"
```

## WMI / WinRM (ejecución remota)

```bash
# WMI endpoint mapper → pivoting
tcp.dstport == 135 && ip.src != [admin_range]

# WinRM (PowerShell remoting)
tcp.dstport == 5985 || tcp.dstport == 5986
```

<div class="highlight-box">

**Patrón clásico de pivoting:**

`web_server (10.0.1.50)` → SMB `445` → `dc01 (10.0.0.10)`

Un servidor de aplicación **nunca** accede a shares del DC

</div>

</div>
</div>

---

# Encrypted Traffic Analysis (ETA)

<div class="cols">
<div>

## Detectar malware SIN descifrar payload

**Técnicas de Machine Learning:**

<div class="list-item"><strong>Packet Size Distribution</strong></div>
<div class="list-item-sub">Malware C2: distribución uniforme (mensajes fijos)</div>
<div class="list-item"><strong>Inter-Arrival Times</strong></div>
<div class="list-item-sub">C2 beaconing: intervalos constantes o con jitter mínimo</div>
<div class="list-item"><strong>TLS Certificate Analysis</strong></div>
<div class="list-item-sub">Self-signed, CN mismatch, expirado</div>
<div class="list-item"><strong>Flow Duration vs Bytes</strong></div>
<div class="list-item-sub">Flujo muy largo con muy pocos datos → beaconing</div>

</div>
<div>

**Herramientas:**

<div class="list-item"><strong>Joy</strong> (Cisco) — análisis estadístico de flows cifrados</div>
<div class="list-item"><strong>Mercury</strong> — fingerprinting de protocolos cifrados</div>
<div class="list-item"><strong>Zeek ML</strong> — scripts de detección basados en ML</div>
<div class="list-item"><strong>RITA</strong> — detección de beaconing en logs Zeek</div>

<div class="highlight-box">

ETA no reemplaza el descifrado, pero permite priorizar qué descifrar

</div>

</div>
</div>

---

# QUIC / HTTP/3 — El Nuevo Reto

<div class="cols">
<div>

**¿Qué es HTTP/3?**

<div class="list-item">HTTP/3 corre sobre <strong>QUIC</strong> (UDP)</div>
<div class="list-item">El 50%+ del tráfico web en 2025</div>
<div class="list-item">Usado por: Google, Facebook, Cloudflare</div>

**Desafíos forenses:**

<div class="list-item">No hay TCP handshake (sin SYN/ACK)</div>
<div class="list-item">Connection ID ofuscado</div>
<div class="list-item">0-RTT: la primera request ya va cifrada</div>
<div class="list-item">Wireshark puede diseccionarlo pero necesita las keys</div>

</div>
<div>

<div class="warn-box">

**Los filtros TCP clásicos no funcionan con QUIC:**

`tcp.port == 443` no captura QUIC

`udp.port == 443` sí

</div>

<div class="highlight-box">

**Estrategia:**

<div class="list-item">SSLKEYLOGFILE en el endpoint</div>
<div class="list-item">Análisis estadístico del flujo UDP</div>
<div class="list-item">Correlación con logs DNS</div>

</div>

</div>
</div>

---

# Memory Forensics + PCAP Correlation

<div class="cols">
<div>

**El poder de la correlación:**

Cuando tenemos volcado de memoria **Y** PCAP, podemos:

<div class="list-item">Identificar el <strong>proceso exacto</strong> que generó el tráfico malicioso</div>
<div class="list-item">Reconstruir la cadena completa: proceso → conexión → payload</div>
<div class="list-item">Confirmar si el proceso fue inyectado</div>

**Pipeline:**

<div class="list-item">Volcado de memoria → Volatility3: <code>windows.netscan</code></div>
<div class="list-item">Extraer: PID, proceso, IP:puerto</div>
<div class="list-item">Correlacionar con PCAP por IP:puerto y timestamp</div>
<div class="list-item">Identificar el proceso malicioso</div>
<div class="list-item">Reconstruir el timeline completo</div>

</div>
<div>

<div class="highlight-box">

**Ejemplo real:**

Memory: `powershell.exe (PID:4832) → 185.220.101.45:443`

PCAP confirma: HTTP POST a `185.220.101.45:443` con User-Agent de PowerShell

→ Conclusión: PowerShell fue el dropper

</div>

<div class="warn-box">

Sin correlación entre fuentes, un atacante con OPSEC puede confundir la atribución

</div>

</div>
</div>

---

# Zeek — El analizador de logs de red

<div class="cols">
<div>

**¿Qué hace Zeek?**

Analiza tráfico en tiempo real y genera **logs estructurados** — no es un IDS, es el motor que "escribe la historia" del tráfico.

## Logs clave para forense

<div class="list-item"><strong>conn.log</strong> — toda conexión TCP/UDP/ICMP (5-tupla, duración, bytes)</div>
<div class="list-item"><strong>dns.log</strong> — consultas y respuestas DNS</div>
<div class="list-item"><strong>http.log</strong> — método, host, URI, user-agent, código de respuesta</div>
<div class="list-item"><strong>ssl.log</strong> — handshakes TLS: versión, cipher, SNI, JA3/JA4</div>
<div class="list-item"><strong>files.log</strong> — ficheros transferidos con hash MD5/SHA256 y tipo MIME</div>
<div class="list-item"><strong>weird.log</strong> — anomalías de protocolo detectadas automáticamente</div>

</div>
<div>

<div class="highlight-box">

**PCAP vs Zeek logs:**

PCAP = la grabación completa

Zeek logs = el índice estructurado de esa grabación

Para investigar, buscas primero en los logs; el PCAP es el "ground truth" al que pivoteas cuando necesitas el payload.

</div>

<div class="warn-box">

**RITA** (Real Intelligence Threat Analytics) lee logs Zeek y detecta automáticamente beaconing, DGA y conexiones largas de baja frecuencia

</div>

</div>
</div>

---

# Zeek — Análisis Forense con Logs

<div class="cols">
<div>

## conn.log — la base de todo

```bash
# Conexiones largas (C2 beaconing)
zeek-cut id.orig_h id.resp_h duration bytes \
  < conn.log | sort -k3 -rn | head -20

# Volumen de datos hacia el exterior
zeek-cut id.orig_h id.resp_h orig_bytes \
  < conn.log | sort -k3 -rn | head -20
```

## files.log — detección de malware

```bash
# Ejecutables descargados con su hash
zeek-cut tx_hosts rx_hosts mime_type md5 sha256 \
  < files.log | grep "application/x-dosexec"
```

</div>
<div>

## dns.log — DGA y tunelización

```bash
# Consultas con hostname muy largo (posible DGA o tunelización)
zeek-cut query answers \
  < dns.log | awk 'length($1) > 40'

# Top dominios consultados
zeek-cut query < dns.log | sort | uniq -c | sort -rn
```

## ssl.log — TLS sospechoso

```bash
# Certificados self-signed
zeek-cut id.orig_h id.resp_h validation_status \
  < ssl.log | grep "self signed"

# JA3 fingerprint de cliente
zeek-cut id.orig_h ja3 ja3s < ssl.log
```

</div>
</div>

---


# Arkime (antes Moloch)

<div class="cols">
<div>

**Sistema open-source para FPC masivo:**

<div class="list-item">Captura, indexa y permite búsqueda en PCAPs</div>
<div class="list-item">Escala a terabytes de tráfico histórico</div>
<div class="list-item">Búsqueda en segundos gracias a Elasticsearch</div>

**Tres componentes:**

<div class="list-item"><strong>Capture</strong> — almacena PCAPs completos en disco</div>
<div class="list-item"><strong>Elasticsearch</strong> — indexa metadatos de sesiones (SPI)</div>
<div class="list-item"><strong>Viewer</strong> — interfaz web para búsqueda y análisis</div>

</div>
<div>

```bash
# Búsquedas en Arkime (ejemplos):

# TLS 1.3 a IPs rusas
protocols == tls &&
  tls.version == "TLSv1.3" &&
  country == "RU"

# DNS over HTTPS (DoH)
host == cloudflare-dns.com ||
  host == dns.google

# Beaconing detectado
packets >= 50 &&
  bytes < 10000 &&
  duration > 3600

# Exfiltración ICMP
protocols == icmp &&
  bytes.dst > 100000
```

</div>
</div>

---

# Arkime — Información SPI

<div class="cols">
<div>

**Session Profile Information — metadatos extraídos de cada sesión:**

## DNS
<div class="list-item">Direcciones IP resueltas</div>
<div class="list-item">Hostnames consultados</div>

## HTTP
<div class="list-item">Método (GET/POST/PUT...)</div>
<div class="list-item">Códigos de estado</div>
<div class="list-item">Cabeceras (User-Agent, Host, Referer)</div>
<div class="list-item">Tipo de contenido</div>

</div>
<div>

## TLS/SSL
<div class="list-item">Certificados (sujeto, emisor, SANs)</div>
<div class="list-item">Números de serie</div>
<div class="list-item">JA3/JA4 fingerprints</div>

## SSH
<div class="list-item">Nombre del cliente y versión</div>
<div class="list-item">Clave pública del servidor</div>

## SMTP
<div class="list-item">Cabeceras de correo (From, To, Subject)</div>
<div class="list-item">Asunto y tipo de contenido</div>

</div>
</div>

---

# Integración con el Stack de Seguridad Moderno

<div class="cols">
<div>

## Pipeline de Detección y Respuesta

**1. Captura**
<div class="list-item-sub">TAP/SPAN → Arkime (PCAP indexado)</div>
<div class="list-item-sub">Zeek/Suricata (logs enriquecidos)</div>

**2. Agregación**
<div class="list-item-sub">Flows → Elastic Stack / Splunk / Chronicle</div>

**3. Detección**
<div class="list-item-sub">SIEM Rules + ML → Alertas de anomalías</div>
<div class="list-item-sub">Beaconing, DGA, lateral movement</div>

</div>
<div>

**4. Investigación**
<div class="list-item-sub">Alerta SIEM → Pivot a Arkime con timestamp</div>
<div class="list-item-sub">Extraer PCAP de contexto</div>

**5. Enriquecimiento**
<div class="list-item-sub">IOCs → VirusTotal, AbuseIPDB, ThreatFox</div>
<div class="list-item-sub">Correlación con EDR (proceso, usuario)</div>

**6. Respuesta**
<div class="list-item-sub">Firewall API → Bloqueo automático</div>
<div class="list-item-sub">SOAR → Ticket de incidente + notificación</div>

<div class="highlight-box">

**Clave:** PCAP es el 'ground truth' cuando el SIEM duda

</div>

</div>
</div>

---

# LogiCorp — Búsqueda histórica con Arkime

<div class="warn-box">

**Ejemplo de búsqueda histórica:**

Con un IOC identificado — por ejemplo `spotsbill.com` del Lab 4 — buscamos en Arkime **cuándo empezó realmente** la actividad del malware.

</div>

<div class="cols">
<div>

**Query en Arkime:**

```
host == "spotsbill.com"
```

**Resultado hipotético:**

<div class="list-item">Primera sesión: días o semanas antes del reporte del usuario</div>
<div class="list-item">El malware llevaba tiempo activo sin ser detectado</div>
<div class="list-item">Permite reconstruir el timeline completo de la infección</div>

</div>
<div>

**Si tuviéramos EDR desplegado:**

<div class="list-item">Arkime identifica IP y puerto → cruzamos con logs de EDR</div>
<div class="list-item">El EDR revelaría el proceso responsable de la conexión</div>
<div class="list-item">Confirmaría el mecanismo de ejecución (process injection, service, etc.)</div>

<div class="highlight-box">

**El valor de combinar fuentes:**

PCAP + Arkime + EDR = atribución completa y timeline de 23 días que el SIEM solo no habría detectado

</div>

</div>
</div>

