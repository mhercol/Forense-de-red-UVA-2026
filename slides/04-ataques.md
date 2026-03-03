
---

# Kill Chain sobre la Red Corporativa

```
  INTERNET          FIREWALL EXT.        DMZ              FIREWALL INT.     USUARIOS / DC
─────────────────────────────────────────────────────────────────────────────────────────
[1] Recon          │                  │                 │                 │
    OSINT, scan    │                  │                 │                 │
                   │                  │                 │                 │
[3] Delivery ──────┼─► Mail Relay ───►│ email malicioso │                 │
                   │  Web Server      │ drive-by        │                 │
                   │                  │                 │                 │
[4][5] Exploit  ───┼──────────────────┼─────────────────┼──► Stewie-PC ◄──┤
       Install     │                  │                 │    payload      │
                   │                  │                 │    persistence  │
[6] C2   ◄─────────┼──────────────────┼─────────────────┼─── beacon out  │
         beaconing │                  │                 │                 │
                   │                  │                 │                 │
[7] Actions     ───┼──────────────────┼─────────────────┼────────────────►│ DC / files
    Lateral mvmt   │                  │                 │  SMB, RDP      │ exfil
─────────────────────────────────────────────────────────────────────────────────────────
  [2] Weaponization — offline, sin traza de red
```

---

# Kill Chain → ¿Qué buscamos en el PCAP?

<div class="cols">
<div>

<div class="phase-box">

## [1] Reconocimiento
<div class="list-item">Escaneos de puertos desde Internet</div>
<div class="list-item">Peticiones DNS inusuales al dominio</div>
<div class="highlight-box">SYN sin ACK · <code>nmap</code> fingerprinting</div>

</div>

<div class="phase-box">

## [3] Delivery
<div class="list-item">Email con adjunto/URL maliciosa</div>
<div class="list-item">HTTP a dominio recién registrado</div>
<div class="highlight-box">SMTP headers · <code>http.request</code> a dominios raros</div>

</div>

<div class="phase-box">

## [4–5] Exploit & Install
<div class="list-item">Descarga de payload (HTTP/S, DNS)</div>
<div class="list-item">Conexiones a CDNs inusuales</div>
<div class="highlight-box">JA3 fingerprint · PE en stream HTTP</div>

</div>

</div>
<div>

<div class="phase-box">

## [6] Command & Control
<div class="list-item">Beaconing periódico (intervalo fijo)</div>
<div class="list-item">DNS tunneling · HTTPS a IP pura</div>
<div class="highlight-box">Entropía de intervalos · <code>ssl.server_name</code> ≠ dominio conocido</div>

</div>

<div class="phase-box">

## [7] Acciones sobre objetivos
<div class="list-item">Lateral movement: SMB, RDP, WMI</div>
<div class="list-item">Exfiltración: volumen anómalo saliente</div>
<div class="highlight-box">Tráfico Este-Oeste inesperado · <code>smb2</code> · grandes transfers</div>

</div>

<div class="warn-box">

**LogiCorp:** tenemos evidencias de las fases 3, 6 y 7

</div>

</div>
</div>

---

# Lab 3 — LogiCorp: Reconocimiento de la red interna

<div class="lab-box">

**Escenario:**

Se detecta un escaneo activo en el segmento `10.42.42.0/24` de LogiCorp. Uno de los equipos de la red está lanzando peticiones a todos los demás — búsqueda de hosts y puertos abiertos.

Tenemos el PCAP capturado en ese segmento durante la ventana temporal del escaneo.

**PCAP:** `Evidencia03.pcap`

</div>

**Buscamos:**

<div class="list-item">¿Cuál es la IP del equipo desde el que se lanza el escaneo?</div>
<div class="list-item">¿Qué tipo de escaneo de puertos es el primero?</div>
<div class="list-item-sub">TCP SYN | TCP ACK | UDP | TCP Connect | TCP XMAS | TCP RST</div>
<div class="list-item">¿Cuáles son las IPs de los otros sistemas de LogiCorp descubiertos?</div>
<div class="list-item">¿Cuál es la MAC del equipo Apple encontrado?</div>
<div class="list-item">¿Cuál es la IP del sistema Windows? *(pista: TTL de Windows en Google)*</div>
<div class="list-item">¿Qué puertos estaban abiertos en el sistema Windows?</div>

---

# Lab 3 — Identificar el escáner

<div class="highlight-box">

**Statistics → Endpoints** — varios equipos involucrados

Por el **número de paquetes enviados**, identificamos el equipo que escanea

Para el tipo de escaneo: filtrar SYN sin ACK de respuesta → **TCP SYN (half-open)**

`tcp.flags.syn == 1 && tcp.flags.ack == 0`

</div>

---

# Lab 3 — Tipos de escaneo de puertos

<div class="list-item">
<strong>TCP Connect:</strong> Completa el 3-way handshake. Fácil de detectar.
</div>

<div class="list-item">
<strong>SYN Stealth:</strong> Envía solo el SYN y corta con RST tras recibir SYN/ACK. Menos visible.
</div>

<div class="list-item">
<strong>ACK Scan:</strong> Envía paquetes con flag ACK para identificar reglas de firewall.
</div>

<div class="list-item">
<strong>XMAS Scan:</strong> Usa muchas flags y analiza la respuesta en puertos abiertos para evadir detección tradicional.
</div>

<div class="list-item">
<strong>UDP Scan:</strong> Envía datagramas UDP vacíos y asume puerto abierto si no hay respuesta ICMP.
</div>

<div class="list-item">
<strong>NULL Scan:</strong> Envía paquetes TCP sin flags activadas y deduce el estado según si recibe o no un RST.
</div>

| Tipo | Flags TCP | Respuesta abierto | Detección |
|------|-----------|-------------------|-----------|
| TCP Connect | SYN→SYN/ACK→ACK | Handshake completo | Fácil (logs) |
| SYN Stealth | SYN→SYN/ACK→RST | Solo SYN/ACK | Moderada |
| ACK | ACK | RST | Mapeo firewall |
| XMAS | FIN+PSH+URG | Silencio | Difícil |
| UDP | UDP vacío | Sin respuesta | Muy difícil |
| NULL | Sin flags | Silencio | Difícil |

---

# Lab 3 — Resultados

<div class="cols">
<div>

**IPs activas y su OS por TTL:**

<div class="list-item">Statistics → Endpoints → IPv4</div>
<div class="list-item">TTL = 128 → Windows | TTL = 64 → Linux/Mac</div>
<div class="list-item">El escáner aparece con el recuento de paquetes más alto</div>

**Puertos abiertos en el Windows:**

<div class="list-item">Filtro: <code>tcp.flags == 0x12</code> (SYN-ACK = puerto abierto)</div>
<div class="list-item">El host Windows responde con SYN-ACK en los puertos que tiene abiertos</div>

</div>
<div>

**Identificar el equipo Apple:**

<div class="list-item">Statistics → Endpoints → Ethernet</div>
<div class="list-item">Los primeros 3 octetos de la MAC = OUI del fabricante</div>
<div class="list-item"><code>00:16:cb</code> → Apple Inc. (buscar en <em>Wireshark OUI lookup</em>)</div>

<div class="highlight-box">

Wireshark resuelve los OUI automáticamente en la columna de MACs

</div>

</div>
</div>

---

# Lab 4 — LogiCorp: Infección de un equipo corporativo

<div class="lab-box">

**Escenario:**

Revisando los logs de Logicorp, hemos dado con un trafico que es extraño.

Ances de cerrar la investigacion, analiza este PCAP.

**PCAP:** `Evidencia04.pcap` — contraseña del ZIP: `infected`

**Advertencia — hay malware real dentro**

</div>

**Buscamos:**

<div class="list-item">Fecha y hora exacta de la infección</div>
<div class="list-item">MAC del equipo Windows infectado</div>
<div class="list-item">IP asignada al equipo en el momento de la infección</div>
<div class="list-item">Hostname del equipo</div>
<div class="list-item">¿Con qué tipo de malware se infectó?</div>

---

# Lab 4 — Metodología de análisis de malware en PCAP

<div class="cols">
<div>

**1. Identificar el equipo afectado:**

<div class="list-item">Statistics → Endpoints → Ethernet → MAC + IP del cliente</div>
<div class="list-item">Hostname: filtro <code>dhcp.option.hostname</code> → aparece en el campo Option 12</div>
<div class="list-item">O añadir columna <em>Host</em> en Wireshark para verlo inline</div>

**2. Identificar el momento de la infección:**

<div class="list-item">Buscar la primera descarga sospechosa</div>
<div class="list-item">HTTP GET de <code>.exe</code>, <code>.dll</code>, <code>.zip</code>, <code>.js</code>, <code>.ps1</code></div>
<div class="list-item">Respuesta <code>Content-Type: application/x-msdownload</code> = ejecutable</div>

</div>
<div>

**3. Identificar el malware:**

<div class="list-item">Exportar el objeto HTTP descargado</div>
<div class="list-item">Calcular el hash MD5/SHA256</div>
<div class="list-item">Consultar VirusTotal, MalwareBazaar</div>
<div class="list-item">Analizar comportamiento de red post-infección</div>

<div class="warn-box">

Si aparece dominio con caracteres aleatorios = **DGA** (Domain Generation Algorithm)

</div>

</div>
</div>

---

# LogiCorp — Infección confirmada

<div class="warn-box">

**Aplicando la metodología anterior al caso LogiCorp:**

</div>

<div class="cols">
<div>

**1. Equipo afectado:**

<div class="list-item">Statistics → Endpoints → Ethernet</div>
<div class="list-item">Hostname en DHCP: <code>Stewie-PC</code></div>
<div class="list-item">IP en el momento de la infección: <code>172.16.4.193</code></div>

**2. Momento de infección:**

<div class="list-item">Visita a <code>www.homeimprovement.com</code> (sitio comprometido)</div>
<div class="list-item">Redirige a exploit kit → descarga <code>application/x-msdownload</code></div>
<div class="list-item">Primer EXE descargado de <code>194.87.234.129</code> a las 22:55 UTC</div>

</div>
<div>

**3. Malware identificado:**

<div class="list-item">C2 post-infección: <code>spotsbill.com</code></div>
<div class="list-item">Página de pago Bitcoin: <code>p27dokhpz2n7nvgr.1jw2lx.top</code></div>
<div class="list-item">Resultado: <strong>Ransomware</strong> (patrón Cerber)</div>

<div class="highlight-box">

**Timeline:** `homeimprovement.com` → exploit kit → EXE desde `194.87.234.129` → ransomware → C2 `spotsbill.com`

</div>

</div>
</div>

---

# Flujos de Información (Network Flows)

<div class="center-content">

## NetFlow / IPFIX / sFlow

**Telemetría de red a escala**

</div>

---

# Análisis de Flujos — Definición

<div class="cols">
<div>

**¿Qué es un flow (flujo)?**

Resumen de tráfico **unidireccional** que comparte la quíntupla:

<div class="list-item">IP origen / destino</div>
<div class="list-item">Puerto origen / destino</div>
<div class="list-item">Protocolo</div>

**Cada flujo contiene además:**

<div class="list-item">Flags TCP, bytes y paquetes totales</div>
<div class="list-item">Hora de inicio, fin y duración</div>
<div class="list-item">Sensor que recolectó el flujo</div>

</div>
<div>

**Para qué sirve en forense:**

<div class="list-item">Identificar patrones y aislar actividad sospechosa</div>
<div class="list-item">Detectar beaconing C2 por intervalos o volumen</div>
<div class="list-item">Descubrir exfiltración (transferencias anómalas hacia exterior)</div>
<div class="list-item">Construir un <strong>baseline</strong> de comportamiento normal</div>

<div class="highlight-box">

Estándares: **NetFlow** (Cisco) · **IPFIX** (IETF) · **sFlow** (muestreo)

Un flujo ≠ una conexión TCP

</div>

</div>
</div>

---

# PCAP vs *Flows — La Gran Diferencia

<div class="cols">
<div>

## PCAP

<div class="list-item">Como <strong>escuchar en un hilo telefónico</strong></div>
<div class="list-item">Todo el contenido — cabeceras + payload</div>
<div class="list-item">Muy costoso en almacenamiento</div>
<div class="list-item">Retención limitada (días/semanas)</div>

</div>
<div>

## *Flows

<div class="list-item">Como <strong>mirar la factura del teléfono</strong></div>
<div class="list-item">Solo metadatos — quién habló con quién</div>
<div class="list-item">Muy eficiente en almacenamiento</div>
<div class="list-item">Retención larga (meses/años)</div>

</div>
</div>

<div class="highlight-box">

Se puede aprender mucho de la "factura":

Quién → quién | protocolo | duración | velocidad | dirección de la transferencia

</div>

---

# Análisis de Flujos — Técnicas

<div class="cols">
<div>

## Baseline

<div class="list-item">Los flows permiten retención larga → construir perfil de actividad normal</div>
<div class="list-item">Detectar cambios drásticos en el comportamiento de un host</div>
<div class="list-item">Sin baseline no hay anomalía — sin anomalía no hay alerta</div>

## Beaconing

<div class="list-item">Conexiones periódicas de duración corta hacia el mismo destino</div>
<div class="list-item">Intervalo fijo = señal de C2 automatizado</div>
<div class="list-item">Visible en flows incluso si el payload está cifrado</div>

</div>
<div>

## Exfiltración por volumen

<div class="list-item">Transferencias anómalas hacia el exterior (bytes out >> bytes in)</div>
<div class="list-item">Un host que normalmente envía 1 MB/día de repente envía 10 GB</div>
<div class="list-item">La dirección importa: upload sospechoso &gt; download sospechoso</div>

<div class="highlight-box">

Los flows no tienen payload — pero **el comportamiento traiciona la intención**

</div>

</div>
</div>

---

# Full Packet Capture (FPC)

<div class="center-content">

## La captura total de paquetes

**Máxima visibilidad, máximo coste**

</div>

---

# Necesidad del FPC

<div class="cols">
<div>

**¿Por qué FPC?**

Casi todas las herramientas de seguridad usan un modelo de **seguridad negativa:**

<div class="list-item">Difícilmente detectan Zero-Days</div>
<div class="list-item">Fallan con malware nuevo (sin firmas)</div>
<div class="list-item">No detectan nada si no tienen una firma previa</div>

</div>
<div>

**Ventajas del FPC:**

<div class="list-item">Permite revisar <strong>todas las comunicaciones</strong> de todos los sistemas</div>
<div class="list-item">Detecta comunicaciones maliciosas que evaden otras herramientas</div>
<div class="list-item"><strong>Retrospección</strong> — reproducir tráfico antiguo con nuevas firmas</div>
<div class="list-item">Determinar si hubo ataque <strong>antes del parche</strong></div>
<div class="list-item">Extraer nuevas firmas y muestras de malware del tráfico</div>

</div>
</div>

---

# Planificación del FPC — Las 3 preguntas clave

<div class="cols">
<div>

## ¿Dónde capturar?

<div class="list-item">En los <strong>límites entre redes confiables y no confiables</strong></div>
<div class="list-item-sub">LAN ↔ Internet · Internet ↔ DMZ · segmentos críticos internos</div>

<div class="warn-box">

FPC detrás de un proxy → solo ve el tráfico del proxy, no del cliente real

</div>

## ¿Qué almacenar?

<div class="list-item">Todo lo posible, pero priorizar tráfico Norte-Sur</div>
<div class="list-item">Filtros BPF para excluir ruido (backups, monitorización interna)</div>

</div>
<div>

## ¿Durante cuánto tiempo?

<div class="list-item">Mínimo: el <strong>MTTD</strong> de tu organización (tiempo medio de detección)</div>
<div class="list-item">Regla práctica: si tardas 30 días en detectar una brecha, necesitas 30+ días de FPC</div>
<div class="list-item">El MTTD medio global en 2024 es de <strong>~194 días</strong></div>

<div class="highlight-box">

Cuanto mayor el MTTD, mayor el almacenamiento necesario — y más cara la investigación

</div>

</div>
</div>

---

# ¿Por qué casi nadie tiene FPC completo en producción?

<div class="cols">
<div>

**El problema no es técnico — es económico:**

<div class="list-item">Un enlace de 1 Gbps al 75% de uso genera <strong>~32 TB/día</strong></div>
<div class="list-item">Con retención de 72h → ~96 TB solo para ese enlace</div>
<div class="list-item">Una red corporativa media tiene varios enlaces de ese calibre</div>

**El cálculo:**

```
0.75 Gbps × 75% uso × 72h retención
= 0.75 × 0.75 × 259200 / 8 / 1024³
≈ 24 TB por enlace
```

</div>
<div>

<div class="warn-box">

**La realidad:**

La mayoría de organizaciones tiene FPC solo en los puntos críticos, con retención de 3–7 días — insuficiente dado el MTTD medio de 194 días

</div>

<div class="highlight-box">

**Alternativa práctica:**

FPC completo en perímetro (días) + Flows en toda la red (meses) + SIEM con logs (años)

Cada capa cubre lo que la anterior no puede retener

</div>

</div>
</div>

