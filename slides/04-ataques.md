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

# Lab 1 — Extraer el documento filtrado (LogiCorp)

<div class="cols">
<div>

**Proceso de extracción manual:**

<div class="list-item">Localizar la firma del archivo en el dump hexadecimal</div>
<div class="list-item">Archivos ZIP/DOCX comienzan con <code>PK</code> = <code>504B0304</code></div>
<div class="list-item">Limpiar el HEX: eliminar todo lo anterior y posterior a la firma</div>
<div class="list-item">Guardar como <code>.docx</code> → el documento interno de LogiCorp</div>

</div>
<div>

![w:380](./images/slide_109_img_72.png)

![w:380](./images/slide_109_img_73.png)

</div>
</div>

---

# El caso Ana — la máquina que recibió el fichero

<div class="warn-box">

Mientras se investigaba a Ana, el equipo de seguridad analizó el tráfico de la máquina que **recibió** `recipe.docx`: `annlaptop` (`192.168.1.159`).

El PCAP de esa máquina muestra tráfico SMTP saliente en texto claro — una cuenta de correo personal siendo usada desde la red corporativa.

</div>

---

# Lab 2 — LogiCorp: El email de Ann

<div class="lab-box">

**Escenario:**

El PCAP capturado en el perímetro muestra tráfico **SMTP saliente** desde `annlaptop` (`192.168.1.159`) en texto claro.

Quien lo envía es **Ann Dercover** — la misma máquina que recibió la receta. Está usando su cuenta personal AOL para coordinarse con su contacto externo.

**PCAP:** `Evidencia02.pcap`

</div>

**Buscamos:**

<div class="list-item">¿Cuál es el email desde el que escribe Ann?</div>
<div class="list-item">¿Y su contraseña? (en texto claro en el PCAP)</div>
<div class="list-item">¿Cuál es el email del contacto externo?</div>
<div class="list-item">¿Qué dos cosas le pide Ann a su contacto?</div>
<div class="list-item">¿Cuál es el nombre del fichero adjunto enviado?</div>
<div class="list-item">¿En qué ciudad y país quedan para encontrarse?</div>

---

# Lab 2 — Análisis de conversaciones

<div class="highlight-box">

**Estrategia:** Statistics → Conversations → TCP

2 conversaciones — abrimos la primera para analizar si hay correo electrónico

</div>

---

# Lab 2 — Primera conversación

<div class="highlight-box">

Follow TCP Stream → Email a `sec558@gmail.com`, asunto *"lunch next week"*

Ann dice que no puede quedar. **No es relevante** — es un email de cortesía (o distracción).

</div>

---

# Lab 2 — Segunda conversación (es la correcta)

<div class="cols">
<div>

**Follow TCP Stream → AUTH LOGIN:**

<div class="list-item">El servidor pide usuario y contraseña en <strong>Base64</strong></div>
<div class="list-item"><code>c25lYWt5ZzMza0Bhb2wuY29t</code> → <code>sneakyg33k@aol.com</code></div>
<div class="list-item"><code>NTU4cjAwbHo=</code> → <code>558r00lz</code></div>
<div class="list-item-sub">Base64 no es cifrado — cualquier decoder online lo lee</div>

</div>
<div>

**El email a `mistersecretx@aol.com`:**

<div class="list-item">Asunto: <em>rendezvous</em></div>
<div class="list-item">Cuerpo: <em>"Bring your fake passport and a bathing suit"</em></div>
<div class="list-item">Adjunto: <code>secretrendezvous.docx</code></div>

</div>
</div>

---

# Lab 2 — La ciudad del encuentro

<div class="highlight-box">

La ciudad **no está en el cuerpo del email** — está en el documento adjunto

**File → Export Objects → IMF** → guardamos el `.eml`

</div>

<div class="list-item">Abrir el <code>.eml</code> y extraer el adjunto</div>
<div class="list-item">El <code>secretrendezvous.docx</code> contiene una imagen de Google Maps</div>
<div class="list-item">El mapa muestra la dirección: <strong>Playa del Carmen, México</strong></div>

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

El análisis del caso LogiCorp nos lleva al origen: ¿cómo entró el atacante?

Un usuario de LogiCorp navegó a un sitio web comprometido. Este PCAP captura la sesión completa: desde la navegación normal hasta la descarga del malware.

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

Resumen de tráfico **unidireccional** que comparte:

<div class="list-item">IP origen</div>
<div class="list-item">IP destino</div>
<div class="list-item">Puerto origen</div>
<div class="list-item">Puerto destino</div>
<div class="list-item">Protocolo</div>

*RFC 3954: "secuencia unidireccional de paquetes con alguna propiedad común"*

</div>
<div>

**Los datos de un flujo contienen:**

<div class="list-item">Los 5 elementos de la quíntupla</div>
<div class="list-item">Flags TCP de la sesión</div>
<div class="list-item">Bytes y paquetes totales transferidos</div>
<div class="list-item">Hora de inicio, fin y duración</div>
<div class="list-item">Sensor que recolectó el flujo</div>

<div class="highlight-box">

Un flujo ≠ una conexión TCP — puede haber múltiples conexiones en un flujo o viceversa

</div>

</div>
</div>

---

# Análisis de Flujos — Usos

<div class="cols">
<div>

**El análisis de flujos se usa para:**

<div class="list-item">Identificar patrones en el tráfico</div>
<div class="list-item">Aislar actividad sospechosa</div>
<div class="list-item">Analizar protocolos de capas superiores</div>
<div class="list-item">Extraer información sobre comunicaciones</div>

</div>
<div>

**Estándares:**

<div class="list-item"><strong>NetFlow v5/v7/v9</strong> — Cisco (1996), ahora IETF</div>
<div class="list-item"><strong>IPFIX</strong> — "NetFlow v10", estándar abierto</div>
<div class="list-item"><strong>sFlow</strong> — muestreo con menor granularidad</div>
<div class="list-item"><strong>jFlow</strong> — implementación Juniper de sFlow</div>

</div>
</div>

---

# NetFlow v9 — Formato

<div class="center-content">

![w:700](./images/slide_081_img_65.png)

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

# SNMP vs *Flow

<div class="cols">
<div>

## SNMP (polling)

<div class="list-item">El gestor solicita información al dispositivo</div>
<div class="list-item">Necesita decidir <strong>cuándo</strong> hacer el poll</div>
<div class="list-item">Para cuando se hace el poll, la info puede no estar</div>
<div class="list-item">La correlación requiere múltiples peticiones</div>
<div class="list-item">El equipo no controla la cantidad de información</div>

</div>
<div>

## NetFlow (push)

<div class="list-item">La información se manda <strong>de forma asíncrona</strong></div>
<div class="list-item">Postprocesado posible en el router/switch</div>
<div class="list-item">La información se borra del equipo tras exportar</div>
<div class="list-item">Escalable — cada router/switch es un sensor</div>

<div class="highlight-box">

Los flows son la forma de **telemetría** enviada por routers y switches — cada uno es un sensor de red

</div>

</div>
</div>

---

# De Dónde se Obtienen los Flows

<div class="cols">
<div>

**Fuentes:**

<div class="list-item">Del <strong>router o switch</strong> directamente (NetFlow/sFlow)</div>
<div class="list-item">Generados a partir de un <strong>PCAP existente</strong></div>
<div class="list-item">Generados por <strong>probes de red</strong> que analizan el tráfico en tiempo real</div>

</div>
<div>

<div class="warn-box">

**Limitaciones:**

<div class="list-item">Capacidad del enlace analizado</div>
<div class="list-item">Recursos de hardware del dispositivo</div>
<div class="list-item">Muestreo (sFlow) → no todos los paquetes</div>
<div class="list-item">Similares a los desafíos del despliegue de Arkime</div>

</div>

</div>
</div>

---

# Análisis de Flujos — Técnicas

<div class="cols">
<div>

## Filtrado

<div class="list-item">Básico para reducir el espacio de análisis</div>
<div class="list-item">Aislar actividad por IP específica</div>
<div class="list-item">Filtrar por patrones de tráfico conocidos</div>
<div class="list-item">Usar un pequeño porcentaje para análisis detallado</div>

## Baseline

<div class="list-item">Los flows permiten mayor retención de datos</div>
<div class="list-item">Construir perfil de actividad "normal"</div>
<div class="list-item">Detectar cambios drásticos en el comportamiento de un host</div>

</div>
<div>

## Valores no deseados

<div class="list-item">Similar a las reglas de un IDS</div>
<div class="list-item">Lista de IPs, puertos o protocolos sospechosos</div>

## Búsqueda de patrones

<div class="list-item">Según IP, puertos, protocolos</div>
<div class="list-item">Intentos de conexión y escaneo de puertos</div>
<div class="list-item">Transferencias grandes y dirección de la transferencia</div>

<div class="highlight-box">

Anomalía clásica: Un host que normalmente envía 1MB/día de repente envía 10GB hacia el exterior

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

# Planificación del FPC

<div class="cols">
<div>

**Preguntas clave al desplegar:**

<div class="list-item">¿<strong>Dónde</strong> lo colocamos en la red?</div>
<div class="list-item">¿<strong>Qué</strong> va a monitorizar?</div>
<div class="list-item">¿Cuáles son las necesidades de <strong>retención</strong>?</div>
<div class="list-item">¿Qué hay de la <strong>redundancia y escalabilidad</strong>?</div>
<div class="list-item">¿Herramienta <strong>comercial o open source</strong>?</div>

</div>
<div>

**Colocación recomendada:**

<div class="list-item">En los <strong>límites entre redes confiables y no confiables</strong></div>
<div class="list-item-sub">Entre LAN e Internet</div>
<div class="list-item-sub">Entre Internet y la DMZ</div>
<div class="list-item-sub">Entre segmentos críticos internos</div>

<div class="warn-box">

FPC detrás de un FW que actúa como proxy → solo ve tráfico del proxy, no del cliente real

</div>

</div>
</div>

---

# Necesidades de Almacenamiento FPC

<div class="cols">
<div>

**Factores a considerar:**

<div class="list-item">¿Existe obligación legal de retención?</div>
<div class="list-item">¿Cuál es el <strong>tiempo medio de detección</strong> (MTTD)?</div>
<div class="list-item">¿SOC 24/7 o solo en horario de oficina?</div>
<div class="list-item">MTTD determina el **mínimo** tiempo de almacenamiento</div>

**Cálculo básico:**

```
Capacidad del enlace
× ocupación media del enlace
× segundos de almacenamiento
= bytes necesarios
```

</div>
<div>

<div class="highlight-box">

**Ejemplo:**

0.75 Gbps × 75% uso × 72h retención

= `0.75 × 0.75 × 72 × 3600 / 8 / 1024³`

≈ **~24 TB** de almacenamiento

</div>

<div class="warn-box">

**Ojo:** Además del espacio hay que tener en cuenta la **velocidad de escritura** de los discos

→ Puede requerir combinación SSD + HDD o RAID

</div>

</div>
</div>

---

# Infraestructura FPC

<div class="cols">
<div>

## Network TAPs (preferido)

<div class="list-item">Método preferido para FPC</div>
<div class="list-item">TAP físico — tráfico idéntico al original</div>
<div class="list-item">No requiere SPAN port</div>
<div class="list-item">No descarta paquetes en caso de saturación</div>

## NICs de captura

<div class="list-item">Tarjetas con chips especializados</div>
<div class="list-item">Capaces de procesar tráfico de alta velocidad</div>
<div class="list-item">Con timestamping hardware de alta precisión</div>

</div>
<div>

## Filtrado BPF en captura

<div class="list-item">No todo el tráfico en el TAP es útil</div>
<div class="list-item-sub">Tráfico del propio FPC</div>
<div class="list-item-sub">Tráfico de backup</div>
<div class="list-item">Filtros BPF en las NICs de captura</div>
<div class="list-item">Soportados por OpenFPC, Snort, Suricata, Arkime</div>

## Packet Brokers

<div class="list-item">Para tráfico excesivamente alto</div>
<div class="list-item">Balanceo de carga entre sensores</div>
<div class="list-item">Filtrado L2-L7 y descifrado</div>

</div>
</div>
