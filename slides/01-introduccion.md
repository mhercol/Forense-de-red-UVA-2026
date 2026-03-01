---
marp: true
theme: uncover
paginate: true
backgroundColor: #1a1b26
color: #c0caf5
footer: 'Miguel Herrero | 2026'
style: |
  section {
    font-size: 20px;
    padding: 30px 50px;
    text-align: left;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    background-color: #1a1b26;
    color: #c0caf5;
  }

  h1 {
    color: #7aa2f7;
    border-bottom: 2px solid #f7768e;
    font-size: 1.4em;
    margin-bottom: 10px;
  }

  h2 {
    color: #bb9af7;
    font-size: 1.1em;
  }

  .cols {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    align-items: start;
  }

  .text-img {
    display: grid;
    grid-template-columns: 1.2fr 1fr;
    gap: 25px;
    align-items: center;
  }

  .img-text {
    display: grid;
    grid-template-columns: 1fr 1.2fr;
    gap: 25px;
    align-items: center;
  }

  .list-item {
    margin-left: 20px;
    margin-bottom: 8px;
    position: relative;
  }

  .list-item::before {
    content: "▸";
    color: #7aa2f7;
    position: absolute;
    left: -20px;
  }

  .list-item-sub {
    margin-left: 40px;
    margin-bottom: 6px;
    position: relative;
  }

  .list-item-sub::before {
    content: "▹";
    color: #bb9af7;
    position: absolute;
    left: -20px;
  }

  pre {
    font-size: 16px;
    background: #16161e;
    padding: 15px;
    border-left: 3px solid #7aa2f7;
    margin: 10px 0;
    white-space: pre-wrap;
  }

  code {
    background: #24283b;
    color: #9ece6a;
  }

  strong { 
    color: #ff9e64; 
    font-weight: bold; 
  }

  img {
    display: block;
    margin: 10px auto;
    border-radius: 8px;
    max-height: 400px;
    border: 2px solid #414868;
  }

  .highlight-box {
    background: #1f2335;
    border-left: 4px solid #7aa2f7;
    padding: 15px;
    margin: 10px 0;
    border-radius: 4px;
  }

  .center-content {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    height: 100%;
  }

  .cols3 {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 14px;
    align-items: start;
    flex: 1;
  }

  .phase-box {
    background: #1f2335;
    border: 1px solid #414868;
    border-top: 3px solid #7aa2f7;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.88em;
  }

  .phase-box h2 {
    font-size: 1.0em;
    margin-top: 0;
    margin-bottom: 6px;
  }

  .phase-box .list-item {
    margin-bottom: 4px;
  }

  .phase-box .highlight-box {
    padding: 8px 12px;
    margin: 8px 0 0 0;
    font-size: 0.9em;
  }

  .warn-box {
    background: #2d1b24;
    border-left: 4px solid #f7768e;
    padding: 12px 16px;
    border-radius: 4px;
    margin: 10px 0;
    color: #ff9e64;
  }

  .lab-box {
    background: #1a2415;
    border-left: 4px solid #9ece6a;
    padding: 15px 20px;
    border-radius: 4px;
    margin: 10px 0;
  }
---


# Fundamentos de Análisis de tráfico de red

<div class="center-content">

## Network Forensics 2026

**Análisis profesional de tráfico corporativo**

</div>

--- 

# Quien soy

<div class="text-img">
<div>

**Miguel Herrero Collantes**

<div class="list-item">Ingeniero técnico de telecomunicación - Sistemas electrónicos</div>
<div class="list-item">Ingeniero de Telecomunicación</div>
<div class="list-item"><strong>Responsable de Seguridad de red</strong> - EEAS (Bruselas) (2021-Actualidad)</div>
<div class="list-item"><strong>Analista de SOC</strong> - Consejo de la UE (Bruselas) (2017-2021)</div>
<div class="list-item"><strong>Consultor de ciberseguridad</strong> - Empresas financieras (2015-2019)</div>
<div class="list-item"><strong>Técnico de ciberseguridad</strong> - Incibe (2011-2017)</div>
<div class="list-item"><strong>Ingeniero de Red 3G/4G</strong> - Datatronics (2008-2011)</div>

Correo: mhercol[@]gmail[.]com

</div>
<div>

![w:300](./images/about.png)

</div>
</div>

---

# Contenido del curso

```
Sesión 1 (2h): Visibilidad, Captura y Protocolos Clave
  ▸ Arquitectura de captura: TAPs, SPAN, Zero Trust, Cloud
  ▸ PCAP, tcpdump, BPF y Wireshark
  ▸ Protocolos clave: ARP, TCP/IP, DNS, HTTP/S
  ▸ Lab 1 [LogiCorp]: Ana y la receta secreta (mensajería + extracción de archivo)
  ▸ Lab 2 [LogiCorp]: Ann Dercover — email personal desde la red corporativa

Sesión 2 (2h): Forense de Red y Caza de Amenazas
  ▸ TLS 1.3: descifrado con SSLKEYLOGFILE
  ▸ Metodología forense, fuentes y técnicas de análisis
  ▸ Lab 3 [LogiCorp]: Reconocimiento de la red interna
  ▸ NetFlow, Full Packet Capture, Arkime
  ▸ Lab 4 [LogiCorp]: Infección de Stewie-PC
```

<div class="highlight-box">

**Apéndice disponible:** 
Está pensado como **referencia para** las sesiones presenciales.
A. Modelo TCP/IP y encapsulamiento · B. Sistemas de numeración
C. Formato PCAP / pcapng · D. Herramientas de manipulación de PCAP
E. Protocolos de capa de enlace y red

</div>

---

# Mapa del Curso

```
 CASO INTEGRADOR: Empresa "LogiCorp" — Incidente en curso
 ──────────────────────────────────────────────────────────
 [1] CAPTURA                 ¿Cómo recogemos el tráfico?
      └─ TAPs · SPAN · Cloud · PCAP · tcpdump · BPF

 [2] HERRAMIENTAS            ¿Con qué lo analizamos?
      └─ Wireshark · Filtros · Exportación · Streams

 [3] PROTOCOLOS              ¿Qué vemos en el tráfico?
      └─ ARP · TCP · DNS · HTTP · TLS · Marco legal

 [4] ATAQUES                 ¿Cómo detectamos al atacante?
      └─ NetFlow · Arkime · JA3 · Kill Chain · ETA

 ══════════════════════════════════════════════════════════
 [+] AVANZADO (bonus)        Infraestructuras modernas
      └─ Cloud · Kubernetes · eBPF · Contenedores
 ──────────────────────────────────────────────────────────
```

---

# Caso Integrador — LogiCorp

<div class="highlight-box">

**Escenario que articula el curso:**

</div>

<div class="cols">
<div>

**La empresa:**

<div class="list-item"><strong>LogiCorp S.L.</strong> — empresa logística, 300 empleados</div>
<div class="list-item">Red corporativa on-prem</div>
<div class="list-item">Con seguridad básica</div>

**El incidente:**

<div class="list-item">Un usuario interno exfiltra informacion importante de la empresa</div>
<div class="list-item">IT captura traficos interesantes y nos piden ayuda para investigar el caso. </div>

</div>
<div>

<div class="highlight-box">

**Evidencias recibidas:**

<div class="list-item"><code>Evidencia01.pcap</code> — tráfico de la red WiFi corporativa</div>
<div class="list-item"><code>Evidencia02.pcap</code> — tráfico SMTP capturado en el gateway</div>
<div class="list-item"><code>Evidencia03.pcap</code> — captura del segmento de red interno</div>
<div class="list-item"><code>Evidencia04.pcap</code> — sesión de navegación del equipo infectado</div>

</div>

<div class="warn-box">

**Fases de la investigación:**

<div class="list-item">¿Cómo se exfiltró el activo crítico?</div>
<div class="list-item">¿Se usó email para coordinar con el exterior?</div>
<div class="list-item">¿Qué sistemas fueron reconocidos internamente?</div>
<div class="list-item">¿Cómo entró el malware en Stewie-PC?</div>

</div>

</div>
</div>

---

# Arquitectura de Captura Corporativa

<div class="cols">
<div>

## Visibilidad Norte-Sur

<div class="list-item">Tráfico que cruza el perímetro</div>
<div class="list-item">Firewalls, Proxies, Internet Gateway</div>

## Visibilidad Este-Oeste

<div class="list-item">Tráfico lateral entre servidores</div>
<div class="list-item">Microservicios</div>
<div class="list-item"><strong>El más difícil de capturar</strong></div>

</div>
<div>

## Acceso al Dato

<div class="highlight-box">

**TAP (Test Access Point)**

<div class="list-item">[OK] Copia física</div>
<div class="list-item">[OK] Infalible</div>
<div class="list-item">[X] Costoso</div>

**SPAN/Mirror Port**

<div class="list-item">[OK] Copia lógica</div>
<div class="list-item">[X] Puede perder paquetes</div>
<div class="list-item">[OK] Económico</div>

**Cloud**

<div class="list-item">VPC Flow Logs</div>
<div class="list-item">Virtual TAPs</div>

</div>

</div>
</div>

---

# El Desafío Zero Trust (ZT)

```
Cifrado Everywhere
  mTLS y TLS 1.3 ocultan el payload incluso internamente

Microsegmentación
  Tráfico lateral aislado, no pasa por Core Switch

Impacto Forense
  PCAP inútil sin llaves de sesión

Estrategia: SSLKEYLOGFILE
  Recolección de llaves en endpoints para descifrado
```

<div class="highlight-box">

**Desafío 2025**: El 80% del tráfico interno corporativo está cifrado

</div>

---

# PCAP (Packet Capture)

<div class="cols">
<div>

**¿Qué es PCAP?**

<div class="list-item"><strong>P</strong>acket <strong>Cap</strong>ture (captura de paquetes)</div>
<div class="list-item">Graba la actividad de red <strong>completa</strong> de las capas 2 a 7</div>

**Formato más común: libpcap**

<div class="list-item">[OK] Open source</div>
<div class="list-item">[OK] Disponible en *nix y Windows</div>
<div class="list-item">[OK] Librería en C</div>
<div class="list-item">[OK] Módulos en muchos lenguajes</div>

</div>
<div>

<div class="highlight-box">

**Usos principales:**

<div class="list-item">Investigación forense</div>
<div class="list-item">Debugging de red</div>
<div class="list-item">Análisis de malware</div>
<div class="list-item">Respuesta a incidentes</div>
<div class="list-item">Entrenamiento y educación</div>

</div>

</div>
</div>

---

# Quién usa PCAP

<div class="cols">
<div>

**Investigadores**

<div class="list-item">Acceder a información en crudo</div>
<div class="list-item">Análisis profundo de protocolos</div>

**Administradores de red**

<div class="list-item">Depurar problemas de red</div>
<div class="list-item">Optimización de rendimiento</div>

</div>
<div>

**Analistas de seguridad**

<div class="list-item">Analizar actividad de malware</div>
<div class="list-item">Caracterizar amenazas</div>

**Respuesta a incidentes**

<div class="list-item">Perseguir malware</div>
<div class="list-item">Recopilar evidencias</div>
<div class="list-item">Timeline reconstruction</div>

</div>
</div>

---

# Tcpdump

<div class="text-img">
<div>

**La herramienta de captura más usada**

<div class="list-item">[OK] Open Source</div>
<div class="list-item">[OK] Multiplataforma</div>
<div class="list-item">[OK] Basada en libpcap</div>

**Características:**

<div class="list-item">Usa sintaxis <strong>BPF</strong> (Berkeley Packet Filter)</div>
<div class="list-item">Muestra detalles en terminal o guarda en pcap</div>
<div class="list-item">Lee de la red o de un pcap existente</div>

</div>
<div>

```bash
# Captura básica
tcpdump -i eth0

# Guardar a archivo
tcpdump -i eth0 -w captura.pcap

# Con filtro BPF
tcpdump -i eth0 'host 10.0.0.1'

# Leer de archivo
tcpdump -r captura.pcap
```

</div>
</div>

---

# Lectura/Escritura de pcaps

<div class="cols">
<div>

**Tcpdump**

<div class="list-item">Línea de comandos</div>
<div class="list-item">Captura desde interfaz de red</div>

**Wireshark**

<div class="list-item">GUI completa</div>
<div class="list-item">Lee desde interfaz o archivo</div>

**Tshark**

<div class="list-item">Wireshark en línea de comandos</div>
<div class="list-item">Scriptable y automatizable</div>

</div>
<div>

**Scapy**

<div class="list-item">Herramienta en Python</div>
<div class="list-item">Leer, escribir y manipular paquetes</div>

**Libtins**

<div class="list-item">Librería C++</div>
<div class="list-item">Más rápida que libpcap</div>
<div class="list-item">Para procesamiento masivo</div>

</div>
</div>

---

# BPF (Berkeley Packet Filter)

<div class="cols">
<div>

**¿Qué es BPF?**

<div class="list-item">Sintaxis para <strong>filtrar paquetes</strong> rápidamente</div>
<div class="list-item">Usada por <strong>tcpdump</strong> y <strong>wireshark</strong> (tshark)</div>
<div class="list-item"><strong>Esencial</strong> para analistas</div>
<div class="list-item"><strong>Optimizada</strong> por el kernel</div>

<div class="highlight-box">

**Ventaja:**
Filtrado a nivel de kernel = Máximo rendimiento

</div>

</div>
<div>

```bash
# Ejemplo básico
tcpdump -i eth0 -w archivo.pcap \
  'host 10.10.10.1 and tcp port 443'
```

![w:400](./images/slide_029_img_17.png)

</div>
</div>

---

# BPF - Sintaxis básica

<div class="cols">
<div>

**Modificadores:**

**Type (Tipo)**

<div class="list-item">host - Dirección IP</div>
<div class="list-item">net - Red</div>
<div class="list-item">port - Puerto</div>

**Dir (Dirección)**

<div class="list-item">src - Origen</div>
<div class="list-item">dst - Destino</div>
<div class="list-item">(por defecto: ambos)</div>

**Proto (Protocolo)**

<div class="list-item">tcp, udp, icmp</div>
<div class="list-item">arp, ip, ip6</div>

</div>
<div>

**Operadores booleanos:**

<div class="list-item">and (&&)</div>
<div class="list-item">or (||)</div>
<div class="list-item">not (!)</div>
<div class="list-item">() para agrupar</div>

**Funciones:**

<div class="list-item">len - Número de bytes del paquete</div>

```bash
# Ejemplos combinados
host 10.0.0.1 and tcp port 80

src net 192.168.0.0/16 and \
  dst port 443

tcp and (port 80 or port 443)
```

</div>
</div>

---

# BPF - Filtros por tamaño y flags

```
Filtra por tamaño del paquete

  ▸ 'len <= 64'  ->  Paquetes pequeños (SYN, RST, DNS)
  ▸ 'len > 1400'  ->  Paquetes grandes (datos HTTP, exfiltración)

Filtra UDP/IP de origen hacia direcciones privadas

  ▸ 'udp[8:2] > 10 && ip[16:4] <= 0xC0A80000'

Captura solo paquetes TCP con SYN (handshakes)

  ▸ 'tcp[13] & 2 != 0'

Paquetes con carga útil HTTP (método GET/POST)

  ▸ 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
```

---

# BPF - Detección de amenazas

```
Captura paquetes con User-Agent sospechoso

  ▸ 'tcp[((tcp[12:1] & 0xf0) >> 2):11] = "curl"'

Tráfico TLS con certificate exchange

  ▸ 'tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16 && \
     tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x0b'

Paquetes con TTL bajo (posible IP spoofing)

  ▸ 'ip[8] < 10'

Filtra RST inmediatos tras SYN (port scan)

  ▸ 'tcp[13] = 0x14 && len = 40'
```

---

# BPF - Filtros avanzados

```
Paquetes UDP con payload superior a 100 bytes

  ▸ 'udp && len > 100'

Paquetes ICMP con código de error

  ▸ 'icmp[0] = 3 || icmp[0] = 11'

Tráfico a puertos no estándar (evasión)

  ▸ 'tcp dst portrange 1024-65535 && \
     tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'

Fragmentos IP (posible ataque de fragmentación)

  ▸ 'ip[6:2] & 0x1fff != 0'
```

---

# Wireshark - La herramienta esencial

<div class="cols">
<div>

**Wireshark**

<div class="list-item">Herramienta <strong>principal</strong> para análisis de red</div>
<div class="list-item"><strong>Open source</strong></div>
<div class="list-item">GUI completa e intuitiva</div>

**Características:**

<div class="list-item">[OK] Excelente parseo de protocolos</div>
<div class="list-item">[OK] Filtros potentes</div>
<div class="list-item">[OK] Búsqueda de cadenas de texto</div>
<div class="list-item">[OK] Exportación (archivos, objetos HTTP, descifrado)</div>

</div>
<div>

<div class="list-item">[OK] Estadísticas detalladas</div>
<div class="list-item">[OK] Datos expertos (Expert Info)</div>
<div class="list-item">[OK] Información sobre protocolos</div>
<div class="list-item">[OK] Análisis de conversaciones</div>
<div class="list-item">[OK] Seguimiento de streams (TCP, UDP, HTTP)</div>

<div class="highlight-box">

**Tip:**
Dominar Wireshark es fundamental para cualquier analista de red

</div>

</div>
</div>
