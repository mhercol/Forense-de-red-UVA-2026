---


# Crear filtros en Wireshark

<div class="highlight-box">

**Opción 1:** Barra de filtros — sintaxis directa con **autocompletar**

</div>

<div class="center-content">

![w:620](./images/slide_034_img_33.png)

![w:620](./images/slide_034_img_34.png)

</div>

---

# Crear filtros en Wireshark

<div class="highlight-box">

**Opción 2:** Botón **Expression** — selección guiada por protocolo y campo

</div>

<div class="center-content">

![w:600](./images/slide_035_img_35.png)

![w:600](./images/slide_035_img_36.png)

</div>

---

# Crear filtros en Wireshark

<div class="highlight-box">

**Opción 3:** Click derecho sobre un paquete o campo → *Apply as Filter*

</div>

<div class="center-content">

![w:500](./images/slide_036_img_37.png)

![w:500](./images/slide_036_img_38.png)

</div>

---

# Crear filtros en Wireshark

<div class="center-content">

![w:600](./images/slide_036_img_39.png)

![w:600](./images/slide_036_img_40.png)

</div>

---

# Filtros de lectura (Display Filters)

<div class="cols">
<div>

**Al abrir un PCAP** se puede aplicar un filtro de lectura:

<div class="list-item">Solo aparecen los paquetes que cumplen las condiciones</div>
<div class="list-item">Útil para <strong>reducir PCAPs grandes</strong></div>
<div class="list-item">No destruye datos — se puede quitar el filtro</div>

<div class="highlight-box">

**Diferencia clave:**

`Capture Filter` = filtra durante la captura (BPF)

`Display Filter` = filtra la vista del archivo ya capturado

</div>

</div>
<div>

![w:400](./images/slide_037_img_42.png)

</div>
</div>

---

# Exportar objetos de Wireshark

<div class="text-img">
<div>

**File → Export Objects → HTTP**

Wireshark puede **reconstituir y exportar** objetos HTTP:

<div class="list-item">Páginas HTML</div>
<div class="list-item">Imágenes descargadas</div>
<div class="list-item">Binarios / ejecutables</div>
<div class="list-item">Documentos (PDF, Office...)</div>

<div class="highlight-box">

Se guardan para análisis forense posterior

</div>

</div>
<div>

![w:400](./images/slide_038_img_43.png)

</div>
</div>

---

# LogiCorp — Apertura del PCAP

<div class="warn-box">

**En el caso de LogiCorp:**

IT nos entrega el PCAP del firewall perimetral de las últimas 4 horas. Lo primero es orientarse sin perdernos en los miles de paquetes.

</div>

<div class="cols">
<div>

**Filtros iniciales aplicados:**

<div class="list-item"><code>dns</code> — aislamos todas las consultas de nombres</div>
<div class="list-item"><code>ip.src == 10.10.1.45</code> — solo tráfico de DESKTOP-MK3</div>
<div class="list-item"><code>tcp.port == 443 && ip.dst != 10.0.0.0/8</code> — HTTPS saliente</div>

</div>
<div>

<div class="highlight-box">

**Primer hallazgo:**

Al aislar DNS, aparecen consultas repetidas al mismo dominio desconocido — exactamente cada 60 segundos.

Pasamos al módulo de protocolos para entender qué estamos viendo.

</div>

</div>
</div>

---

# Un poquito de protocolos…

<div class="center-content">

> *"Attackers bend and break protocols in order to smuggle covert data, sneak past firewalls, bypass authentication, and conduct widespread denial-of-service (DoS) attacks."*
>
> — Davidoff & Ham, 2012

</div>

---

# Capa de enlace IEEE 802.x — Trama

<div class="center-content">

![w:700](./images/slide_042_img_44.png)

**Tamaño mínimo de trama:** 14 + 46 + 4 bytes (mecanismo anti-colisiones)

</div>

---

# Capa de enlace IEEE 802.x — Wireshark

<div class="center-content">

![w:750](./images/slide_043_img_45.png)

</div>

---

# ARP — Address Resolution Protocol

<div class="img-text">
<div>

![w:350](./images/slide_044_img_46.png)

</div>
<div>

**¿Para qué sirve ARP?**

<div class="list-item">Resolución de dirección IP → MAC en el mismo segmento LAN</div>
<div class="list-item">Necesario antes de cualquier comunicación L2</div>

**Flujo:**

<div class="list-item-sub">A quiere hablar con 10.0.0.2 pero no sabe su MAC</div>
<div class="list-item-sub">A emite un ARP Request (broadcast)</div>
<div class="list-item-sub">10.0.0.2 responde con su MAC (ARP Reply unicast)</div>
<div class="list-item-sub">A almacena la entrada en su cache ARP</div>

</div>
</div>

---

# ARP — En Wireshark

<div class="center-content">

![w:650](./images/slide_044_img_47.png)

</div>

---

# Problemas de ARP

<div class="cols">
<div>

<div class="warn-box">

**ARP no es seguro:**

<div class="list-item">No valida autenticidad del emisor</div>
<div class="list-item">Cualquiera puede responder a cualquier petición ARP</div>
<div class="list-item">Todos los equipos actualizan su caché al recibir ARP</div>

</div>

**ARP Spoofing / Poisoning:**

<div class="list-item">Un atacante envía ARP Replies falsos</div>
<div class="list-item">Redirige tráfico hacia sí mismo → <strong>MITM</strong></div>
<div class="list-item">Permite capturar o modificar tráfico</div>

</div>
<div>

![w:400](./images/slide_045_img_49.png)

<div class="highlight-box">

**Detección en Wireshark:**

`arp.duplicate-address-detected` o múltiples MACs para la misma IP

</div>

</div>
</div>

---

# IPv4 vs IPv6

<div class="cols">
<div>

## IPv4

<div class="list-item">Direccionamiento de <strong>32 bits</strong></div>
<div class="list-item">~4.300 millones de direcciones</div>
<div class="list-item">RFC 791</div>

![w:320](./images/slide_048_img_50.png)

</div>
<div>

## IPv6

<div class="list-item">Direccionamiento de <strong>128 bits</strong></div>
<div class="list-item">340 undecillones de direcciones</div>
<div class="list-item">RFC 2460, RFC 4291</div>

![w:320](./images/slide_048_img_51.png)

</div>
</div>

---

# Cabecera de IPv4

<div class="img-text">
<div>

![w:380](./images/slide_049_img_52.png)

</div>
<div>

**Campos clave:**

<div class="list-item"><strong>Versión</strong>: 4 (IPv4) o 6 (IPv6) — otro valor → descarte</div>
<div class="list-item"><strong>Protocol</strong>: tipo de capa 4 encapsulada</div>
<div class="list-item-sub">ICMP: 1 | TCP: 6 | UDP: 17 (0x11)</div>
<div class="list-item"><strong>TTL</strong>: saltos máximos antes del descarte</div>
<div class="list-item-sub">Windows: 128 | Linux: 64 | Routers: 255</div>
<div class="list-item"><strong>ECN</strong>: notificación de congestión</div>
<div class="list-item-sub">00 = No ECN | 01/10 = ECN-Aware | 11 = Congestión</div>

</div>
</div>

---

# Cabecera IPv4 — Campos adicionales

<div class="cols">
<div>

**Tamaño y calidad de servicio:**

<div class="list-item"><strong>IHL</strong>: longitud de cabecera en palabras de 32 bits</div>
<div class="list-item-sub">Mínimo: 5 (20 bytes) | Máximo: 15 (60 bytes)</div>
<div class="list-item"><strong>DSCP/ToS</strong>: prioridad y clase de tráfico</div>
<div class="list-item-sub">VoIP, vídeo → valores elevados de DSCP</div>
<div class="list-item"><strong>Total Length</strong>: tamaño total del paquete (cabecera + datos)</div>
<div class="list-item-sub">Máximo: 65 535 bytes</div>

</div>
<div>

**Fragmentación e integridad:**

<div class="list-item"><strong>Identification</strong>: ID común a todos los fragmentos del mismo datagrama</div>
<div class="list-item"><strong>Flags</strong>: control de fragmentación</div>
<div class="list-item-sub">DF (Don't Fragment) | MF (More Fragments)</div>
<div class="list-item"><strong>Fragment Offset</strong>: posición del fragmento (múltiplo de 8 bytes)</div>
<div class="list-item"><strong>Header Checksum</strong>: verificación de integridad solo de la cabecera</div>
<div class="list-item-sub">Recalculado en cada router (el TTL cambia)</div>

</div>
</div>

---

# Fragmentación de IPv4

<div class="cols">
<div>

**¿Cuándo ocurre?**

<div class="list-item">Paquete mayor que el <strong>MTU</strong> del enlace</div>
<div class="list-item-sub">Máx IP: 64KB | Ethernet: 1500 bytes</div>

**Control de fragmentación:**

<div class="list-item"><strong>ID</strong>: mismo valor en todos los fragmentos</div>
<div class="list-item"><strong>Offset</strong>: posición del fragmento (múltiplo de 8)</div>
<div class="list-item"><strong>Flag M</strong>: "More Fragments" — activo en todos salvo el último</div>

</div>
<div>

![w:380](./images/slide_050_img_54.png)

<div class="highlight-box">

**Forense:**

La fragmentación puede usarse para evadir IDS que solo inspeccionan el primer fragmento

</div>

</div>
</div>

---

# IPv6 — Ventajas

<div class="cols">
<div>

**Motivación:**

<div class="list-item">Direcciones IPv4 públicas agotadas desde ~2011</div>
<div class="list-item">NAT y redes privadas son parches temporales</div>

**Mejoras técnicas:**

<div class="list-item">Enrutamiento más sencillo (sin broadcast)</div>
<div class="list-item"><strong>Seguridad nativa</strong> (IPSec integrado)</div>
<div class="list-item-sub">Cifrado del payload</div>
<div class="list-item-sub">Comprobación de integridad</div>
<div class="list-item-sub">Autenticación del origen</div>

</div>
<div>

<div class="highlight-box">

**Más mejoras:**

<div class="list-item">QoS mejorado (Flow Label)</div>
<div class="list-item">Payloads mayores (jumbogramas)</div>
<div class="list-item">Autoconfiguración SLAAC</div>
<div class="list-item">Sin checksums en cabecera</div>

</div>

<div class="warn-box">

**Reto forense:** Mayor opacidad si no se tiene visibilidad sobre el enrutamiento IPv6 interno

</div>

</div>
</div>

---

# TCP vs UDP

<div class="cols">
<div>

## TCP
## Transmission Control Protocol

<div class="list-item"><strong>Confiable</strong></div>
<div class="list-item">Con secuenciación y reordenación</div>
<div class="list-item">Orientado a conexión (3-way handshake)</div>
<div class="list-item">Control de flujo y congestión</div>
<div class="list-item">Puertos 0–65535 | RFC 793</div>

</div>
<div>

## UDP
## User Datagram Protocol

<div class="list-item"><strong>No confiable</strong></div>
<div class="list-item">Sin secuenciación</div>
<div class="list-item">No orientado a conexión</div>
<div class="list-item">Sin control de flujo</div>
<div class="list-item">Puertos 0–65535 | RFC 768</div>

</div>
</div>

---

# TCP vs UDP — Cabeceras

<div class="center-content">

![w:700](./images/slide_053_img_55.png)

</div>

---

# Establecimiento de conexión TCP (3-Way Handshake)

<div class="center-content">

![w:700](./images/slide_054_img_57.jpg)

</div>

---

# Fin de conexión TCP (4-Way Teardown)

<div class="center-content">

![w:700](./images/slide_055_img_58.jpg)

</div>

---

# UDP — Características

<div class="cols">
<div>

**Protocolo ligero y rápido:**

<div class="list-item">Sobrecarga mínima de cabecera (8 bytes)</div>
<div class="list-item">Sin control de flujo ni retransmisiones</div>
<div class="list-item">Sin garantía de orden de llegada</div>

**Protocolos basados en UDP:**

<div class="list-item"><strong>DNS</strong> — resolución de nombres</div>
<div class="list-item"><strong>NTP</strong> — sincronización de tiempo</div>
<div class="list-item"><strong>SNMP</strong> — monitorización</div>
<div class="list-item"><strong>DHCP</strong> — configuración dinámica</div>
<div class="list-item"><strong>QUIC/HTTP3</strong> — web moderno</div>

</div>
<div>

<div class="highlight-box">

**Cabecera UDP (8 bytes):**

Puerto origen | Puerto destino

Longitud total | Checksum

</div>

<div class="warn-box">

Diseñados en una era sin modelo de seguridad → son vectores de ataque habituales

</div>

</div>
</div>

---

# UDP — En Wireshark

<div class="center-content">

![w:750](./images/slide_057_img_59.png)

**Tamaño mínimo:** 8 bytes (solo cabecera) — si vale 0 = jumbograma

</div>

---

# ICMP — Internet Control Message Protocol

<div class="cols">
<div>

**Propósito:**

<div class="list-item">Reportar errores <strong>no temporales</strong> de la red</div>
<div class="list-item">Intercambiar información de control simple</div>

**Casos de uso:**

<div class="list-item">Fragmentación necesaria pero DF=1</div>
<div class="list-item">Puerto inalcanzable (destino no responde)</div>
<div class="list-item"><strong>Ping</strong> (Echo Request / Echo Reply)</div>
<div class="list-item">TTL Exceeded (traceroute)</div>

</div>
<div>

<div class="warn-box">

**Habitual bloquearlo en redes corporativas:**

<div class="list-item">Dificulta el descubrimiento de la red</div>
<div class="list-item">Anula PMTUD → puede generar problemas de red</div>

</div>

<div class="highlight-box">

**Forense:**

Los mensajes de error ICMP **incluyen parte del paquete original** que causó el error → revelan información de sesiones internas

</div>

</div>
</div>

---

# ICMP Echo Request / Reply (PING)

<div class="cols">
<div>

**Estructura:**

<div class="list-item"><strong>Mismo identificador</strong> en request y reply</div>
<div class="list-item">Diferentes <strong>números de secuencia</strong> por envío</div>
<div class="list-item">Permite controlar paquetes perdidos y latencia</div>

**Uso malicioso:**

<div class="list-item"><strong>ICMP Tunneling</strong> — exfiltración de datos en el payload ICMP</div>
<div class="list-item">Reconocimiento de red (ping sweep)</div>
<div class="list-item">Fragmentación maliciosa (Ping of Death)</div>

</div>
<div>

<div class="highlight-box">

**Detección en Wireshark:**

Filtro: `icmp.type == 8` (request)

Payload ICMP anormalmente grande = sospechoso

</div>

</div>
</div>

---

# DNS — Domain Name System

<div class="text-img">
<div>

**¿Qué hace DNS?**

<div class="list-item">Traduce nombres de dominio en direcciones IP</div>
<div class="list-item">Jerarquía de servidores involucrados:</div>
<div class="list-item-sub"><strong>Resolutores</strong> (stub + recursive)</div>
<div class="list-item-sub"><strong>Raíz</strong> (13 grupos de root servers)</div>
<div class="list-item-sub"><strong>TLD</strong> (.com, .es, .org...)</div>
<div class="list-item-sub"><strong>Autoritativos</strong> (zona del dominio)</div>

</div>
<div>

![w:400](./images/slide_061_img_60.png)

</div>
</div>

---

# DNS — Respuesta en Wireshark

<div class="img-text">
<div>

![w:420](./images/slide_062_img_61.png)

</div>
<div>

**Secciones de la respuesta DNS:**

<div class="list-item"><strong>Question</strong>: el nombre consultado</div>
<div class="list-item"><strong>Answer</strong>: registros que responden la consulta</div>
<div class="list-item"><strong>Authority</strong>: servidores autoritativos del dominio</div>
<div class="list-item"><strong>Additional</strong>: IPs de los autoritativos</div>

<div class="highlight-box">

**Forense DNS:**

DNS es el protocolo de exfiltración y C2 más usado — todo el tráfico interno pasa por el DNS corporativo

</div>

</div>
</div>

---

# DNS Records — Tipos

| Tipo | Función | Relevancia Forense |
|------|---------|-------------------|
| A | IPv4 del dominio | Resolución C2, phishing |
| AAAA | IPv6 del dominio | C2 sobre IPv6 |
| CNAME | Alias | Redirección encubierta |
| MX | Servidor de correo | SPAM, phishing |
| TXT | Texto libre | Exfiltración, verificación |
| PTR | Reverse DNS (IP→nombre) | Atribución |
| NS | Servidor autoritativo | Takeover de dominio |

---

# DNS — Variantes de transporte

<div class="cols">
<div>

**DNS clásico (UDP/53):**

<div class="list-item">Sin cifrado — visible en la red</div>
<div class="list-item">Fácil de analizar en Wireshark</div>
<div class="list-item">Fácil de bloquear o interceptar</div>

**DNS sobre TLS (DoT / puerto 853):**

<div class="list-item">Tráfico cifrado TCP</div>
<div class="list-item">Más fácil de bloquear (puerto único)</div>

</div>
<div>

**DNS sobre HTTPS (DoH / puerto 443):**

<div class="list-item">Mezclado con tráfico HTTPS normal</div>
<div class="list-item"><strong>Difícil de bloquear sin rompimiento TLS</strong></div>
<div class="list-item">Usado por malware moderno para evasión</div>

<div class="warn-box">

**Reto forense 2025:**

Malware usa DoH (Cloudflare, Google) para ocultar resoluciones de C2

</div>

</div>
</div>

---

# LogiCorp — Anomalía DNS detectada

<div class="warn-box">

**En el caso de LogiCorp:**

Filtramos `dns` y ordenamos por nombre de dominio. Aparece `upd4te-cdn.net` con 240 consultas en 4 horas.

</div>

<div class="cols">
<div>

**Señales de alarma:**

<div class="list-item">Intervalo exacto de 60 segundos → <strong>beaconing</strong></div>
<div class="list-item">Dominio registrado hace 3 días → sospechoso</div>
<div class="list-item">Sin tráfico web previo a ese dominio → no es legítimo</div>
<div class="list-item">Responde siempre a la misma IP: <code>185.220.101.12</code></div>

</div>
<div>

<div class="highlight-box">

**Filtro Wireshark:**

`dns.qry.name contains "upd4te"`

→ 240 resultados, todos desde `DESKTOP-MK3`

</div>

<div class="warn-box">

Regla práctica: si un dominio aparece con **periodicidad fija**, es C2 hasta que se demuestre lo contrario

</div>

</div>
</div>

---

# HTTP/S — HyperText Transfer Protocol

<div class="cols">
<div>

## HTTP (puerto 80)

<div class="list-item">Protocolo de texto claro</div>
<div class="list-item">Uso muy reducido hoy en día</div>
<div class="list-item">Visible directamente en Wireshark</div>

## HTTPS (puerto 443)

<div class="list-item">HTTP sobre TLS/SSL — cifrado end-to-end</div>
<div class="list-item">Requiere interceptación mediante proxy o SSLKEYLOGFILE</div>
<div class="list-item">95%+ del tráfico web actual</div>

</div>
<div>

<div class="highlight-box">

**Vector muy común y difícil de bloquear:**

<div class="list-item">Navegación web legítima</div>
<div class="list-item">APIs REST</div>
<div class="list-item">Delivery de malware</div>
<div class="list-item">Canales C2</div>
<div class="list-item">Exfiltración de datos</div>

</div>

<div class="warn-box">

Casi todos los campos HTTP son **manipulables** por el atacante

</div>

</div>
</div>

---

# HTTP/S — Códigos de respuesta

| Rango | Significado | Ejemplo forense |
|-------|------------|----------------|
| 1xx | Informativo | Poco común, ignorable |
| 2xx | Éxito | 200 OK — contenido servido |
| 3xx | Redirección | 302 → redirección a C2 |
| 4xx | Error cliente | 404 fichero no existe, 403 acceso denegado |
| 5xx | Error servidor | 500 = posible explotación |

<div class="highlight-box">

**Truco forense:** Una ráfaga de 404 desde una IP = reconocimiento (fuzzing de rutas)

Una serie de 200 hacia URLs aleatorias = posible DGA / C2

</div>

---

# HTTP — Métodos

<div class="cols">
<div>

**Métodos comunes:**

<div class="list-item"><strong>GET</strong> — solicitar recurso (sin body)</div>
<div class="list-item"><strong>POST</strong> — enviar datos al servidor</div>
<div class="list-item"><strong>PUT</strong> — subir/actualizar recurso</div>
<div class="list-item"><strong>DELETE</strong> — eliminar recurso</div>
<div class="list-item"><strong>HEAD</strong> — solo cabeceras, sin cuerpo</div>

</div>
<div>

<div class="highlight-box">

**Relevancia forense:**

<div class="list-item">POST con body grande → posible exfiltración</div>
<div class="list-item">PUT/DELETE inusuales → posible webshell</div>
<div class="list-item">User-Agent sospechoso → herramienta de ataque</div>
<div class="list-item">Muchos GET rápidos → fuzzing / scaneo</div>

</div>

</div>
</div>
