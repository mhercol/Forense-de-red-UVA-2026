---

# Glosario — Network Forensics

<div class="center-content">

## Términos clave del curso

</div>

---

# Glosario (A–F)

<div class="cols">
<div>

**ARP** *(Address Resolution Protocol)*
Protocolo que mapea una IP a su dirección MAC en la red local. Vulnerable a ARP spoofing.

**Beaconing**
Comunicación periódica de un malware con su servidor C2. Patrón: intervalos regulares, pocos bytes.

**BPF** *(Berkeley Packet Filter)*
Sintaxis de filtrado de paquetes usada por tcpdump y Wireshark. Opera a nivel de kernel.

**C2** *(Command & Control)*
Infraestructura usada por el atacante para controlar el malware instalado en la víctima.

**Cadena de custodia**
Registro documental de quién ha tenido acceso a una evidencia desde su recogida hasta el juicio.

</div>
<div>

**DGA** *(Domain Generation Algorithm)*
Técnica de malware que genera dominios C2 automáticamente para dificultar el bloqueo.

**ETA** *(Encrypted Traffic Analysis)*
Análisis del tráfico cifrado sin descifrarlo, usando metadatos como tamaño y timing.

**Flow / NetFlow**
Resumen de una conversación de red: IPs, puertos, protocolo, bytes y paquetes. Menos detalle que PCAP pero mucho más ligero.

**FPC** *(Full Packet Capture)*
Captura completa de todos los paquetes, incluyendo payload. Máximo detalle forense.

</div>
</div>

---

# Glosario (F–M)

<div class="cols">
<div>

**Fragmentación IP**
División de un paquete IP en trozos más pequeños cuando supera el MTU. Puede usarse para evadir IDS.

**GDPR / RGPD**
Reglamento General de Protección de Datos. Rige el tratamiento de datos personales en la UE, incluidos los capturados en tráfico de red.

**Hash (SHA-256)**
Huella digital de un fichero. Se usa para verificar que una evidencia no ha sido alterada.

**IOC** *(Indicator of Compromise)*
Señal de que un sistema ha sido comprometido: IP maliciosa, hash de malware, dominio C2.

</div>
<div>

**JA3 / JA4**
Huella digital del TLS ClientHello. Permite identificar el cliente TLS sin descifrar el tráfico.

**Kill Chain**
Modelo que describe las fases de un ataque: reconocimiento, entrega, explotación, instalación, C2, movimiento lateral, exfiltración.

**Lateral Movement**
Técnica del atacante para moverse de un sistema a otro dentro de la red comprometida.

**Movimiento Norte-Sur**
Tráfico entre la red interna y el exterior (Internet). Cruce del perímetro.

</div>
</div>

---

# Glosario (M–R)

<div class="cols">
<div>

**Movimiento Este-Oeste**
Tráfico interno entre sistemas de la misma red. Más difícil de monitorizar que el Norte-Sur.

**mTLS** *(Mutual TLS)*
Variante de TLS donde tanto cliente como servidor se autentican con certificados.

**PCAP** *(Packet Capture)*
Fichero que contiene paquetes de red capturados. Formato más común: libpcap / pcapng.

**Perfect Forward Secrecy (PFS)**
Propiedad de TLS 1.3: cada sesión usa claves efímeras. Impide descifrar capturas pasadas si se compromete la clave privada.

**Pivot**
Movimiento del analista de una fuente de datos a otra siguiendo una pista: de alerta SIEM a PCAP en Arkime.

</div>
<div>

**Proxy**
Intermediario entre cliente e Internet. Puede ser punto de captura y control de tráfico.

**QUIC / HTTP/3**
Protocolo de transporte sobre UDP que reemplaza a TCP para HTTP/3. Dificulta el análisis forense clásico.

**REGEX** *(Regular Expression)*
Patrón de búsqueda de texto. En Wireshark se usan con `matches` para detectar patrones en el payload.

**SPAN Port** *(Switch Port Analyzer)*
Puerto de un switch configurado para recibir copias del tráfico de otros puertos. Alternativa económica al TAP.

</div>
</div>

---

# Glosario (S–Z)

<div class="cols">
<div>

**SSLKEYLOGFILE**
Variable de entorno que hace que el navegador exporte las claves de sesión TLS. Permite descifrar PCAPs en Wireshark.

**SYN scan / Port scan**
Técnica de reconocimiento que envía SYN a múltiples puertos para detectar servicios abiertos sin completar el handshake.

**TAP** *(Test Access Point)*
Dispositivo hardware que intercepta y copia el tráfico de red de forma pasiva e indetectable.

**Threat Hunting**
Búsqueda proactiva de amenazas usando hipótesis, antes de que se genere una alerta.

**TLS** *(Transport Layer Security)*
Protocolo de cifrado de la capa de transporte. La versión 1.3 es el estándar actual.

</div>
<div>

**TTL** *(Time To Live)*
Campo del paquete IP que indica cuántos saltos puede dar antes de descartarse. Útil para inferir el OS origen.

**Wireshark**
Herramienta gráfica de análisis de paquetes de red. Estándar de facto en forense de red.

**Zeek** *(antes Bro)*
Framework de análisis de red que genera logs estructurados por protocolo a partir de PCAP o tráfico en vivo.

**Zero Trust**
Modelo de seguridad que no confía en ningún nodo por defecto, incluso dentro de la red corporativa. Implica cifrado ubicuo y microsegmentación.

</div>
</div>
