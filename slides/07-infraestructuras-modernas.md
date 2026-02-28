---

# Módulo Avanzado — Por si acaso

<div class="center-content">

```
 ┌─────────────────────────────────────────────────────┐
 │                                                     │
 │   BONUS TRACK — Infraestructuras Modernas           │
 │                                                     │
 │   Este módulo va más allá del curso base.           │
 │   Es material de referencia para cuando trabajes    │
 │   en entornos cloud o con contenedores.             │
 │                                                     │
 │   No es examen. Es contexto profesional real.       │
 │                                                     │
 └─────────────────────────────────────────────────────┘
```

</div>

---

# Análisis Forense en Infraestructuras Corporativas Modernas

<div class="center-content">

## Cloud, contenedores y microservicios: visibilidad sin acceso físico

La infraestructura moderna ha reescrito las reglas del forense de red

</div>

---

# Network Forensics en Cloud (2025)

<div class="cols">
<div>

## AWS

<div class="list-item"><strong>VPC Flow Logs</strong>: Metadatos (5-tupla, bytes, packets)</div>
<div class="list-item"><strong>VPC Traffic Mirroring</strong>: PCAP completo -> EC2/NLB</div>

## Azure

<div class="list-item"><strong>NSG Flow Logs</strong>: Equivalente a VPC Flow Logs</div>
<div class="list-item"><strong>Network Watcher Packet Capture</strong>: PCAP temporal (máx 5h, 10GB)</div>

</div>
<div>

## GCP

<div class="list-item"><strong>VPC Flow Logs</strong>: Muestreo configurable (1:1 a 1:1000)</div>
<div class="list-item"><strong>Packet Mirroring</strong>: Clona tráfico a collector instance</div>

<div class="highlight-box">

**[!] Limitación crítica**

Flow Logs **NO contienen payload**
(solo headers L3/L4)

</div>

</div>
</div>

---

# El nuevo paradigma: contenedores vs VMs

<div class="highlight-box">

**"Trata a los contenedores como ganado, no como mascotas"**

Los servidores tradicionales son *mascotas*: tienen nombre, historia y se reparan cuando fallan. Los contenedores son *ganado*: fungibles, numerados y reemplazados — nunca reparados. Esta filosofía tiene consecuencias directas en el forense: **la evidencia es efímera por diseño**.

</div>

<div class="cols">
<div>

**Infraestructura tradicional (VMs)**

<div class="list-item">IP fija, MAC conocida, OS persistente</div>
<div class="list-item">Logs en disco, en el mismo nodo</div>
<div class="list-item">Ciclo de vida: semanas/meses</div>
<div class="list-item">Estado forense disponible post-incidente</div>

**Herramientas clásicas funcionan:**
`tcpdump`, Wireshark, `netstat`, PCAP directo

</div>
<div>

**Entornos contenerizados**

<div class="list-item">IP efímera — cambia en cada reinicio</div>
<div class="list-item">Contenedor destruido = evidencia destruida</div>
<div class="list-item">Ciclo de vida: segundos/minutos</div>
<div class="list-item">Un pod puede vivir en cualquier nodo</div>

**Los retos forenses son nuevos:**
visibilidad de red, namespaces, overlay, mTLS

</div>
</div>

---

# Arquitectura de red en Kubernetes

<div class="highlight-box">

**Problema central**: en Kubernetes, el tráfico entre pods viaja por redes virtuales superpuestas (*overlay networks*) — invisible a herramientas de captura convencionales sobre la NIC física

</div>

**Capas de red involucradas:**

<div class="list-item">**eth0 del pod** — interfaz virtual dentro del namespace de red del contenedor</div>
<div class="list-item">**veth pair** — cable virtual entre el pod y el nodo host</div>
<div class="list-item">**bridge/CNI** — plugin de red: Flannel, Calico, Cilium, Weave</div>
<div class="list-item">**NIC física del nodo** — tráfico encapsulado (VXLAN, Geneve, IP-in-IP)</div>
<div class="list-item">**kube-proxy / eBPF** — balanceo de servicios (iptables o eBPF según CNI)</div>

```
[Pod A] ──veth──► [cbr0 bridge] ──VXLAN──► [Nodo B] ──veth──► [Pod B]
        namespace red aislado        encapsulado en UDP/8472
```

---

# Desafíos de visibilidad — Por qué el PCAP clásico falla

<div class="cols">
<div>

**Problema 1: Namespaces de red**

Cada pod tiene su propio namespace de red. `tcpdump` en el host **no ve** el tráfico interno entre pods del mismo nodo.

**Problema 2: Ephemeral by design**

Un `kubectl delete pod` destruye toda evidencia local. Los contenedores son inmutables — no se "parchean", se recrean.

**Problema 3: IPs dinámicas**

DHCP/IPAM asigna IPs al vuelo. La IP `10.0.1.42` que ves en logs puede pertenecer a 10 pods distintos en el mismo día.

</div>
<div>

**Problema 4: Encapsulación**

El tráfico Este-Oeste entre nodos viaja encapsulado en VXLAN (UDP/8472) o Geneve. Capturar en la NIC física muestra **encapsulación**, no el payload real.

**Problema 5: Escala y velocidad**

Miles de pods, decenas de nodos. Retención muy corta. Correlacionar un evento pasado con logs de pods ya destruidos es extremadamente difícil.

**Problema 6: mTLS en service meshes**

Istio/Linkerd cifran **todo** el tráfico Este-Oeste con mTLS. Sin gestión de claves, el tráfico es opaco.

</div>
</div>

---

# Redes overlay — El tráfico "invisible"

<div class="highlight-box">

**VXLAN (Virtual eXtensible LAN)**: el tráfico entre pods de distintos nodos se encapsula en UDP/8472. Un `tcpdump` en la NIC física del nodo captura el wrapper, no el contenido real.

</div>

```bash
# Lo que ves capturando en eth0 del nodo:
IP nodo-1:47392 > nodo-2:8472: VXLAN, flags [I], vni 1
IP 10.0.1.5:54321 > 10.0.2.8:443: Flags [P.], ...
#    ^pod-origen         ^pod-destino    ^payload dentro del VXLAN

# Para ver el tráfico real, necesitas capturar DENTRO del namespace del pod:
nsenter -t <PID_del_pod> -n -- tcpdump -i eth0 -w /tmp/captura.pcap
```

**CNI plugins y sus implicaciones forenses:**

<div class="list-item">**Flannel** — VXLAN simple, fácil de descifrar manualmente</div>
<div class="list-item">**Calico** — IP-in-IP o BGP nativo, más eficiente, misma opacidad</div>
<div class="list-item">**Cilium** — eBPF nativo, ofrece su propio plano de observabilidad (Hubble)</div>
<div class="list-item">**Weave** — cifrado opcional del overlay (añade otra capa de opacidad)</div>

---

# Service Mesh y mTLS — El reto del cifrado Este-Oeste

<div class="cols">
<div>

**Istio / Linkerd en modo mTLS**

Cada pod tiene un sidecar proxy (**Envoy**) que intercepta todo el tráfico entrante y saliente y aplica mTLS automáticamente.

**Consecuencia forense:**

El tráfico entre `servicio-A` → `servicio-B` está cifrado aunque ambos servicios estén en la misma red interna.

**A diferencia de TLS externo:**

No hay un único punto de terminación TLS (como un proxy inverso). Las claves están distribuidas entre todos los sidecars.

</div>
<div>

**Estrategias de visibilidad:**

<div class="list-item">**Envoy access logs** — el sidecar registra conexiones (IP, puerto, L7 si hay permiso)</div>
<div class="list-item">**Istio telemetry API** — exporta métricas y trazas a Prometheus/Jaeger</div>
<div class="list-item">**Captura en el sidecar** — `kubectl exec` en el contenedor `istio-proxy` para tcpdump antes del cifrado</div>
<div class="list-item">**Mutual TLS certs** — los certificados de corta vida (SVID con SPIFFE) son trazables por identidad de workload, no por IP</div>

```bash
# Captura en el sidecar Envoy (tráfico pre-mTLS):
kubectl exec -it <pod> -c istio-proxy -- \
  tcpdump -i lo -w /tmp/cap.pcap
```

</div>
</div>

---

# Captura de tráfico en Kubernetes — nsenter

<div class="highlight-box">

**`nsenter`**: entra en los namespaces de Linux (red, PID, mount) de un proceso en ejecución. Permite ejecutar herramientas del host **dentro del namespace de red de un pod** sin modificar el pod.

</div>

```bash
# 1. Obtener el PID del proceso principal del contenedor en el nodo
CONTAINER_ID=$(kubectl get pod <pod-name> -o jsonpath='{.status.containerStatuses[0].containerID}' \
               | cut -d'/' -f3)
PID=$(docker inspect --format '{{.State.Pid}}' $CONTAINER_ID)
# o con containerd:
PID=$(crictl inspect $CONTAINER_ID | jq '.info.pid')

# 2. Entrar en su namespace de red y capturar
nsenter -t $PID -n -- tcpdump -i eth0 -w /tmp/pod-capture.pcap

# 3. Copiar la captura al host
# (el archivo ya está en /tmp del sistema de archivos del host, no del pod)
```

**Ventajas:** no requiere modificar el pod, sin privilegios extra en el pod, funciona con contenedores sin shell

**Limitación:** el pod debe estar **vivo** en el momento de la captura

---

# ksniff — Captura de tráfico remota desde kubectl

<div class="highlight-box">

**ksniff** es un plugin de `kubectl` que automatiza la captura de tráfico en un pod remoto y lo redirige en tiempo real a Wireshark local — sin necesidad de SSH ni privilegios en el pod.

</div>

```bash
# Instalación
kubectl krew install sniff

# Captura en tiempo real (abre Wireshark localmente):
kubectl sniff <pod-name> -n <namespace>

# Captura a fichero PCAP:
kubectl sniff <pod-name> -n <namespace> -o /tmp/pod-traffic.pcap

# Filtro BPF para reducir ruido:
kubectl sniff <pod-name> -n <namespace> -f "port 8080"

# Pod sin privilegios (usa contenedor efímero):
kubectl sniff <pod-name> -n <namespace> --privileged=false
```

**Casos de uso forenses:**

<div class="list-item">Capturar tráfico de un pod sospechoso sin interrumpir el servicio</div>
<div class="list-item">Validar si un pod está realizando conexiones no autorizadas</div>
<div class="list-item">Analizar tráfico de microservicio en un entorno de producción</div>

---

# eBPF — La revolución de la visibilidad en contenedores

<div class="cols">
<div>

**¿Qué es eBPF?**

Extended Berkeley Packet Filter permite ejecutar programas sandboxeados **en el kernel de Linux** sin modificar el código del kernel.

**Para forense de contenedores:**

<div class="list-item">Captura de tráfico **antes** del cifrado TLS</div>
<div class="list-item">Trazado de syscalls por PID/contenedor</div>
<div class="list-item">Visibilidad de conexiones de red a nivel de proceso</div>
<div class="list-item">Overhead mínimo — apto para producción</div>
<div class="list-item">No requiere modificar pods ni sidecars</div>

</div>
<div>

**Herramientas basadas en eBPF:**

| Herramienta | Uso forense |
|-------------|-------------|
| **Falco** | Detección de anomalías en tiempo real |
| **Tetragon** | Trazado de procesos y red (Cilium) |
| **Hubble** | Observabilidad de red en Kubernetes |
| **Pixie** | Análisis de tráfico L7 sin instrumentación |
| **Tracee** | Forense de syscalls (Aqua Security) |
| **bpftrace** | Scripting eBPF ad-hoc |

```bash
# Ver conexiones TCP de todos los pods en tiempo real:
bpftrace -e 'kprobe:tcp_connect {
  printf("%s -> %s\n", comm,
    ntop(arg0->__sk_common.skc_daddr)); }'
```

</div>
</div>

---

# Falco — Detección en tiempo real en contenedores

<div class="highlight-box">

**Falco** (CNCF) usa eBPF/kernel module para monitorizar llamadas al sistema en todos los contenedores del nodo. Define reglas declarativas para detectar comportamientos anómalos.

</div>

**Reglas relevantes para forense de red:**

```yaml
# Detección: shell dentro de contenedor de producción
- rule: Terminal shell in container
  desc: Container running an interactive shell
  condition: spawned_process and container and shell_procs and proc.tty != 0
  output: "Shell en contenedor (user=%user.name container=%container.name)"
  priority: WARNING

# Detección: conexión saliente inesperada desde contenedor
- rule: Unexpected outbound connection
  desc: Outbound connection on unexpected port
  condition: outbound and container and not (fd.sport in (allowed_ports))
  output: "Conexión no autorizada (pod=%k8s.pod.name dst=%fd.rip:%fd.rport)"
  priority: CRITICAL
```

**Exportación de alertas:**

<div class="list-item">stdout → log aggregation (Fluentd, Loki)</div>
<div class="list-item">gRPC → Falcosidekick → Slack, SIEM, PagerDuty</div>
<div class="list-item">JSON estructurado con metadatos Kubernetes (pod, namespace, node, image)</div>

---

# Cilium Hubble — Observabilidad de red en Kubernetes

<div class="cols">
<div>

**Hubble** es el plano de observabilidad de Cilium. Usando eBPF proporciona visibilidad L3/L4/L7 del tráfico entre pods **sin modificar aplicaciones ni añadir sidecars**.

**Capacidades:**

<div class="list-item">Flujos de red por pod, namespace, label</div>
<div class="list-item">Visibilidad L7: HTTP, gRPC, DNS, Kafka</div>
<div class="list-item">Mapa de servicios en tiempo real</div>
<div class="list-item">Correlación con identidades Kubernetes</div>
<div class="list-item">Retención configurable de flujos</div>

</div>
<div>

```bash
# Instalar CLI de Hubble
hubble version

# Ver flujos en tiempo real (todos los namespaces):
hubble observe --all-namespaces

# Filtrar por pod concreto:
hubble observe --pod frontend/nginx-7d9f --follow

# Ver solo conexiones rechazadas (policy violations):
hubble observe --verdict DROPPED

# Flujos DNS para detectar C2:
hubble observe -t l7 --protocol DNS \
  --namespace production

# Exportar a JSON para análisis forense:
hubble observe --output json > flujos-$(date +%Y%m%d).json
```

</div>
</div>

---

# Forense de sistema de archivos — OverlayFS

<div class="highlight-box">

Los contenedores Docker/containerd usan **OverlayFS**: capas de imagen de solo lectura + capa de escritura efímera (upperdir). Al destruir el contenedor, la capa de escritura desaparece.

</div>

<div class="cols">
<div>

**Estructura OverlayFS:**

```
/var/lib/docker/overlay2/
  <layer-id>/
    diff/        ← cambios del contenedor (upperdir)
    merged/      ← vista combinada (mountpoint)
    work/        ← directorio interno OverlayFS
    lower        ← referencia a capas inferiores
```

**Evidencia recuperable (si el contenedor aún existe):**

<div class="list-item">Archivos descargados por malware</div>
<div class="list-item">Credenciales escritas en disco</div>
<div class="list-item">Scripts ejecutados y logs internos</div>

</div>
<div>

```bash
# Extraer sistema de archivos de un contenedor vivo:
docker export <container-id> > container-fs.tar

# Inspeccionar la capa de escritura directamente:
LAYER=$(docker inspect <id> \
  --format '{{.GraphDriver.Data.UpperDir}}')
ls -la $LAYER

# Copiar archivo específico del contenedor:
docker cp <container-id>:/tmp/malware.sh ./evidencia/

# Si ya está destruido — buscar en capas de imagen:
docker history <image>:tag
docker save <image> | tar -xv
```

**Cadena de custodia:**

```bash
# Hash antes de cualquier análisis:
sha256sum container-fs.tar > container-fs.tar.sha256
```

</div>
</div>

---

# Kubernetes Audit Logs — La traza del plano de control

<div class="highlight-box">

El **API Server de Kubernetes** registra todas las operaciones: `kubectl exec`, creación de pods, cambios de RBAC, acceso a secrets. Son la fuente de verdad del plano de control.

</div>

**Configuración de política de auditoría:**

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Registrar todos los exec y port-forward (indicadores de intrusión):
  - level: Request
    resources: [{group: "", resources: ["pods/exec", "pods/portforward"]}]
  # Registrar acceso a secrets:
  - level: Metadata
    resources: [{group: "", resources: ["secrets"]}]
  # Registrar cambios de RBAC:
  - level: RequestResponse
    resources: [{group: "rbac.authorization.k8s.io"}]
```

**Indicadores de compromiso en audit logs:**

<div class="list-item">**`pods/exec`** a pods en producción desde IPs no habituales</div>
<div class="list-item">Creación de **ClusterRoleBinding** privilegiado fuera de ventana de mantenimiento</div>
<div class="list-item">Acceso masivo a **secrets** desde una SA que normalmente no los lee</div>
<div class="list-item">**`pods/portforward`** a puertos internos — posible tunelización de tráfico</div>

---

# Correlación entre capas — La visión completa

<div class="cols">
<div>

**Fuentes disponibles en entornos contenerizados:**

<div class="list-item">**Kubernetes audit logs** — quién hizo qué en el plano de control</div>
<div class="list-item">**Hubble/eBPF flows** — qué tráfico de red hubo entre pods</div>
<div class="list-item">**Falco alerts** — qué syscalls/comportamientos anómalos ocurrieron</div>
<div class="list-item">**Container runtime logs** — qué imagen, cuándo se inició, variables de entorno</div>
<div class="list-item">**OverlayFS / docker export** — qué archivos se crearon o modificaron</div>
<div class="list-item">**PCAP (nsenter/ksniff)** — tráfico de red en bruto si se capturó a tiempo</div>

</div>
<div>

**Pipeline de correlación forense:**

```
[Alerta SIEM / Detección Falco]
         │
         ▼
[Kubernetes audit logs]
  → ¿Qué SA/usuario ejecutó el pod?
  → ¿Hubo kubectl exec sospechoso?
         │
         ▼
[Hubble flows / NetFlow del CNI]
  → ¿A qué IPs se conectó el pod?
  → ¿Qué puertos y protocolos?
         │
         ▼
[PCAP con nsenter/ksniff]
  → Contenido de las conexiones sospechosas
         │
         ▼
[OverlayFS / docker export]
  → ¿Qué archivos dejó el atacante?
```

</div>
</div>

---

# Escenario práctico — Lateral movement en Kubernetes

<div class="lab-box">

**Escenario:** Se detecta tráfico inusual desde un pod del namespace `frontend`. El pod contacta con la API de Kubernetes y con pods del namespace `backend` en puertos no autorizados.

</div>

**Investigación paso a paso:**

```bash
# 1. Identificar el pod y su service account:
kubectl get pod <pod-sospechoso> -o yaml | grep serviceAccount

# 2. Revisar qué permisos tiene esa SA:
kubectl auth can-i --list --as=system:serviceaccount:frontend:default

# 3. Ver audit logs del API server filtrando por esa SA:
grep '"serviceAccount":"default"' /var/log/kube-apiserver-audit.log \
  | grep '"verb":"create\|exec\|list"' | jq .

# 4. Capturar tráfico del pod con ksniff:
kubectl sniff <pod-sospechoso> -n frontend -o /tmp/lateral.pcap

# 5. Consultar flujos en Hubble:
hubble observe --pod frontend/<pod-sospechoso> \
  --verdict FORWARDED --output json | jq '.destination'

# 6. Extraer el sistema de archivos para análisis offline:
docker export <container-id> | tar -x -C /mnt/evidencia/
sha256sum /mnt/evidencia/**/* > /mnt/evidencia/hashes.txt
```

---

# Resumen — Herramientas para forense en contenedores

<div class="cols">
<div>

**Captura de tráfico:**

| Herramienta | Método | Nivel |
|-------------|--------|-------|
| `nsenter` | Network namespace | L2-L4 |
| `ksniff` | Plugin kubectl | L2-L7 |
| Hubble | eBPF (Cilium) | L3-L7 |
| Pixie | eBPF | L7 (HTTP/gRPC/DNS) |

**Detección y alertas:**

| Herramienta | Enfoque |
|-------------|---------|
| Falco | Syscalls y comportamiento |
| Tetragon | Procesos y red (eBPF) |
| Tracee | Forense de syscalls |

</div>
<div>

**Análisis de sistema de archivos:**

| Comando | Uso |
|---------|-----|
| `docker export` | Extraer FS completo |
| `docker cp` | Copiar archivo concreto |
| `docker inspect` | Metadata del contenedor |
| `crictl inspect` | containerd runtime info |

**Plano de control:**

| Fuente | Información |
|--------|-------------|
| K8s audit logs | Operaciones API server |
| RBAC audit | Escalada de privilegios |
| Envoy access logs | Tráfico mTLS en service mesh |

**Regla de oro en contenedores:**

La evidencia es **efímera** — capturar antes de que el pod desaparezca. Automatizar la respuesta con Falco + hooks de preservación de evidencia.

</div>
</div>
