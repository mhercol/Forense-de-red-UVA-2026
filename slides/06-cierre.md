---

# Caso LogiCorp — Resolución

<div class="cols">
<div>

**¿Qué encontramos en los PCAPs?**

<div class="list-item">Lab 1: <code>recipe.docx</code> transferida por AIM desde <code>Sec558user1</code> (Ana)</div>
<div class="list-item">Lab 2: Ann Dercover usa <code>sneakyg33k@aol.com</code> para coordinar cita en Playa del Carmen con <code>mistersecretx@aol.com</code></div>
<div class="list-item">Lab 3: Escaneo TCP SYN desde <code>10.42.42.253</code> — Windows en <code>.50</code> (puertos 135, 139), Apple en <code>.25</code></div>
<div class="list-item">Lab 4: <code>Stewie-PC</code> infectado vía <code>www.homeimprovement.com</code> → exploit kit → <strong>ransomware</strong></div>

**Herramientas que usamos:**

<div class="list-item">Wireshark — Follow TCP Stream, Export Objects</div>
<div class="list-item">Statistics → Endpoints, Conversations</div>
<div class="list-item">VirusTotal / MalwareBazaar para identificación</div>

</div>
<div>

<div class="highlight-box">

**Conclusión forense:**

Insider threat (Ana + Ann) filtró la receta secreta y coordinó un encuentro externo. Paralelamente, un equipo corporativo (`Stewie-PC`, `172.16.4.193`) fue infectado con ransomware tras visitar un sitio comprometido.

**IOCs del Lab 4:**
- Servidor malware: `194.87.234.129`
- C2 post-infección: `spotsbill.com`
- Ransom page: `p27dokhpz2n7nvgr.1jw2lx.top`

</div>

<div class="warn-box">

SHA-256 de cada PCAP documentado. Evidencia preservada para el equipo legal.

</div>

</div>
</div>

---

# Próximos Pasos en tu Carrera

<div class="cols">
<div>

<div class="phase-box">

## Si estás empezando
<div class="list-item"><strong>Malware-Traffic-Analysis.net</strong> — PCAPs de malware reales, actualizados semanalmente</div>
<div class="list-item"><strong>Wireshark</strong> — practica con capturas propias de tu red</div>
<div class="list-item"><strong>CTFs</strong> — TryHackMe, HackTheBox, PicoCTF</div>

</div>

<div class="phase-box">

## Si ya te interesa en serio
<div class="list-item"><strong>PacketTotal</strong> — análisis colaborativo de PCAPs</div>
<div class="list-item"><strong>SANS ISC</strong> — lectura diaria de amenazas actuales</div>
<div class="list-item"><strong>BSides</strong> — eventos locales de seguridad</div>
<div class="list-item">Escribe tus análisis — blog propio o GitHub write-ups</div>

</div>

</div>
<div>

<div class="phase-box">

## Si quieres dedicarte profesionalmente
<div class="list-item"><strong>SANS FOR572</strong> → examen <strong>GCIA</strong></div>
<div class="list-item-sub">El binomio estándar del sector — el curso prepara el examen</div>
<div class="list-item">Busca roles: <em>"network analyst"</em>, <em>"tier 2 SOC"</em>, <em>"DFIR junior"</em></div>

</div>

<div class="highlight-box">

El camino más corto: un PCAP real analizado y documentado en público vale más en una entrevista que cualquier curso sin práctica.

</div>

</div>
</div>

---

# Resumen Final

<div class="cols">
<div>

**Lo que hemos aprendido:**

<div class="list-item">Fundamentos de protocolos de red (L2-L7)</div>
<div class="list-item">Captura y análisis con Wireshark / tcpdump</div>
<div class="list-item">Filtros BPF y display filters avanzados</div>
<div class="list-item">Metodología de forense de red</div>
<div class="list-item">Fuentes de información en la investigación</div>
<div class="list-item">NetFlow y análisis de flujos</div>
<div class="list-item">Full Packet Capture con Arkime</div>
<div class="list-item">Técnicas avanzadas: JA3, ETA, QUIC</div>

</div>
<div>

<div class="highlight-box">

**El mejor analista de forense de red es el que:**

<div class="list-item">Conoce bien los protocolos</div>
<div class="list-item">Sabe qué es normal en su red</div>
<div class="list-item">Practica con PCAPs reales</div>
<div class="list-item">Correlaciona múltiples fuentes</div>
<div class="list-item">Documenta todo con rigor</div>

</div>

**Contacto:** mhercol[@]gmail[.]com

</div>
</div>

---

# Fin del Curso

<div class="center-content">

## Network Forensics 2025

**Gracias — preguntas y contacto:**

`mhercol[@]gmail[.]com`

<div class="highlight-box">

**A continuación:** Material de referencia y módulo avanzado (bonus)

Glosario · Apéndices · Cloud & Kubernetes · eBPF

</div>

</div>
