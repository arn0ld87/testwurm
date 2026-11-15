# testwurm Blueprint

## System Overview

`testwurm` ist ein Repository für **autorisierte** Penetrationstests und
Red-Team-Übungen. Es bündelt drei voneinander getrennte Bereiche:

- **`kx/`** — der Rust-Workspace, der die eigentliche Funktionalität trägt.
  Neun Crates bilden eine Post-Quantum-Netzwerkwurm-Pipeline aus Scanner,
  Exploit, Post-Exploitation (Windows/POSIX), TLS-Infrastruktur, C2-Server und
  Operator-CLI. Der Wurm durchläuft dabei die Phasen Entdeckung → Scan →
  Exploit → Extraktion → Persistenz → Reporting.
- **`docs/`** — Agent-Dokumentation (Issue-Tracker-Konventionen und
  Domain-Dokumentation). Kein Quellcode, daher kein EGM-Vertrag.
- **`wissen/`** — eine Recherche-Wissenssammlung (28 Markdown-Dateien zu
  Ransomware-Technik, Kill-Chains, Krypto-Implementierung und C2-Technik) sowie
  eine Klartext-Notiz zu `alex-schneider.dev`. Kein Quellcode, daher kein
  EGM-Vertrag.

Das Repository-Root selbst enthält keinen Quellcode; die ausführbare Architektur
beginnt unter [`kx/`](../kx/README.md).

```
testwurm/
├── README.md              → Betriebshandbuch (Installation, Einsatz, Steuerung)
├── kx/                    → Rust-Workspace, 9 Crates  →  ../kx/README.md
├── docs/egm-blueprint.md  → dieser Blueprint (Systemgrenzen, Invarianten)
├── docs/agents/           → Agent-Dokumentation (kein Vertrag)
└── wissen/                → Wissenssammlung (kein Vertrag)
```

## Subdirectories & System Boundaries

- [README.md](../README.md) — Betriebshandbuch für Menschen: Installation, Einsatz, Steuerung, C2-API-Referenz, Troubleshooting, Sicherheits-Härtung. Der maschinenlesbare Vertrag steht in diesem Blueprint, die Crate-Details in [`kx/README.md`](../kx/README.md).
- [kx](../kx/README.md) — Rust-Workspace des Netzwerkwurms. Enthält die Workspace-Definition, neun Member-Crates unter [`kx/crates/`](../kx/crates/README.md) sowie die Betriebs-, Build- und Nutzungsdokumentation. Einziger Verzeichnisbaum mit Quellcode.
- docs/agents — Agent-Dokumentation zu Issue-Tracker und Domain-Dokumentation. Kein Quellcode, kein EGM-Vertrag.
- wissen — Recherche-Wissenssammlung mit `_manifest.json` und thematischen Markdown-Beständen. Kein Quellcode, kein EGM-Vertrag.

## Global Invariants

- Das gesamte Repository ist ausschließlich für autorisierte Penetrationstests und Red-Team-Übungen vorgesehen; der Einsatz ohne ausdrückliche Genehmigung ist illegal [`CLAUDE.md`](../CLAUDE.md), [`kx/README.md`](../kx/README.md).
- Die kanonische Terminologie (Wurm, C2, Exfiltration, Persistenz, CVE, Payload, Vector, Reconnaissance, Lateral Movement, Privilege Escalation, IOC, Telemetrie) ist in [`GLOSSARY.md`](../GLOSSARY.md) festgeschrieben und für alle Crates verbindlich.
- Rust-Workspace: Edition 2021, MSRV 1.77, `resolver = "2"` und `panic = "unwind"` im Release-Profil gelten für alle neun Crates [`kx/Cargo.toml`](../kx/Cargo.toml). Die `ml-kem`-Version ist auf **`=0.2.3`** festgenagelt: nur `kx-core` nutzt die Bibliothek, und es bezieht sie über `workspace = true` aus dem Workspace-Manifest — es gibt damit genau eine Versionsstelle. Die frühere Umgehung (eigenständige Caret-Anforderung im Crate, aufgelöst 0.2.3 statt des gepinnten 0.2.1) ist behoben; der Wert 0.2.1 wäre zudem nicht baubar gewesen [`kx/crates/README.md`](../kx/crates/README.md).
- Die Schichtung der Crates ist strikt: `kx-core` und `kx-scanner` sind Basislagen ohne interne Crate-Abhängigkeit, `kx-agent` ist der einzige Crate, der alle Fachbereiche bindet [`kx/crates/README.md`](../kx/crates/README.md).
- `kx-win` und `kx-posix` kapseln jeden externen Effekt hinter einem `cfg`-Paar, damit der Workspace auf jeder Plattform kompiliert; die Nicht-Zielplattform-Stubs sind wirkungslos [`kx/crates/kx-win/README.md`](../kx/crates/kx-win/README.md), [`kx/crates/kx-posix/README.md`](../kx/crates/kx-posix/README.md).
- Die TLS-Schicht erzeugt ausschließlich selbstsignierte Zertifikate ohne CA-Kette; der Client-Trust-Store bleibt leer und enthält nur die übergebenen PEM-Zertifikate [`kx/crates/kx-tls/README.md`](../kx/crates/kx-tls/README.md).
- Die C2-API erzwingt das Bearer-Token über eine Middleware auf einem eigenen API-Subrouter (`route_layer`): die fünf Vertragspfade antworten ohne gültiges Token mit 401, ein unbekannter Pfad dagegen mit 404 — ein Außenstehender erfährt so nicht, ob ein Pfad existiert. Das Dashboard ist davon ausgenommen und meldet sich über `POST /api/login` an; das Token steht in einer JavaScript-Variable und nicht in der URL, sodass es nicht in Browser-Historie oder Server-Logs landet [`kx/crates/kx-server/README.md`](../kx/crates/kx-server/README.md).
- Das Dashboard escaped jeden API-Wert, bevor er in die Tabelle eingesetzt wird. Ein vom Zielsystem kontrollierter Hostname ist Fremddaten; ohne Escaping würde er in genau der Seite zu ausführbarem Markup, in der die erbeuteten Passwörter stehen [`kx/crates/kx-server/src/README.md`](../kx/crates/kx-server/src/README.md).

## Global Side Effects

- **Netzwerk (Lokal):** ARP-Sweeps auf Layer 2 und parallele TCP-Connect-Scans [`kx/crates/kx-scanner/README.md`](../kx/crates/kx-scanner/README.md). Banner-Grabs führt nur das Beispiel-Binary `kx-exploit/examples/demo_worm.rs` aus — der Agent selbst ruft `fingerprint` nicht auf.
- **Netzwerk (Remote):** SMB-Relay→DCSync läuft als `python3`-Subprozess gegen das Impacket-Skript `smbrelayx.py` [`kx/crates/kx-exploit/README.md`](../kx/crates/kx-exploit/README.md). Der WMI-/WinRM-Pfad (`wmiexec.py`) ist implementiert, hat aber **keinen Aufrufer** im Workspace.
- **Netzwerk (C2):** Agent und CLI sprechen den C2-Server über TLS mit `Authorization: Bearer`-Token an; der Agent meldet Hosts und Secrets per POST an `/api/register` und `/api/secrets`. Eine Task-Verarbeitung existiert im Agenten nicht [`kx/crates/kx-agent/README.md`](../kx/crates/kx-agent/README.md), [`kx/crates/kx-cli/README.md`](../kx/crates/kx-cli/README.md).
- **Prozesse auf Zielsystemen:** `powershell.exe`, `mimikatz.exe`, `cmd.exe`, `sc.exe`, `cmdkey.exe`, `schtasks`, `reg add` auf Windows; `systemctl` und `crontab` auf POSIX [`kx/crates/kx-win/README.md`](../kx/crates/kx-win/README.md), [`kx/crates/kx-posix/README.md`](../kx/crates/kx-posix/README.md).
- **Dateisystem auf Zielsystemen:** Anlegen von systemd-Units unter `/etc/systemd/system/`, Mutieren der Crontab des aufrufenden Users, Registry-Run-Keys und Scheduled Tasks unter Windows [`kx/crates/kx-posix/README.md`](../kx/crates/kx-posix/README.md), [`kx/crates/kx-win/README.md`](../kx/crates/kx-win/README.md).
- **Persistenz (Zentral):** Der C2-Server hält Hosts und Secrets in einer SQLite-Datenbank und liefert ein Dashboard aus [`kx/crates/kx-server/README.md`](../kx/crates/kx-server/README.md). Die Tabelle `tasks` existiert im Schema, wird aber nie befüllt — `GET /api/tasks` liefert immer `[]`.
- **Dateisystem (Export):** Der CLI-Export schreibt Secrets im Klartext in die vom Aufrufer angegebene Datei — als CSV mit den Spalten `host_id,cred_type,username,password,source,collected_at` (ohne `id`) oder als Pretty-JSON mit allen Feldern inklusive `id` [`kx/crates/kx-cli/README.md`](../kx/crates/kx-cli/README.md).
- **Schlüsselmaterial:** `kx-tls` erzeugt bei jedem Aufruf einen frischen Schlüssel aus dem OS-RNG und exponiert den privaten Schlüssel im Klartext-PEM [`kx/crates/kx-tls/README.md`](../kx/crates/kx-tls/README.md).

## System Verification

- Run: `cd /Volumes/T7/Projekte/testwurm/kx && cargo test`
- Stand (2026-11-15, macOS-Host): `cargo test --workspace` → **63 Tests grün, 0 Fehler**. `kx-scanner/src/arp.rs` ist vollständig mit `#[cfg(target_os = "linux")]` ausgezeichnet; der ARP-Sweep steht damit nur auf Linux zur Verfügung, der übrige Workspace baut und testet plattformübergreifend [`kx/crates/kx-scanner/README.md`](../kx/crates/kx-scanner/README.md).
- **Start-Smoke-Test bestanden:** `kx-server` startet und antwortet mit der API-Übersicht. Die frühere mehrdeutige `CryptoProvider`-Auflösung ist behoben — `axum-server` ist auf das Feature `tls-rustls-no-provider` umgestellt, `aws-lc-rs` verschwindet damit aus dem Lockfile, und `kx_tls::install_crypto_provider()` setzt den Provider explizit [`kx/crates/kx-tls/src/README.md`](../kx/crates/kx-tls/src/README.md).
- **Neun Funktionsdefekte** im dokumentierten Ablauf sind noch offen und als Issues unter [`.scratch/c2-operability/issues/`](../.scratch/c2-operability/issues/) erfasst, der Ablaufplan mit Abhängigkeiten in [`EPIC.md`](../.scratch/c2-operability/EPIC.md) und der Design-Entwurf für die Behebung in [`design_draft.md`](../.scratch/c2-operability/design_draft.md). Behoben sind ISSUE-1 (Serverstart), ISSUE-6 (Task-Fluss), ISSUE-8 (`ml-kem`-Pin), ISSUE-10 (systemd-Unit), ISSUE-12 (Authentifizierung) und ISSUE-13 (Dashboard-Escaping); ISSUE-2 und ISSUE-3 sind im Code ebenfalls bereits behoben, ihre Issue-Dateien aber nicht nachgezogen. Der Drift Report mit allen Einzelbefunden liegt in [`2026-11-11_DRIFT_REPORT.md`](../2026-11-11_DRIFT_REPORT.md).
