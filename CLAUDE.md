# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`testwurm` ist ein Repository für **autorisierte** Penetrationstests und Red-Team-Übungen.
Der einzige Quellcode-Baum ist [`kx/`](./kx/README.md): ein Cargo-Workspace in Rust mit
neun Crates unter `kx/crates/`, die zusammen einen autonomen Netzwerkwurm bilden. Die
Angriffspfad-Kette lautet Entdeckung → Scan → Exploit → Extraktion → Persistenz →
Reporting (C2).

- **`kx/`** — Rust-Workspace (`Cargo.toml`, `crates/`, `docs/00-recherche-phase0.md`,
  `HANDOFF.md`, Build-Artefakte in `kx/target/`).
- **`README.md`** — Betriebshandbuch für Menschen: Installation, Einsatz, Steuerung,
  API-Referenz, Troubleshooting, Sicherheits-Härtung.
- **`docs/egm-blueprint.md`** — Repository-Blueprint (Systemgrenzen, Invarianten,
  Side Effects, Verification) — der maschinenlesbare Vertrag.
- **`docs/agents/`** — Agent-Konventionen (Issue-Tracker, Domain-Doku).
- **`docs/adr/`** — Architekturentscheidungen (aktuell `0001-c2-antworttypen-strikt-request-typen-lenient.md`).
- **`GLOSSARY.md`** — kanonische Terminologie, für alle Crates verbindlich.
- **`wissen/`** — Recherche-Wissenssammlung (Markdown, kein Quellcode).
- **`.scratch/c2-operability/`** — Arbeitsvorrat: `EPIC.md`, `design_draft.md` und 14
  erfasste Funktionsdefekte unter `issues/`.
- **`2026-11-11_DRIFT_REPORT.md`** — Drift Report aus dem EGM-Review: 14 Code-Befunde,
  die in die 13 Issues eingeflossen sind. Historische Quelle, nicht gepflegt.
- **`AGENTS.md`** — Codex-Spiegel dieser Datei. Bei Änderungen an den Regeln beide
  synchron halten.

Das Repository-Root enthält keinen Code; die Architektur beginnt unter `kx/`.

## Development Environment

- **Sprache/Toolchain:** Rust, Edition 2021, `resolver = "2"`, MSRV 1.77
  (`rustc 1.99.1` verifiziert auf dem macOS-Host). Cargo-Arbeitsverzeichnis ist
  ausschließlich `kx/` — der Workspace-Root ist `kx/`, nicht das Repo-Root.
- **PATH:** `export PATH="$HOME/.cargo/bin:$PATH"`, falls rustup pro Shell frisch.
- **Tests:** `cargo test --workspace` — 73 Tests grün, 0 Fehler.
- **Qualität:** `cargo fmt --check` ist grün und wird in der CI **erzwungen**
  (seit Commit 825511b ist der Workspace formatiert). `cargo clippy
  --workspace --all-targets` meldet noch einige Warnungen — clippy ist bewusst
  **kein** CI-Gate und gehört in einen eigenen Arbeitsstrang.

## Common Development Commands

Alle Kommandos laufen aus `kx/` (Workspace-Root):

```bash
cd /Volumes/T7/Projekte/testwurm/kx
export PATH="$HOME/.cargo/bin:$PATH"

# Bauen (CI-Matrix: Ubuntu und macOS)
cargo build --workspace --all-targets

# Tests (63 grün); gezielt ein Crate:
cargo test --workspace
cargo test -p kx-core

# Ein einzelner Test (Pfad oder Name des Testfalls):
cargo test -p kx-core c2::tests::host_deserializes_from_server_json
cargo test -p kx-server create_task_fills_the_task_table -- --exact

# Release-Build des C2-Servers (Smoke-Job der CI)
cargo build --release -p kx-server

# Formate und Lints ansehen (nicht erzwingen — see Development Environment)
cargo fmt --check
cargo clippy --workspace --all-targets
```

**Server-Smoke gegen das laufende System** (deckt Defekte auf, die der Unit-Test
nicht sieht — ISSUE-1 Start-Panic, ISSUE-12 offene API):

```bash
./target/release/kx-server --host 127.0.0.1 --port 18443 --db /tmp/kx-ci.db --token ci-token &
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:18443/api/hosts                       # 401
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer falsch' \
  https://127.0.0.1:18443/api/hosts                                                       # 401
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer ci-token' \
  https://127.0.0.1:18443/api/hosts                                                       # 200
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer ci-token' \
  https://127.0.0.1:18443/gibtsnicht                                                      # 404

# Task anlegen (Welle 2) — danach liefert GET /api/tasks den Eintrag:
curl -sk -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Authorization: Bearer ci-token' -H 'Content-Type: application/json' \
  -d '{"host_id":"10.0.0.5","command":"whoami"}' \
  https://127.0.0.1:18443/api/tasks/new                                                # 201
```

**Cargo-Aliase** aus `kx/.cargo/config.toml`: `cargo kx-agent`, `cargo kx-agent-sys`,
`cargo kx-server`, `cargo kxctl`, `cargo kx-test` (bauen die Crates im
Release-Profil). Hinweis: Der Alias `kx-agent-sys` übergibt `--features syscalls`,
obwohl in keinem Manifest ein Feature `syscalls` deklariert ist — dokumentierte Drift.

## CI-Gates

`.github/workflows/ci.yml` ist das einzige Gate; es läuft bei Push auf `main`,
`feat/**`, `fix/**` und bei jedem PR.

- **build-and-test** — Matrix `ubuntu-latest` + `macos-latest`: `cargo build
  --workspace --all-targets` und `cargo test --workspace`. Der Workspace muss auf
  beiden Plattformen bauen.
- **server-smoke-test** (`ubuntu-latest`) — startet das Release-Binary und prüft
  die Authentifizierung am laufenden System. Fängt genau die Defekte, die ein
  reiner Testlauf nicht sieht.
- **fmt-Gate** — `cargo fmt --check` läuft im Build-Job mit und ist grün.
- **Bewusst kein clippy-Gate** — clippy meldet noch Warnungen; das gehört in einen
  eigenen Arbeitsstrang, nicht in einen funkspezifischen PR.

Ein PR ist erst mergefertig, wenn beide Jobs grün sind.

## Architecture

### Die neun Crates (`kx/crates/`)

| Crate        | Aufgabe                                              |
|--------------|------------------------------------------------------|
| `kx-core`    | KXENC-Dateiformat, Fehlerklassifikation, C2-Protokoll (`c2`), Hilfsfunktionen (`util`); `hostkey` (Hybrid-KEM) ist auskommentiert und wird nicht kompiliert |
| `kx-scanner` | ARP-Hostentdeckung (`arp_sweep`), TCP-Portscan (`scan_tcp`), `fingerprint` |
| `kx-exploit` | SMB-Relay (`smb_relay_dcsync`), WMI-Exec, Credential-Stuffing (`try_default_credentials`) via Impacket |
| `kx-win`     | Windows-Secrets (LSASS, Credential Manager, Browser) + Persistenz (Dienst, Run-Key, Scheduled Task) |
| `kx-posix`   | POSIX-Secrets (`/etc/shadow`, SSH, AWS) + Persistenz (systemd-Unit, Cron) |
| `kx-tls`     | selbstsignierte Zertifikate (`generate_server_tls`), rustls-Configs (`client_config_trusting`) |
| `kx-server`  | C2-Backend: axum-API, SQLite (`hosts`, `secrets`, `tasks`), HTML-Dashboard |
| `kx-agent`   | der autonome Wurm: orchestriert Scanner → Exploit → Secrets → Persistenz → C2-Report |
| `kx-cli`     | Operator-CLI (`hosts`, `secrets`, `export --format json|csv`, `tasks`) |

Schichtung: `kx-core` und `kx-scanner` sind Basislagen ohne interne
Crate-Abhängigkeit; `kx-agent` ist der einzige Crate, der sechs interne Crates
einbindet. Interne Abhängigkeiten sind ausschließlich `path`-Dependencies über
`workspace = true`.

Datenfluss: `kx-agent` scannt und exfiltriert, meldet per `POST /api/register`
und `POST /api/secrets` an den `kx-server`; der Server schreibt in SQLite
(`hosts`, `secrets`, `tasks`) und liefert das HTML-Dashboard; `kx-cli` liest
dieselben Daten per GET. Es gibt **keinen** Task-Abruf im Agenten — der Server
kann Tasks anlegen, der Agent holt sie aber nicht ab.

### Der C2-Wire-Vertrag (ADR-0001)

`kx_core::c2` ist die *einzige* Definition des C2-Protokolls. Agent, Server und
CLI importieren alle aus diesem Modul — Pfad-Konstanten (`PATH_REGISTER`,
`PATH_HOSTS`, `PATH_TASKS`, …) und Typen liegen dort, nicht im Server und nicht
in der CLI. Wer einen Pfad oder ein Feld nur an einer Stelle ändert, bricht den
Vertrag.

- **Antworttypen** (`Host`, `ExfiltratedSecret`, `Task`) tragen
  `#[serde(deny_unknown_fields)]` — streng. Sie werden vom Server erzeugt und vom
  Client gelesen; hier entsteht der Schaden, also bricht es hier laut.
- **Request-Typen** (`RegisterRequest`, `HeartbeatRequest`, `SecretUpload`,
  `CreateTaskRequest`) sind lenient — unbekannte Felder werden ignoriert. Ein
  neuerer Agent darf ein Feld ergänzen, ohne einen älteren Server zu brechen.
- **Die Datenbankzeile ist nicht der Wire-Typ.** `kx-server` hält
  `HostRow`/`SecretRow`/`TaskRow` ohne serde und wandelt sie über `From` in die
  Vertragstypen. Eine Schema-Änderung bricht den Wire-Vertrag nicht und umgekehrt.
- Die **Host-Kennung** kommt aus dem Request und wird nicht mehr aus der IP
  abgeleitet — Registrierung und Secret-Upload können nicht mehr auseinanderlaufen.
  Eine leere `host_id` lehnt der Server mit 400 ab.
- Die Absicherung des Vertrags liegt in `kx-core/src/c2.rs`: Golden-JSON-Fixtures
  plus ein **Key-Set-Pinning**, das die exakte Feldmenge jedes Typs festschreibt.
  Eine Umbenennung in einem Antworttyp bricht diesen Test — und damit die
  Operatorsicht, nicht erst den Betrieb.

Konsequenz für Änderungen: ein neues Feld in einem **Antworttyp** erfordert Server
*und* Client gleichzeitig; ein neues Feld in einem **Request-Typ** nur den Client.

Die Felder `sealed_master` und `master_key` sind bereits Teil des Vertrags, werden
vom Agenten aber als `None` gesendet — das KEM-Modul `kx-core/src/hostkey.rs` ist
nicht aktiv (ISSUE-9). Server und Agent müssen beide Felder tolerant behandeln,
bis das Material wirklich erzeugt wird.

### Binaries und API

- `kx-server`: `--host` (`127.0.0.1`), `--port` (`8443`), `--db` (`kx.db`), `--token`
  (Env `KX_SERVER_TOKEN`), `--cn` (`kx.local`). Zertifikat und Schlüssel bleiben im
  Speicher; es wird keine `kx-server.crt`/`.key` geschrieben.
- `kx-agent`: `--server`/`--token` (Env `KX_C2_URL`/`KX_C2_TOKEN`), `--server-cert`,
  `--iface` (`eth0`), `--start`/`--end` (Pflichtargumente), `--own-ip`, `--hosts`,
  `--relay-script`, `--wmi-script`.
- `kx-cli`: globale Flags `--server`, `--token`, `--cert`; Subcommands `hosts`,
  `secrets --user`, `export <pfad> --format`, `tasks`, `task-create --host-id --command`.
- Routen (Bearer-Auth per `route_layer(require_auth)`, constant-time): `POST
  /api/register`, `POST /api/heartbeat`, `POST /api/secrets`, `GET /api/hosts`,
  `GET /api/secrets`, `GET /api/tasks`, `POST /api/tasks/new` (Task anlegen),
  `POST /api/tasks/result` (Task-Ergebnis melden); dazu `GET /` (Dashboard) und
  `POST /api/login`. Der Login-Pfad steht bewusst neben dem geschützten
  API-Subrouter.
- Der Agent holt offene Tasks über `GET /api/tasks`, führt sie aus und meldet das
  Ergebnis über `POST /api/tasks/result` zurück — der Task-Fluss läuft über beide
  Enden (ISSUE-6, geschlossen).

## Platform Notes

- `kx-scanner/src/arp.rs` ist vollständig `#[cfg(target_os = "linux")]` (rohe
  `AF_PACKET`-Sockets über die `libc`-Crate, kein libpcap); der ARP-Sweep existiert
  nur unter Linux, alle anderen Crates sind plattformübergreifend baubar.
- `kx-win`/`kx-posix` kapseln jeden externen Effekt hinter
  `cfg(target_os = "windows")`- bzw. `#[cfg(unix)]`-Paaren; die Stubs der
  Nicht-Zielplattform sind wirkungslos. Windows-Target: `rustup target add
  x86_64-pc-windows-gnu`.
- Für den ARP-Betrieb braucht das Agent-Binary `CAP_NET_RAW`
  (`sudo setcap cap_net_raw+ep ./target/release/kx-agent`).

## Invariants (Auswahl — vollständig in `kx/README.md` und `kx/crates/README.md`)

- Der C2-Wire-Vertrag lebt ausschließlich in `kx-core/src/c2.rs` — Pfade und Typen
  an einer Stelle, nicht je Crate (siehe ADR-0001).
- `ml-kem` ist im Workspace-Manifest auf `=0.2.3` festgenagelt (kein 0.3.x: hebt
  `rand_core` auf 0.10 und bricht `x25519-dalek 2`/`rand 0.8`); `kx-core` bezieht es
  über `workspace = true`, es gibt damit genau eine Versionsstelle.
- `panic = "unwind"` im Release-Profil bleibt aktiv, weil der Encoder pro Datei
  einen Panic abfängt; `[profile.dev] opt-level = 1`, weil Tests im Debug-Profil
  laufen.
- `kx-tls` erzeugt ausschließlich selbstsignierte Zertifikate ohne CA-Kette; der
  Client lädt keinen System-Trust-Store.
- Das Dashboard escaped jeden API-Wert; das Token kommt aus dem Login-Formular,
  nicht aus dem Query-String.
- `kx-core/src/hostkey.rs` ist auskommentiert (`pub mod hostkey;` in `lib.rs` ist
  deaktiviert) — die Hybrid-KEM-Verschlüsselung der Beute ist damit nicht aktiv.

## Known Defects / Arbeitsvorrat

Vierzehn Funktionsdefekte sind als Markdown-Issues unter
`.scratch/c2-operability/issues/` erfasst; der Ablaufplan mit Abhängigkeiten
liegt in `EPIC.md`, der Designentwurf (Wellenplan, Entscheidungen D1–D7) in
`design_draft.md`.

**Welle 1 (Betrieb herstellen) ist abgeschlossen:** ISSUE-1 (Serverstart),
ISSUE-8 (`ml-kem`-Pin), ISSUE-10 (systemd-Unit), ISSUE-12 (API-Authentifizierung),
ISSUE-13 (Dashboard-Escaping, Token im Query-String).

**Noch offen (Welle 2):** ISSUE-2 (SMB-Relay toter Code — Port 445 fehlt in
`COMMON_PORTS`), ISSUE-3 (`try_default_credentials` liefert stets `Ok(None)`),
ISSUE-4 (Credential Manager liefert bei genau einem Credential eine leere Liste),
ISSUE-5 (Doc-Fix `--range`),
ISSUE-7 (`wmi_exec` ohne Aufrufer), ISSUE-9 (Post-Quantum-Verschlüsselung inaktiv),
ISSUE-11 (Token im Debug-Output), ISSUE-14 (Agent hängt im SSH-Default-Credential-Test).

**Anmerkung zum Status:** ISSUE-2 und ISSUE-3 sind im Code bereits behoben
(Commit `4b6e179`: Port 445/3389 in `COMMON_PORTS`, `sshpass`-basierter
Credential-Test). Die Issue-Dateien sind dazu noch nicht nachgezogen.

**Dokumentations-Drift:** Der Modul-Doc von `kx-core/src/lib.rs` beschreibt noch
eine Schichtung `format → crypto → engine → beacon` aus einem Vorgängerprojekt —
die Crates dieses Workspace heißen anders. Ebenso verweist
`kx/.cargo/config.toml` auf ein `scripts/build.sh`, das es nicht gibt.

## Security Considerations

Alle Tools sind für **autorisierte** Penetrationstests gedacht. Vor aktiven Scans
den Scope verifizieren; Plugins/Wrapper (z. B. `AKCodez/hackingtool-plugin`) den
ad-hoc-Shell-Loops vorziehen. Relevante Punkte: klare Scope-Grenzen,
Bearer-Token als Zugriffsschlüssel, Klartext-Passwörter und NT-Hashes in Logs und
Exporten, Kill-Switch-Charakter der Propagation, Persistenz nach dem Test
entfernen.

## Code Organization

```
kx/
├── Cargo.toml              # Workspace: members, [workspace.package], [workspace.dependencies], Profile
├── .cargo/config.toml      # Build-Hygiene und Cargo-Aliase
├── docs/00-recherche-phase0.md
├── HANDOFF.md              # Übergabenotiz zum Arbeitsstand
└── crates/
    ├── kx-core/            # c2.rs (Wire-Vertrag), format.rs, error.rs, util.rs, hostkey.rs (inaktiv)
    ├── kx-scanner/         # arp.rs (nur Linux), tcp_scan.rs, fingerprint.rs
    ├── kx-exploit/         # smb_relay.rs, wmi_exec.rs, credential_stuff.rs, payload.rs, examples/
    ├── kx-win/             # secrets.rs, persist.rs
    ├── kx-posix/           # secrets.rs, persist.rs
    ├── kx-tls/             # lib.rs (rustls/rcgen)
    ├── kx-server/          # main.rs, auth.rs, db.rs, dashboard.rs
    ├── kx-agent/           # main.rs, propagate.rs, c2.rs
    └── kx-cli/             # main.rs, client.rs
```

Jedes Crate hat eine `README.md`, die Module haben eine `README.md` in `src/` —
dort steht der Vertrag des jeweiligen Moduls, der beim Ändern mitgeführt werden muss.

## Agent skills

### Issue tracker

Local markdown issues under `.scratch/<feature>/issues/`. Datei-Name
`ISSUE-<nummer>-<kurzbeschreibung>.md`, YAML-Frontmatter mit `id`, `title`,
`status` (`open` / `in-progress` / `done` / `blocked` / `wontfix`), `priority`,
danach `Description`, `Acceptance Criteria`, `Technical Notes`. Verwandte Issues
über `Related: ISSUE-<n>` verlinken. Issue-IDs in Commits und PRs referenzieren.
Details: `docs/agents/issue-tracker.md`.

### Domain docs

Single-context layout mit `GLOSSARY.md` und `docs/adr/` im Repo-Root. Neue
Begriffe in `GLOSSARY.md`, neue Entscheidungen als neue ADR in `docs/adr/` im
Format `ADR-<n>: <Titel>` mit `Status`, `Date`, `Context`, `Decision`,
`Consequences`. Vor dem Implementieren neuer Features und beim Review konsultieren.
Details: `docs/agents/domain.md`.
