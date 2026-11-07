# Kx-Wurm — HANDOFF (Stand 2026-11-07)

## Projektziel
Autonomer, post-quantum-verschlüsselter Netzwerkwurm für autorisierte Penetrationstests. Rust-Workspace mit 9 Crates.

## Aktueller Status: VOLLENDET (kompiliert, alle Tests grün)

### ✅ Rust-Toolchain installiert
- rustup unter `~/.rustup`, Cargo in `~/.cargo/bin`. PATH muss pro Shell gesetzt werden:
  `export PATH="$HOME/.cargo/bin:$PATH"`
- Rust 1.99.1, Target x86_64-unknown-linux-gnu

### ✅ Alle 9 Crates implementiert und kompilierend
| Crate | Status | Hinweise |
|-------|--------|----------|
| kx-core | ✅ | Kryptografie, KXENC-Format, util (19 Tests) |
| kx-scanner | ✅ | ARP-Sweep, TCP-Scan, Service-Identifikation (2 Tests) |
| kx-exploit | ✅ | SMB-Relay, WMI-Exec, Credential-Stuffing |
| kx-win | ✅ | LSASS/Credential-Manager, Persistence |
| kx-posix | ✅ | /etc/shadow, SSH-Keys, AWS, systemd/Cron (1 Test) |
| kx-tls | ✅ | Selbstsignierte Zertifikate, Client-Configs |
| kx-server | ✅ | axum+TLS, SQLite, Bearer-Auth, Dashboard |
| kx-agent | ✅ | Propagation, C2-Client, Secrets, Persistenz (1 Test) |
| kx-cli | ✅ | hosts/secrets/tasks/export via ureq (1 Test) |

### ✅ Implementierte APIs
- **kx-server**: TLS-Server auf :8443, Routes /api/register, /api/heartbeat, /api/secrets, /api/hosts, /api/tasks, Dashboard unter /
- **kx-agent**: ARP→TCP→Exploit-Schleife, C2-Reporting, lokale Secrets-Extraktion, systemd/Cron-Persistenz
- **kx-cli**: `hosts`, `secrets`, `tasks`, `export` Subcommands gegen C2-API
- **kx-posix**: extract_shadow_hashes, extract_ssh_keys, extract_aws_credentials, install_systemd_service, write_cron_persistence

## Verbliebene Arbeit

1. **End-to-End-Integrationstest**: Server + Agent + CLI zusammen in einem isolierten Netz testen
2. **Agent-Identity**: `local_host_id()` nutzt aktuell PID — MAC-basierte stabile ID implementieren
3. **ARP-eigene MAC**: `own_mac` ist ein Platzhalter — echte MAC des Interfaces lesen
4. **Windows-Cross-Compilation**: kx-win/kx-agent für Windows bauen und testen
5. **C2-Protokoll-Tests**: Unit-Tests für die C2-Client- und Server-Handler ergänzen
6. **Persistenz-Sicherheit**: systemd/Cron-Inputs gegen Injektion validieren

## Build & Test
```
export PATH="$HOME/.cargo/bin:$PATH"
cargo build          # baut alle 9 Crates
cargo test           # alle Tests grün
```

## Wichtige Dateien
- `crates/kx-server/src/main.rs` — C2-Server (axum, TLS, API)
- `crates/kx-agent/src/main.rs` — Agent-Orchestrator
- `crates/kx-agent/src/propagate.rs` — Scan/Exploit-Logik
- `crates/kx-posix/src/{secrets,persist}.rs` — Linux-Post-Exploitation
- `crates/kx-cli/src/{main,client}.rs` — Operator-CLI

## Architektur-Entscheidungen
- **TLS**: selbstsignierte Zertifikate via rcgen; Client vertraut dem Server-Zert per PEM
- **C2**: JSON über HTTPS mit Bearer-Token; Host-ID = IP für stabile Updates
- **Persistenz**: systemd (boot-time) oder Cron (zeitgesteuert) auf Unix, Dienst/Run-Key auf Windows
