# kx-posix

## Overview

Crate `kx-posix` des Kx-Workspace: POSIX-Post-Exploitation für autorisierte
Penetrationstests. Es bündelt die Linux-/Unix-Schicht des Agenten — Secrets-Extraktion
(Passwort-Hashes aus `/etc/shadow`, SSH-Private-Keys aus `$HOME/.ssh`, AWS-Credentials aus
`$HOME/.aws/credentials`) und Persistenz (systemd-Systemdienst, Cron-Eintrag).

Das Crate ist über `Cargo.toml` [Cargo.toml:package] definiert: `version`, `edition`,
`rust-version`, `license` und `authors` werden aus dem Workspace geerbt, die Beschreibung
lautet "POSIX-Post-Exploitation: Secrets-Extraktion und Persistence" [Cargo.toml:description].
Die Abhängigkeiten sind `kx-core`, `serde`, `thiserror`, `tracing` und `tokio`
[Cargo.toml:dependencies]. `kx-core` ist zwar deklariert, wird aber in keiner Datei des Crates
importiert; kein Symbol wird daher kx-core zugerechnet.

Alle Funktionen sind cross-platform kompilierbar — die eigentliche Logik läuft nur unter
`#[cfg(unix)]`, Nicht-Unix-Builds erhalten Stubs [src/secrets.rs:extract_shadow_hashes]
[src/persist.rs:install_systemd_service].

## Subdirectories & Boundaries

- [src](./src/README.md) - Vollständige Implementierung der POSIX-Post-Exploitation: `lib.rs` (Modul-Deklaration und Re-Exports), `error.rs` (Fehlerenum `PosixError`), `secrets.rs` (Extraktion von Shadow-Hashes, SSH-Keys und AWS-Credentials) und `persist.rs` (systemd- und Cron-Persistenz).

## Interface

- Öffentliche Module: `error` [src/lib.rs:error], `persist` [src/lib.rs:persist], `secrets` [src/lib.rs:secrets]
- Re-Exports auf Crate-Ebene: `PosixError` [src/lib.rs:PosixError], `install_systemd_service` [src/lib.rs:install_systemd_service], `write_cron_persistence` [src/lib.rs:write_cron_persistence], `extract_aws_credentials` [src/lib.rs:extract_aws_credentials], `extract_shadow_hashes` [src/lib.rs:extract_shadow_hashes], `extract_ssh_keys` [src/lib.rs:extract_ssh_keys], `Secret` [src/lib.rs:Secret]
- `PosixError` — Fehler-Enum mit `#[derive(Debug, thiserror::Error)]`; Varianten `ToolMissing`, `ToolFailed`, `FileAccess`, `Systemd`, `Cron` [src/error.rs:PosixError]. `ToolMissing` und `ToolFailed` werden im Crate **nirgends konstruiert** — alle Prozess- und Dateifehler werden stattdessen auf `Systemd` bzw. `Cron` abgebildet.
- `Secret` — serialisierbarer Datentyp (`#[derive(Debug, Clone, Serialize, Deserialize)]`) mit den Feldern `secret_type`, `target`, `value` [src/secrets.rs:Secret]. `target` ist je nach `secret_type` der Benutzername, der SSH-Dateiname oder `{profile}/{key}`.
- `pub async fn extract_shadow_hashes() -> Result<Vec<Secret>, PosixError>` [src/secrets.rs:extract_shadow_hashes]
- `pub async fn extract_ssh_keys() -> Result<Vec<Secret>, PosixError>` [src/secrets.rs:extract_ssh_keys]
- `pub async fn extract_aws_credentials() -> Result<Vec<Secret>, PosixError>` [src/secrets.rs:extract_aws_credentials]
- `pub async fn install_systemd_service(service_name: &str, binary_path: &Path, command: &str) -> Result<(), PosixError>` [src/persist.rs:install_systemd_service]
- `pub async fn write_cron_persistence(minute: i32, command: &str) -> Result<(), PosixError>` [src/persist.rs:write_cron_persistence]
- Unterverzeichnis: [src](./src/README.md) — Implementierung der Module `error`, `persist` und `secrets`

## Invariants

- Die drei Module sind unabhängig von der Zielplattform `pub` [src/lib.rs:error]
- Die öffentliche API des Crates wird vollständig über `pub use` auf Crate-Ebene re-exportiert [src/lib.rs:PosixError]
- Jede öffentliche POSIX-Funktion existiert doppelt: `#[cfg(unix)]` mit echter Logik und `#[cfg(not(unix))]` als Stub [src/secrets.rs:extract_shadow_hashes] [src/persist.rs:install_systemd_service]
- Die Nicht-Unix-Stubs der Extraktion liefern `Ok(vec![])` statt eines Fehlers [src/secrets.rs:extract_shadow_hashes] [src/secrets.rs:extract_ssh_keys] [src/secrets.rs:extract_aws_credentials]
- Die Nicht-Unix-Stubs der Persistenz liefern `Err(PosixError::Systemd(...))` bzw. `Err(PosixError::Cron(...))` und führen weder Datei- noch Prozesszugriff aus [src/persist.rs:install_systemd_service] [src/persist.rs:write_cron_persistence]
- Ein fehlendes `/etc/shadow` ist kein Fehler, sondern liefert `Ok(vec![])` [src/secrets.rs:extract_shadow_hashes]
- Ein fehlendes oder unlesbares `$HOME/.ssh` liefert ebenso `Ok(vec![])` statt eines Fehlers [src/secrets.rs:extract_ssh_keys]
- Eine fehlende oder unlesbare `$HOME/.aws/credentials` liefert `Ok(vec![])` [src/secrets.rs:extract_aws_credentials]
- Gesperrte Shadow-Konten werden übersprungen, wenn das Hash-Feld leer ist, exakt `!` ist oder mit `!*` beginnt [src/secrets.rs:extract_shadow_hashes]
- `$HOME` wird aus der Umgebung gelesen; Fallback ist der Literalwert `/root` [src/secrets.rs:extract_ssh_keys] [src/secrets.rs:extract_aws_credentials]
- Ein SSH-Kandidat muss eine reguläre Datei ohne `.pub`-Endung sein und im Namen `id_` beginnen oder `private` bzw. `key` enthalten [src/secrets.rs:extract_ssh_keys]
- Eine SSH-Datei wird nur übernommen, wenn ihr Inhalt die Zeichenfolge `PRIVATE KEY` enthält [src/secrets.rs:extract_ssh_keys]
- Der AWS-Profileintrag startet als `default` und wird durch Zeilen in `[...]` ersetzt; gesammelt werden nur die Schlüssel `aws_access_key_id` und `aws_secret_access_key` [src/secrets.rs:extract_aws_credentials]
- `secret_type` ist fest vorgegeben: `shadow` [src/secrets.rs:extract_shadow_hashes], `ssh_key` [src/secrets.rs:extract_ssh_keys], `aws` [src/secrets.rs:extract_aws_credentials]
- Ein `binary_path`, der kein gültiges UTF-8 ist, bricht vor jedem Schreibzugriff mit `PosixError::Systemd` ab [src/persist.rs:install_systemd_service]
- Der systemd-Unit-Text ist fest vorgegeben (`Type=oneshot`, `EnvironmentFile={env_path}`, `WorkingDirectory={binary-dir}`, `ExecStart={path} {args}`, `Restart=no`, `WantedBy={name}.timer`) [src/persist.rs:systemd_unit_content]
- Der Timer-Text ist fest vorgegeben (`OnBootSec=2min`, `OnUnitActiveSec=5min`, `Persistent=true`, `Unit={name}.service`, `WantedBy=timers.target`) [src/persist.rs:systemd_timer_content]
- Environment-, Service- und Timer-Datei werden nur geschrieben, wenn sich ihr Inhalt ändert [src/persist.rs:write_if_changed]
- `minute < 0` erzeugt die Cron-Zeile `@reboot {command}`, sonst `{minute} * * * * {command}` [src/persist.rs:write_cron_persistence]
- Enthält die bestehende Crontab bereits den Substring `command`, wird ohne Schreibzugriff `Ok(())` zurückgegeben [src/persist.rs:write_cron_persistence]
- Ein fehlgeschlagener `crontab -l`-Aufruf wird als leerer Bestand behandelt [src/persist.rs:write_cron_persistence]

## Side Effects

- Liest `/etc/shadow` über `std::fs::read_to_string` [src/secrets.rs:extract_shadow_hashes]
- Listet `$HOME/.ssh` über `std::fs::read_dir` und liest jede qualifizierte Datei vollständig ein [src/secrets.rs:extract_ssh_keys]
- Liest `$HOME/.aws/credentials` über `std::fs::read_to_string` [src/secrets.rs:extract_aws_credentials]
- Schreibt die Unit-Datei `/etc/systemd/system/{service_name}.service` und die Timer-Datei `/etc/systemd/system/{service_name}.timer` über `std::fs::write` — jeweils nur, wenn sich der Inhalt ändert [src/persist.rs:install_systemd_service] [src/persist.rs:write_if_changed]
- Startet `systemctl daemon-reload` (nur nach einer Änderung), `systemctl enable {service_name}` und `systemctl enable --now {service_name}.timer` über `tokio::process::Command` [src/persist.rs:install_systemd_service]
- Startet `crontab -l` und `crontab -`; der zusammengeführte Crontab-Text wird über stdin in den Kindprozess geschrieben und mutiert damit die Crontab des aufrufenden Users [src/persist.rs:write_cron_persistence]
- Loggt über `tracing::debug!` (Fundzahlen, erfolgreiche Installationen, vorhandener Cron-Eintrag) und `tracing::warn!` (fehlgeschlagenes `systemctl daemon-reload`) [src/secrets.rs:extract_shadow_hashes] [src/persist.rs:install_systemd_service] [src/persist.rs:write_cron_persistence]

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Das Crate bringt ein eigenes Testmodul mit (`#[cfg(test)] mod tests` mit `shadow_extracts_nothing_on_nonunix_or_missing`, `src/secrets.rs:137-147`); `cargo test -p kx-posix` führt 1 Test aus.
