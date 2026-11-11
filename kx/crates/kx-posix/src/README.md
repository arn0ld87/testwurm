# kx-posix — Quellcode

## Overview

Implementierung des Workspace-Crates `kx-posix` (POSIX-Post-Exploitation für autorisierte
Penetrationstests). Das Verzeichnis enthält die gesamte Logik des Crates: die Modul-Deklaration
und die Re-Exports (`lib.rs`), den Fehlertyp (`error.rs`), die Secrets-Extraktion (`secrets.rs`)
und die Persistenz (`persist.rs`).

Die Extraktionsfunktionen lesen Passwort-Hashes aus `/etc/shadow`, SSH-Private-Keys aus
`$HOME/.ssh` und AWS-Credentials aus `$HOME/.aws/credentials`. Die Persistenzfunktionen
installieren einen systemd-Systemdienst unter `/etc/systemd/system/` oder einen Cron-Eintrag
über `crontab`. Jede öffentliche POSIX-Funktion existiert doppelt: eine `#[cfg(unix)]`-Variante
mit echter Logik und eine `#[cfg(not(unix))]`-Variante als Stub, damit der Crate auf
Nicht-Unix-Zielplattformen kompiliert.

`Cargo.toml` deklariert `kx-core`, `serde`, `thiserror`, `tracing` und `tokio`. `kx-core` wird
in keiner Datei dieses Verzeichnisses importiert; nachweislich verwendet werden `serde`
(`secrets.rs:6`), `thiserror` (`error.rs:4`), `tracing` (`secrets.rs:7`,
`persist.rs:7`) und `tokio` (`persist.rs:44`, `secrets.rs:141`).

## Interface

- Öffentliche Module: `error` [lib.rs:error], `persist` [lib.rs:persist], `secrets` [lib.rs:secrets]
- Re-Exports auf Crate-Ebene: `PosixError` [lib.rs:PosixError], `install_systemd_service` [lib.rs:install_systemd_service], `systemd_unit_content` [lib.rs:systemd_unit_content], `systemd_env_content` [lib.rs:systemd_env_content], `systemd_env_file_path` [lib.rs:systemd_env_file_path], `SystemdService` [lib.rs:SystemdService], `ENV_DIR` [lib.rs:ENV_DIR], `write_cron_persistence` [lib.rs:write_cron_persistence], `extract_aws_credentials` [lib.rs:extract_aws_credentials], `extract_shadow_hashes` [lib.rs:extract_shadow_hashes], `extract_ssh_keys` [lib.rs:extract_ssh_keys], `Secret` [lib.rs:Secret]
- `PosixError` — Fehler-Enum mit `#[derive(Debug, thiserror::Error)]`; Varianten `ToolMissing`, `ToolFailed`, `FileAccess`, `Systemd`, `Cron` [error.rs:PosixError]. `ToolMissing` und `ToolFailed` werden im Crate **nirgends konstruiert** — alle Prozess- und Dateifehler werden stattdessen auf `Systemd` bzw. `Cron` abgebildet.
- `Secret` — serialisierbarer Datentyp (`#[derive(Debug, Clone, Serialize, Deserialize)]`) mit den Feldern `secret_type`, `target`, `value` [secrets.rs:Secret]. `target` ist je nach `secret_type` der Benutzername, der SSH-Dateiname oder `{profile}/{key}`.
- `pub async fn extract_shadow_hashes() -> Result<Vec<Secret>, PosixError>` [secrets.rs:extract_shadow_hashes]
- `pub async fn extract_ssh_keys() -> Result<Vec<Secret>, PosixError>` [secrets.rs:extract_ssh_keys]
- `pub async fn extract_aws_credentials() -> Result<Vec<Secret>, PosixError>` [secrets.rs:extract_aws_credentials]
- `pub struct SystemdService { pub name: String, pub binary_path: PathBuf, pub args: Vec<String>, pub env: Vec<(String, String)> }` [persist.rs:SystemdService]
- `pub async fn install_systemd_service(svc: &SystemdService) -> Result<(), PosixError>` [persist.rs:install_systemd_service]
- `pub fn systemd_unit_content(svc: &SystemdService) -> String` [persist.rs:systemd_unit_content]
- `pub fn systemd_env_content(svc: &SystemdService) -> String` [persist.rs:systemd_env_content]
- `pub fn systemd_env_file_path(service_name: &str) -> PathBuf` [persist.rs:systemd_env_file_path]
- `pub const ENV_DIR: &str = "/etc/kx"` [persist.rs:ENV_DIR]
- `pub async fn write_cron_persistence(minute: i32, command: &str) -> Result<(), PosixError>` [persist.rs:write_cron_persistence]

## Invariants

- Die drei Crate-Module sind unabhängig von der Zielplattform `pub` [lib.rs:error]
- Jede öffentliche POSIX-Funktion existiert doppelt: `#[cfg(unix)]` mit echter Logik und `#[cfg(not(unix))]` als Stub [secrets.rs:extract_shadow_hashes] [persist.rs:install_systemd_service]
- Die Nicht-Unix-Stubs der Extraktion liefern `Ok(vec![])` statt eines Fehlers [secrets.rs:extract_shadow_hashes] [secrets.rs:extract_ssh_keys] [secrets.rs:extract_aws_credentials]
- Die Nicht-Unix-Stubs der Persistenz liefern `Err(PosixError::Systemd(...))` bzw. `Err(PosixError::Cron(...))` und führen weder Datei- noch Prozesszugriff aus [persist.rs:install_systemd_service] [persist.rs:write_cron_persistence]
- Ein fehlendes `/etc/shadow` ist kein Fehler, sondern liefert `Ok(vec![])` [secrets.rs:extract_shadow_hashes]
- Ein fehlendes oder unlesbares `$HOME/.ssh` liefert ebenso `Ok(vec![])` statt eines Fehlers [secrets.rs:extract_ssh_keys]
- Eine fehlende oder unlesbare `$HOME/.aws/credentials` liefert `Ok(vec![])` [secrets.rs:extract_aws_credentials]
- Gesperrte Shadow-Konten werden übersprungen, wenn das Hash-Feld leer ist, exakt `!` ist oder mit `!*` beginnt [secrets.rs:extract_shadow_hashes]
- `$HOME` wird aus der Umgebung gelesen; Fallback ist der Literalwert `/root` [secrets.rs:extract_ssh_keys] [secrets.rs:extract_aws_credentials]
- Ein SSH-Kandidat muss eine reguläre Datei ohne `.pub`-Endung sein und im Namen `id_` beginnen oder `private` bzw. `key` enthalten [secrets.rs:extract_ssh_keys]
- Eine SSH-Datei wird nur übernommen, wenn ihr Inhalt die Zeichenfolge `PRIVATE KEY` enthält [secrets.rs:extract_ssh_keys]
- Der AWS-Profileintrag startet als `default` und wird durch Zeilen in `[...]` ersetzt; gesammelt werden nur die Schlüssel `aws_access_key_id` und `aws_secret_access_key` [secrets.rs:extract_aws_credentials]
- `secret_type` ist fest vorgegeben: `shadow` [secrets.rs:extract_shadow_hashes], `ssh_key` [secrets.rs:extract_ssh_keys], `aws` [secrets.rs:extract_aws_credentials]
- Der systemd-Unit-Text ist fest vorgegeben (`Type=simple`, `EnvironmentFile={env_path}`,
  `ExecStart={path} {args}`, `Restart=always`, `RestartSec=5`,
  `WantedBy=multi-user.target`) [persist.rs:systemd_unit_content]
- Der `ExecStart` enthält **alle** Pflichtargumente des Agenten. Ein leerer
  `ExecStart` zusammen mit `Restart=always` erzeugt eine Neustart-Schleife —
  der Agent startet nie durch [persist.rs:systemd_unit_content]
- Das Token steht **nicht** im Klartext in der Unit-Datei: sie ist für jeden
  lesbar, der die Datei lesen darf. Die Unit referenziert `${KX_C2_TOKEN}`, das
  systemd aus der Environment-Datei auflöst [persist.rs:systemd_unit_content]
- Die Environment-Datei liegt unter `/etc/kx/`, **nicht** in
  `/etc/systemd/system/` — dort liest systemd jede `.service`-Datei als Unit,
  und das Verzeichnis ist für andere lesbar [persist.rs:systemd_env_file_path]
- Die Environment-Datei bekommt die Rechte 0600, ihr Verzeichnis 0700 [persist.rs:install_systemd_service]
- Die Environment-Datei wird **vor** der Unit-Datei geschrieben: fehlt sie beim
  Start des Dienstes, schlägt systemd mit einem klaren Fehler fehl, statt den
  Agenten mit leerem Token zu starten [persist.rs:install_systemd_service]
- Die Environment-Datei hat das Format `KEY=VALUE` pro Zeile — das Format, das
  systemd für `EnvironmentFile=` erwartet [persist.rs:systemd_env_content]
- `minute < 0` erzeugt die Cron-Zeile `@reboot {command}`, sonst `{minute} * * * * {command}` [persist.rs:write_cron_persistence]
- Enthält die bestehende Crontab bereits den Substring `command`, wird ohne Schreibzugriff `Ok(())` zurückgegeben [persist.rs:write_cron_persistence]
- Ein fehlgeschlagener `crontab -l`-Aufruf wird als leerer Bestand behandelt [persist.rs:write_cron_persistence]

## Side Effects

- Liest `/etc/shadow` über `std::fs::read_to_string` [secrets.rs:extract_shadow_hashes]
- Listet `$HOME/.ssh` über `std::fs::read_dir` und liest jede qualifizierte Datei vollständig ein [secrets.rs:extract_ssh_keys]
- Liest `$HOME/.aws/credentials` über `std::fs::read_to_string` [secrets.rs:extract_aws_credentials]
- Schreibt die Unit-Datei `/etc/systemd/system/{service_name}.service` über `std::fs::write` [persist.rs:install_systemd_service]
- Startet `systemctl daemon-reload` und `systemctl enable {service_name}` über `tokio::process::Command` [persist.rs:install_systemd_service]
- Startet `crontab -l` und `crontab -`; der zusammengeführte Crontab-Text wird über stdin in den Kindprozess geschrieben und mutiert damit die Crontab des aufrufenden Users [persist.rs:write_cron_persistence]
- Loggt über `tracing::debug!` (Fundzahlen, erfolgreiche Installationen, vorhandener Cron-Eintrag) und `tracing::warn!` (fehlgeschlagenes `systemctl daemon-reload`) [secrets.rs:extract_shadow_hashes] [persist.rs:install_systemd_service] [persist.rs:write_cron_persistence]

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Das Modul `secrets.rs` enthält ein eigenes Testmodul (`#[cfg(test)] mod tests` mit `shadow_extracts_nothing_on_nonunix_or_missing`, `secrets.rs:137-147`); `cargo test -p kx-posix` führt 1 Test aus.
