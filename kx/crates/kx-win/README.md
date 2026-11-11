# kx-win

## Overview

Blueprint des Workspace-Crates `kx-win` (Paketname `kx-win`, Lib-Target `kx_win`) — die
Windows-Post-Exploitation-Komponente des `kx`-Workspace. Das Crate bündelt zwei
Verantwortungsbereiche: Secrets-Extraktion (Windows Credential Manager, LSASS via mimikatz,
Browser-Speicherdaten) und Persistenz (Scheduled Task, Registry-Run-Key, Windows-Dienst).

Der Manifest `Cargo.toml` beschreibt das Paket mit `edition = "2021"`, `rust-version = "1.77"`
(beide aus dem Workspace übernommen), `license = "MIT"` und der Beschreibung
`Windows-Post-Exploitation: Secrets-Extraktion und Persistence`. Erklärt werden `kx-core`,
`thiserror`, `serde`, `serde_json`, `tokio` und `tracing`. `kx-core` wird zwar als Abhängigkeit
deklariert, aber von keinem Quellfile des Crates importiert — kein öffentliches Symbol stammt
aus `kx-core` [Cargo.toml:kx-core].

Der Crate ist Mitglied des Workspace `kx` (`members = ["crates/kx-win", ...]`), der die
gesamte Angriffskette modularisiert; `kx-posix` ist das plattformparallele Gegenstück für
Linux/macOS.

## Subdirectories & Boundaries

- `src`: [./src/README.md](./src/README.md) - Implementierung der öffentlichen Oberfläche:
  die Module `secrets` (Extraktion), `persist` (Persistenz) und `error` (Fehlertyp) sowie die
  `pub use`-Re-Exports am Crate-Root. Alle externen Effekte (Prozessstart, Registry-Schreibzugriff,
  Dienstinstallation) stecken ausschließlich in diesem Modulbaum.

## Interface

Rollup aus [`src/`](./src/README.md):

- `pub struct Secret` mit `secret_type`, `target`, `value` (Debug, Clone, Serialize, Deserialize) [src/secrets.rs:Secret].
- `pub async fn extract_credential_manager`, `pub async fn extract_lsass`, `pub async fn extract_browser_credentials` — Secrets-Extraktion [src/secrets.rs:extract_credential_manager] [src/secrets.rs:extract_lsass] [src/secrets.rs:extract_browser_credentials].
- `pub async fn create_scheduled_task`, `pub async fn create_registry_run_key`, `pub async fn install_service`, `pub async fn start_service` — Persistenz [src/persist.rs:create_scheduled_task] [src/persist.rs:create_registry_run_key] [src/persist.rs:install_service] [src/persist.rs:start_service].
- `pub enum WinError` mit `ToolMissing(String)`, `ToolFailed(i32, String)`, `Registry(String)`, `ScheduledTask(String)`, `Service(String)` [src/error.rs:WinError].
- Öffentliche Module `error`, `persist`, `secrets` mit Re-Exports am Crate-Root [src/lib.rs:error] [src/lib.rs:persist] [src/lib.rs:secrets].

## Invariants

Rollup aus [`src/`](./src/README.md):

- Jede der sieben öffentlichen Funktionen existiert doppelt: echte Implementierung unter `cfg(target_os = "windows")`, wirkungsloser Stub unter `cfg(not(target_os = "windows"))` — das Crate kompiliert damit auf jeder Plattform [src/secrets.rs:cfg(target_os = "windows")] [src/persist.rs:cfg(not(target_os = "windows"))].
- Die Nicht-Windows-Stubs liefern ausschließlich `Ok(Vec::new())` bzw. `Ok(())` und führen weder Prozessstart noch Schreibzugriff aus [src/secrets.rs:extract_credential_manager] [src/persist.rs:create_scheduled_task].
- `kx-core` ist als Abhängigkeit deklariert, wird aber von keinem Quellfile importiert — kein öffentliches Symbol stammt aus `kx-core` [Cargo.toml:kx-core].
- `extract_browser_credentials` liefert auch unter Windows immer eine leere Liste, weil das PowerShell-Skript ein Platzhalter ist [src/secrets.rs:extract_browser_credentials].
- `secret_type` nimmt im Code nur `"credential_manager"` und `"lsass"` an, obwohl die Doc-Kommentare zusätzlich `"browser"` und `"ssh_key"` nennen [src/secrets.rs:secret_type].
- `run_mimikatz` prüft `output.status.success()` nicht und gibt stdout unabhängig vom Exit-Code zurück — ein Fehlschlag ist nicht von einer leeren Ausgabe unterscheidbar [src/secrets.rs:run_mimikatz].
- Die Spawn-Fehler der beiden Tools werden unterschiedlich formuliert: `run_powershell` übergibt den rohen Fehlertext, `run_mimikatz` präfixiert ihn mit `mimikatz nicht gefunden: ` [src/secrets.rs:run_powershell] [src/secrets.rs:run_mimikatz].
- **Code-Bug:** `extract_credential_manager` liefert unter Windows bei **genau einem** gespeicherten Credential eine leere Liste, weil `$results | ConvertTo-Json` bei einem einzelnen Element ein JSON-Objekt statt eines Arrays erzeugt und `serde_json::from_str::<Vec<Secret>>(…).unwrap_or_default()` daran scheitert [src/secrets.rs:extract_credential_manager].
- Der Registry-Schlüsselpfad ist fest `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`; die Kommandos werden per String-Formatierung in einen Shell-String eingebettet und **ungefiltert** an `cmd.exe /C` übergeben [src/persist.rs:create_registry_run_key].
- `install_service` verlangt einen UTF-8-Pfad und lehnt sonst vor jedem Prozessstart mit `WinError::Service` ab [src/persist.rs:install_service].

## Side Effects

Rollup aus [`src/`](./src/README.md):

- Startet `powershell.exe` asynchron via `tokio::process::Command` mit `-NoProfile -ExecutionPolicy Bypass -Command`; das Credential-Manager-Skript ruft als Kindprozess `cmdkey /list | Out-String` auf — die Pipe ist für den mehrzeiligen Regex über `Target:`/`Type:`/`User:` erforderlich [src/secrets.rs:run_powershell] [src/secrets.rs:extract_credential_manager].
- Startet `mimikatz.exe` mit dem Argument `sekurlsa::logonpasswords` für den LSASS-Dump [src/secrets.rs:run_mimikatz].
- Startet `cmd.exe /C` mit `schtasks /Create /F /TN "{task_name}" /TR ""{executable}" {arguments}" /SC ONSTART /RL HIGHEST` und erzeugt damit eine Windows-Aufgabe mit Start beim Hochfahren [src/persist.rs:create_scheduled_task].
- Startet `cmd.exe /C` mit `reg add ... /t REG_SZ /f` und schreibt damit einen dauerhaften Autostart-Wert [src/persist.rs:create_registry_run_key].
- Startet `cmd.exe /C` mit `sc.exe create {service_name} binPath= "{path}" start= auto DisplayName= "{display_name}"` zur Registrierung eines Windows-Dienstes; `start_service` ruft `sc.exe` dagegen **direkt** ohne `cmd.exe`-Wrapper mit den Argumenten `["start", service_name]` auf [src/persist.rs:install_service] [src/persist.rs:start_service].
- Logging über `tracing::debug!` und `tracing::warn!`; pro extrahiertem LSASS-Credential landet der Benutzername im Log [src/secrets.rs:parse_lsass_output].
- Hält extrahierte Credentials einschließlich Klartext-Passwörter und -Hashes als serialisierbare `Secret`-Werte im Speicher [src/secrets.rs:Secret].
- Kein Dateisystem-Schreibzugriff und kein Netzwerkzugriff; sämtliche Effekte liegen in den `cfg(target_os = "windows")`-Pfaden. Die Nicht-Windows-Stubs führen zwar keinen Prozess und keinen Schreibzugriff aus, emittieren aber `debug!`-Logs [src/persist.rs:cfg(not(target_os = "windows"))] [src/secrets.rs:cfg(not(target_os = "windows"))].

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` läuft grün (59 Tests, 0 Fehler). `kx-scanner/src/arp.rs` ist
  vollständig mit `#[cfg(target_os = "linux")]` ausgezeichnet — der ARP-Sweep steht nur unter
  Linux zur Verfügung, der Rest des Workspace baut plattformübergreifend.
