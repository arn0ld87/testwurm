# kx-win/src

## Overview

Quellmodule des Crates `kx-win`. Die drei Module `secrets`, `persist` und `error` bilden die
gesamte öffentliche Oberfläche; `lib.rs` deklariert sie per `pub mod` und re-exportiert die
wesentlichen Typen und Funktionen per `pub use` am Crate-Root.

Jede der sieben öffentlichen Funktionen existiert doppelt: unter `cfg(target_os = "windows")`
mit der echten Implementierung, unter `cfg(not(target_os = "windows"))` als Stub, der ohne
Nebeneffekt `Ok(...)` zurückgibt. Das Crate kompiliert damit auf jeder Plattform; nur die
externe Wirkung ist plattformabhängig.

## Interface

- `pub struct Secret { pub secret_type: String, pub target: String, pub value: String }` —
  ableitungen `Debug`, `Clone`, `Serialize`, `Deserialize` [secrets.rs:Secret]
- `pub async fn extract_credential_manager() -> Result<Vec<Secret>, WinError>` [secrets.rs:extract_credential_manager]
- `pub async fn extract_lsass() -> Result<Vec<Secret>, WinError>` [secrets.rs:extract_lsass]
- `pub async fn extract_browser_credentials() -> Result<Vec<Secret>, WinError>` [secrets.rs:extract_browser_credentials]
- `pub async fn create_scheduled_task(task_name: &str, executable: &str, arguments: &str) -> Result<(), WinError>` [persist.rs:create_scheduled_task]
- `pub async fn create_registry_run_key(name: &str, executable: &str) -> Result<(), WinError>` [persist.rs:create_registry_run_key]
- `pub async fn install_service(service_name: &str, binary_path: &Path, display_name: &str) -> Result<(), WinError>` [persist.rs:install_service]
- `pub async fn start_service(service_name: &str) -> Result<(), WinError>` [persist.rs:start_service]
- `pub enum WinError` mit den Varianten `ToolMissing(String)`, `ToolFailed(i32, String)`,
  `Registry(String)`, `ScheduledTask(String)`, `Service(String)`; `thiserror::Error` [error.rs:WinError]
- Module `error`, `persist`, `secrets` — in `lib.rs` als `pub mod` deklariert und per `pub use`
  re-exportiert (`WinError`, `Secret`, `extract_*`, `create_*`, `install_service`, `start_service`) [lib.rs:pub mod error]
- Private Helfer, nicht am Crate-Root exportiert: `run_powershell`, `run_mimikatz` und
  `parse_lsass_output` sind nur unter `cfg(target_os = "windows")` kompiliert,
  `parse_secrets_from_json` zusätzlich unter `cfg(test)` — der JSON-Parser wird
  ohne Windows-Zielsystem getestet [secrets.rs:run_powershell]

## Invariants

- Auf Nicht-Windows-Zielen sind alle öffentlichen Funktionen effektlose Erfolgsoperationen: die
  drei Extraktionsfunktionen liefern `Ok(Vec::new())`, die vier Persistenzfunktionen `Ok(())`.
  Es wird kein Prozess gestartet und nichts geschrieben [secrets.rs:extract_credential_manager]
  [persist.rs:create_scheduled_task]
- Die Parameter der Nicht-Windows-Stubs werden nicht ausgewertet (Unterstriche-Präfix), Aufruferwerte
  haben dort also keine Wirkung [persist.rs:install_service]
- `parse_secrets_from_json` kann kein `Err` liefern: eine leere Ausgabe ergibt einen leeren `Vec`,
  ein einzelnes JSON-Objekt wird zu einer Liste mit einem Eintrag, und jeder andere unlesbare
  Inhalt erzeugt eine `warn!`-Meldung und einen leeren `Vec` [secrets.rs:parse_secrets_from_json]
- `extract_browser_credentials` liefert deshalb auch unter Windows immer eine leere Liste: das
  PowerShell-Skript ist ein Platzhalter (`ConvertTo-Json -InputObject @()`) [secrets.rs:extract_browser_credentials]
- `parse_lsass_output` erzeugt nur dann ein `Secret`, wenn die Zeile das exakte Trennmuster `": "`
  enthält und beide Teile nicht leer sind; `secret_type` ist dabei fest auf `"lsass"` gesetzt,
  `target` ist der Text davor, `value` der Text danach [secrets.rs:parse_lsass_output]
- `extract_credential_manager` setzt `secret_type` fest auf `"credential_manager"`, `target` stammt
  aus der cmdkey-`Target:`-Capture-Gruppe, `value` aus der `User:`-Capture-Gruppe [secrets.rs:extract_credential_manager]
- `extract_credential_manager` liefert unter Windows auch bei **genau einem** gespeicherten
  Credential eine Liste mit einem Eintrag: das PowerShell-Skript serialisiert mit
  `ConvertTo-Json -InputObject @($results)` immer ein Array, und der Parser akzeptiert
  zusätzlich ein einzelnes JSON-Objekt [secrets.rs:extract_credential_manager]
- `secret_type` nimmt im Code nur die Literale `"credential_manager"` und `"lsass"` an; die
  Doc-Kommentare nennen zusätzlich `"browser"` und `"ssh_key"`, die kein Codepfad erzeugt [secrets.rs:secret_type]
- `run_powershell` startet `powershell.exe` immer mit den festen Flags `-NoProfile`,
  `-ExecutionPolicy Bypass`, `-Command` [secrets.rs:run_powershell]
- Fehlerabbildung der Tool-Aufrufe: ein Spawn-Fehler wird zu `WinError::ToolMissing`, ein
  nicht-nuller Exit-Status zu `WinError::ToolFailed(code, stderr)` mit
  `code = output.status.code().unwrap_or(-1)` — `-1` ist der Sentinel bei fehlendem Exit-Code [secrets.rs:run_powershell]
- `run_mimikatz` prüft `output.status.success()` nicht und gibt stdout unabhängig vom Exit-Code
  zurück; ein fehlgeschlagener mimikatz-Lauf ist damit nicht von einem leeren unterscheidbar [secrets.rs:run_mimikatz]
- `install_service` verlangt einen UTF-8-fähigen Pfad; ein nicht darstellbarer Pfad wird vor jedem
  Prozessstart mit `WinError::Service("ungültiger Pfad")` abgelehnt [persist.rs:install_service]
- Feste Kommando-Schalter: Scheduled Task mit `/F` (überschreiben), `/SC ONSTART` (Start beim
  Hochfahren) und `/RL HIGHEST`; Registry-Wert als `REG_SZ` mit `/f`; Dienst mit `start= auto` [persist.rs:create_scheduled_task]
  [persist.rs:create_registry_run_key] [persist.rs:install_service]
- Registry-Schlüsselpfad fest: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` [persist.rs:create_registry_run_key]
- Die drei Persistenzbefehle werden per String-Formatierung in einen einzelnen Shell-String
  eingebettet und ungefiltert an `cmd.exe /C` übergeben — interpolierte Werte werden nicht auf
  Shell-Metazeichen geprüft oder maskiert [persist.rs:create_scheduled_task] [persist.rs:create_registry_run_key]
  [persist.rs:install_service]
- Unter Windows geben die Persistenzfunktionen bei nicht-nuller Exit-Status `Err` mit dem
  dekodierten stderr zurück; `Ok(())` nur bei erfolgreichem Kommando [persist.rs:start_service]
- Die Fehlervarianten sind je nach Funktion fest zugeordnet: `ScheduledTask` für Scheduled Task,
  `Registry` für den Run-Key, `Service` für Dienstinstallation und -start [persist.rs:create_scheduled_task]
  [persist.rs:create_registry_run_key] [persist.rs:install_service]
- Die Display-Texte von `WinError` sind über die `thiserror`-Formatattribute festgelegt
  (`"Tool nicht verfügbar: {0}"`, `"Tool fehlgeschlagen (Code {0}): {1}"`, `"Registry-Fehler: {0}"`,
  `"Scheduled-Task-Fehler: {0}"`, `"Dienst-Fehler: {0}"`) [error.rs:ToolMissing] [error.rs:ToolFailed]
- Das Crate deklariert `kx-core` als Abhängigkeit, verwendet es aber in keinem Quellfile — kein
  öffentliches Symbol dieses Crates stammt aus `kx-core` [Cargo.toml:kx-core]

## Side Effects

- Startet `powershell.exe` (asynchron über `tokio::process::Command`, stdout und stderr gepiped)
  mit einem Inline-Skript über `-Command` [secrets.rs:run_powershell]
- Startet `mimikatz.exe` mit dem Argument `sekurlsa::logonpasswords` [secrets.rs:run_mimikatz]
  [secrets.rs:extract_lsass]
- Das Credential-Manager-Skript ruft als Kindprozess `cmdkey /list | Out-String` auf und parst dessen Ausgabe — die `Out-String`-Pipe ist für den mehrzeiligen Regex über `Target:`/`Type:`/`User:` erforderlich [secrets.rs:extract_credential_manager]
- Startet `cmd.exe /C` mit `schtasks /Create /F /TN "{task_name}" /TR ""{executable}" {arguments}" /SC ONSTART /RL HIGHEST`
  — erzeugt eine Windows-Aufgabe, die das Programm beim Hochfahren mit höchster Berechtigung startet [persist.rs:create_scheduled_task]
- Startet `cmd.exe /C` mit `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v {name} /t REG_SZ /d "{executable}" /f`
  — schreibt einen dauerhaften Autostart-Wert in die Registry [persist.rs:create_registry_run_key]
- Startet `cmd.exe /C` mit `sc.exe create {service_name} binPath= "{path}" start= auto DisplayName= "{display_name}"`
  — registriert einen neuen Windows-Dienst mit Autostart [persist.rs:install_service]
- Startet `sc.exe` direkt, ohne `cmd.exe`-Wrapper, mit den Argumenten `["start", service_name]`
  — startet einen bereits installierten Dienst [persist.rs:start_service]
- Schreibt pro extrahiertem LSASS-Credential ein `debug!`-Log mit dem Text
  `"LSASS-Credential für {user}"`; der Benutzername landet damit im Log [secrets.rs:parse_lsass_output]
- Loggt in den Nicht-Windows-Stubs per `debug!` (z. B. `"LSASS-Dump nur auf Windows verfügbar"`,
  `"Scheduled Tasks nur auf Windows verfügbar"`) [secrets.rs:extract_lsass] [persist.rs:create_scheduled_task]
- Loggt bei Fehlschlag per `warn!` die stderr-Ausgabe des jeweiligen Kindprozesses
  (`"PowerShell fehlgeschlagen: {err}"`, `"schtasks fehlgeschlagen: {err}"`,
  `"Registry-Run-Key fehlgeschlagen: {err}"`, `"sc.exe create fehlgeschlagen: {err}"`,
  `"sc.exe start fehlgeschlagen: {err}"`) [secrets.rs:run_powershell] [persist.rs:create_scheduled_task]
- Die Spawn-Fehler der beiden Tools werden unterschiedlich formuliert: `run_powershell` übergibt
  den rohen Fehlertext (`secrets.rs:85`), `run_mimikatz` präfixiert ihn mit
  `"mimikatz nicht gefunden: "` (`secrets.rs:103`) [secrets.rs:run_powershell] [secrets.rs:run_mimikatz]
  `"Registry-Run-Key fehlgeschlagen: {err}"`, `"sc.exe create fehlgeschlagen: {err}"`,
  `"sc.exe start fehlgeschlagen: {err}"`) [secrets.rs:run_powershell] [persist.rs:create_scheduled_task]
  [persist.rs:create_registry_run_key] [persist.rs:install_service] [persist.rs:start_service]
- Loggt Erfolg per `debug!` mit `"Scheduled Task {task_name} erstellt"`, `"Registry-Run-Key {name} erstellt"`
  und `"Dienst {service_name} installiert"`; `start_service` hat im Erfolgsfall keinerlei Logging [persist.rs:create_scheduled_task]
  [persist.rs:create_registry_run_key] [persist.rs:install_service] [persist.rs:start_service]
- Hält extrahierte Credentials einschließlich Klartext-Passwörtern und -Hashes als `Secret`-Werte
  im Speicher, die über `serde` serialisierbar sind [secrets.rs:Secret] [secrets.rs:value]
- Kein Dateisystem-Schreibzugriff und kein Netzwerkzugriff; sämtliche Effekte liegen in den
  `cfg(target_os = "windows")`-Pfaden [secrets.rs:cfg(not(target_os = "windows"))] [persist.rs:cfg(not(target_os = "windows"))]

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test -p kx-win` läuft grün (0 Tests, keine Testmodule im Crate). Der
  workspace-weite Lauf ist grün — `kx-scanner/src/arp.rs` ist inzwischen vollständig mit
  `#[cfg(target_os = "linux")]` ausgezeichnet. Die Linux-only-Symbole (`libc::sockaddr_ll`,
  `AF_PACKET` — Linux-only) und zieht `kx-exploit` sowie `kx-agent` mit; `kx-win` ist davon
  nicht betroffen.
