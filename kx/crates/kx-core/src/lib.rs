//! kx-core — plattformneutraler Kern des Encoder-Projekts.
//!
//! Schichtgrenzen (Abhängigkeitsrichtung ist vorgegeben, Band 14 §1):
//! `format` → `crypto` → `engine` → `beacon`. Das Beacon kennt den Encoder,
//! der Encoder kennt kein Beacon.
//!
//! Alles hier ist Plattformcode-frei: Windows- und POSIX-Spezifika stecken in
//! `platform::PlatformHooks`, implementiert in `kx-win` und `kx-posix`.

pub mod c2;
pub mod codec;
pub mod error;
pub mod exfil;
pub mod format;
pub mod hostkey;
pub mod kex;
pub mod kxenc;
pub mod persist;
pub mod secret;
pub mod secretbox;

pub use error::{Error, Result};

/// Formatversion, die dieser Build lesen und schreiben kann (B005).
pub const FORMAT_VERSION: u8 = 1;
/// Aeltere Formatversionen, die dieser Build noch lesen kann.
pub const READABLE_FORMAT_VERSIONS: [u8; 1] = [1];

/// Bezeichnung des Datenformats fuer Werkzeuge und Doku.
pub const FORMAT_NAME: &str = "KXENC";

/// Maximale Anzahl verschluesselter Bereiche pro Datei (Kopf + Fussteil).
/// Der Wert ist konstant, damit das Format keine variable Laenge im Footer traegt.
pub const MAX_RANGES: usize = 2;

#[cfg(test)]
mod tests {
    /// Regressionsschutz fuer die `ml-kem`-Version.
    ///
    /// `kx-core` deklarierte `ml-kem` selbst, mit einem Caret-Bereich. Der
    /// Workspace-Pin wurde dadurch umgangen, und es wurde eine andere Version
    /// aufgeloest als die im Workspace-Manifest festgeschriebene. Jetzt kommt
    /// `ml-kem` aus dem Workspace, es gibt also nur noch eine Stelle.
    ///
    /// Der Test prueft nicht die Versionsnummer, sondern ob die API noch
    /// existiert, die `hostkey.rs` benutzt. Faellt die aufgeloeste Version auf
    /// eine mit anderer API zurueck, schlaegt der Test zur Compile-Zeit fehl —
    /// das ist die eigentliche Absicherung.
    #[test]
    fn mlkem_api_used_by_hostkey_is_available() {
        // Trait-basierte API: `<MlKem768 as KemCore>::generate`.
        fn _takes_kem_core<P: ml_kem::KemCore>() {}
        _takes_kem_core::<ml_kem::MlKem768>();

        // `EncodedSizeUser` fuer die Schluessel-Kodierung — die
        // Schluesseltypen des KEM tragen es, nicht der KEM selbst.
        fn _takes_encoded_size_user<T: ml_kem::EncodedSizeUser>() {}
        _takes_encoded_size_user::<<ml_kem::MlKem768 as ml_kem::KemCore>::EncapsulationKey>();
        _takes_encoded_size_user::<<ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey>();

        // `KemCore::CiphertextSize` — die Chiffretextlaenge.
        fn _takes_array_size<T: ml_kem::ArraySize>() {}
        _takes_array_size::<<ml_kem::MlKem768 as ml_kem::KemCore>::CiphertextSize>();
    }
}
