//! Zusätzliche Signaturen unter Windows (Gegenstück zu `extrasigs.rs` unter Linux).
//!
//! Sanesecurity verteilt seine Daten über rsync und prüft sie mit gpgv; beides gibt es unter
//! Windows nicht. In dieser Fassung sind die zusätzlichen Signaturen unter Windows deshalb nicht
//! verfügbar: Der Stand in `extra-signatures.json` steht immer auf „aus“ mit einem Hinweis, und
//! jeder Abruf meldet das. Die Schnittstelle bleibt dieselbe wie unter Linux.

use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::tr;
use crate::types::{Config, ExtraSignatures, ExtraSource, ExtraStatus};

pub const SOURCE_ID: &str = "sanesecurity";
pub const SOURCE_NAME: &str = "Sanesecurity";
pub const SOURCE_URL: &str = "https://sanesecurity.com";

/// Ergebnis eines Abrufs.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub status: ExtraStatus,
    pub message: Text,
    /// Anzahl der übernommenen (neuen oder geänderten) Dateien.
    pub changed: usize,
    /// Aktive Signaturen der Quelle nach dem Lauf.
    pub signatures: u64,
}

fn unavailable() -> Text {
    tr!(
        "Zusätzliche Signaturen von Sanesecurity sind unter Windows noch nicht verfügbar.",
        "Additional signatures from Sanesecurity are not yet available on Windows."
    )
}

/// Liest extra-signatures.json. Fehlt oder ist sie unlesbar, gilt ein leerer Stand.
pub fn read_state() -> ExtraSignatures {
    fsutil::read_json(&paths::extra_sigs_state_path()).ok().flatten().unwrap_or_default()
}

/// Schreibt den Stand „unter Windows nicht verfügbar“ mit Abstand und letzter Suche von freshclam.
pub fn refresh_state(cfg: &Config) -> Result<(), Text> {
    let msg = unavailable();
    let state = ExtraSignatures {
        updated_at: crate::now_rfc3339(),
        enabled: false,
        interval_hours: cfg.signature_interval_hours,
        freshclam_last_check: freshclam_last_check(),
        sources: vec![ExtraSource {
            id: SOURCE_ID.into(),
            name: SOURCE_NAME.into(),
            url: SOURCE_URL.into(),
            status: ExtraStatus::Off,
            message: Some(msg.de_text()),
            message_en: Some(msg.en_text()),
            ..Default::default()
        }],
    };
    fsutil::write_json(&paths::extra_sigs_state_path(), &state, 0o644)
}

/// Abruf: unter Windows nicht verfügbar (Status „aus“).
pub fn run() -> Outcome {
    let cfg = crate::config::load_config().unwrap_or_default();
    let _ = refresh_state(&cfg);
    Outcome { status: ExtraStatus::Off, message: unavailable(), changed: 0, signatures: 0 }
}

/// Ausschalten: nichts zu entfernen.
pub fn disable() -> Result<Text, Text> {
    Ok(tr!("Zusätzliche Signaturen sind ausgeschaltet.", "Additional signatures are turned off."))
}

/// Beim Deinstallieren: nichts zu entfernen.
pub fn remove_all() -> Result<Text, Text> {
    disable()
}

/// Wert für `Checks` (Suchen je Tag) zu einem Abstand in Stunden.
pub fn freshclam_checks(hours: u32) -> u32 {
    24 / hours.clamp(1, 24)
}

/// Letzte Suche von freshclam (aus dessen Protokoll).
pub fn freshclam_last_check() -> Option<String> {
    crate::win::clamav::last_check()
}
