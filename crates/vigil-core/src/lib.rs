//! Kernbibliothek von Vigil.
//!
//! Wird vom Helfer (root) und von der App (Benutzer) genutzt. Die App verwendet nur
//! lesende Teile (Datentypen, Pfade, Lesefunktionen) und den clamd-Client.
//!
//! Betriebssystem-Schichten: Module, deren Arbeitsweise sich zwischen Linux und Windows
//! grundlegend unterscheidet (Systemcheck, Zeitplan, Signaturaktualisierung, zusätzliche
//! Signaturen, sicherer Dateizugriff), haben unter Windows eine eigene Datei in `win/` mit
//! derselben Schnittstelle. Kleinere Unterschiede stehen mit `cfg` direkt im Modul.

pub mod i18n;

pub mod actions;
pub mod clamd;
pub mod config;
pub mod engine;
#[cfg_attr(windows, path = "win/extrasigs.rs")]
pub mod extrasigs;
pub mod fsutil;
pub mod lock;
pub mod paths;
pub mod pro;
pub mod quarantine;
pub mod quick;
pub mod reports;
pub mod scanner;
#[cfg_attr(windows, path = "win/schedule.rs")]
pub mod schedule;
pub mod selfupdate;
pub mod sign;
pub mod state;
pub mod sysinfo;
#[cfg_attr(windows, path = "win/systemcheck.rs")]
pub mod systemcheck;
pub mod types;
#[cfg_attr(windows, path = "win/update.rs")]
pub mod update;

#[cfg(windows)]
pub mod win;

pub mod cmd;
#[cfg_attr(windows, path = "win/secure_fs.rs")]
mod secure_fs;

pub use clamd::{clamd_socket, scan_file_stream, Verdict};
pub use i18n::{Lang, Text};
pub use types::*;

/// Version des Kerns (gleich der Paketversion von Vigil).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use std::sync::atomic::{AtomicBool, Ordering};

/// Wird vom Signal-Handler des Helfers gesetzt (SIGTERM, SIGINT, SIGHUP; unter Windows
/// Strg+C, Schließen der Konsole und Beenden des Dienstes).
/// Laufende Aufträge behandeln das wie einen Abbruch.
pub static TERMINATE: AtomicBool = AtomicBool::new(false);

/// Prüft, ob ein Abbruch angefordert wurde (Signal oder Abbruchdatei).
pub fn cancel_requested() -> bool {
    TERMINATE.load(Ordering::Relaxed) || paths::cancel_path().exists()
}

/// Liegt das Pausensignal `/var/lib/vigil/pause` vor?
pub fn pause_requested() -> bool {
    paths::pause_path().exists()
}

/// Aktuelle Zeit als RFC 3339 mit Zeitzone, z. B. `2026-10-23T12:30:05+02:00`.
pub fn now_rfc3339() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}
