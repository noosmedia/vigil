//! Pfade von Vigil. Mit `VIGIL_DEV=1` ersetzen `VIGIL_DATA_DIR` und `VIGIL_CONFIG_DIR`
//! die Ordner `/var/lib/vigil` und `/etc/vigil` (Tests ohne root).
//!
//! Unter Windows: Daten unter `C:\ProgramData\Vigil`, Konfiguration unter
//! `C:\ProgramData\Vigil\config`, Programme im Installationsordner (Ordner des laufenden
//! Programms, z. B. `C:\Program Files\Vigil`). Die Kommentare der einzelnen Funktionen nennen
//! die Linux-Pfade.

use std::env;
use std::path::{Path, PathBuf};

/// Standard-Datenordner.
#[cfg(unix)]
pub const DEFAULT_DATA_DIR: &str = "/var/lib/vigil";
/// Standard-Konfigurationsordner.
#[cfg(unix)]
pub const DEFAULT_CONFIG_DIR: &str = "/etc/vigil";
/// Installationsort der Helfer.
#[cfg(unix)]
pub const LIB_DIR: &str = "/usr/lib/vigil";

/// Testbetrieb aktiv (`VIGIL_DEV=1`)?
pub fn is_dev() -> bool {
    env::var("VIGIL_DEV").map(|v| v == "1").unwrap_or(false)
}

/// Liest eine Umgebungsvariable nur im Testbetrieb (sonst immer `None`).
pub fn dev_override(name: &str) -> Option<PathBuf> {
    if !is_dev() {
        return None;
    }
    match env::var_os(name) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// Liest einen Text aus einer Umgebungsvariablen, nur im Testbetrieb (sonst immer `None`).
pub fn dev_value(name: &str) -> Option<String> {
    if !is_dev() {
        return None;
    }
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// Ordner der Helfer und von Vigil Pro (`/usr/lib/vigil`). Im Testbetrieb überschreibt `VIGIL_LIB_DIR`.
pub fn lib_dir() -> PathBuf {
    dev_override("VIGIL_LIB_DIR").unwrap_or_else(default_lib_dir)
}

#[cfg(unix)]
fn default_lib_dir() -> PathBuf {
    PathBuf::from(LIB_DIR)
}

/// Unter Windows liegen App, Helfer und Vigil Pro im Installationsordner, also neben dem
/// laufenden Programm. Ein Pfad aus der Umgebung wird bewusst nicht genutzt.
#[cfg(windows)]
fn default_lib_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\Vigil"))
}

/// Installierte Pro-Dateien (`/usr/lib/vigil/pro`).
pub fn pro_dir() -> PathBuf {
    lib_dir().join("pro")
}

/// Datenordner (`/var/lib/vigil`).
pub fn data_dir() -> PathBuf {
    dev_override("VIGIL_DATA_DIR").unwrap_or_else(default_data_dir)
}

#[cfg(unix)]
fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}

/// `C:\ProgramData\Vigil`
#[cfg(windows)]
fn default_data_dir() -> PathBuf {
    crate::win::program_data().join("Vigil")
}

/// Konfigurationsordner (`/etc/vigil`).
pub fn config_dir() -> PathBuf {
    dev_override("VIGIL_CONFIG_DIR").unwrap_or_else(default_config_dir)
}

#[cfg(unix)]
fn default_config_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR)
}

/// `C:\ProgramData\Vigil\config`
#[cfg(windows)]
fn default_config_dir() -> PathBuf {
    default_data_dir().join("config")
}

/// `/etc/vigil/config.json`
pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// `/var/lib/vigil/state.json`
pub fn state_path() -> PathBuf {
    data_dir().join("state.json")
}

/// `/var/lib/vigil/reports`
pub fn reports_dir() -> PathBuf {
    data_dir().join("reports")
}

/// `/var/lib/vigil/reports/<id>.json` (nur mit gültiger Kennung, siehe [`valid_id`]).
pub fn report_path(id: &str) -> Option<PathBuf> {
    valid_id(id).then(|| reports_dir().join(format!("{id}.json")))
}

/// `/var/lib/vigil/quarantine.json`
pub fn quarantine_index_path() -> PathBuf {
    data_dir().join("quarantine.json")
}

/// `/var/lib/vigil/quarantine`
pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

/// `/var/lib/vigil/quarantine/<qid>` (nur mit gültiger Kennung).
pub fn quarantine_file_path(qid: &str) -> Option<PathBuf> {
    valid_id(qid).then(|| quarantine_dir().join(qid))
}

/// `/var/lib/vigil/system.json`
pub fn system_path() -> PathBuf {
    data_dir().join("system.json")
}

/// `/var/lib/vigil/cancel`
pub fn cancel_path() -> PathBuf {
    data_dir().join("cancel")
}

/// `/var/lib/vigil/pause`: Pausensignal für die laufende Prüfung.
pub fn pause_path() -> PathBuf {
    data_dir().join("pause")
}

/// `/var/lib/vigil/updates`: Ablage für Updates von Vigil selbst (root, 0700).
pub fn updates_dir() -> PathBuf {
    data_dir().join("updates")
}

/// `/var/lib/vigil/pro`: Ablage der Pro-Freigabe (root, 0700).
pub fn pro_data_dir() -> PathBuf {
    data_dir().join("pro")
}

/// `/var/lib/vigil/pro/token`: gespeicherte Pro-Freigabe (0600).
pub fn pro_token_path() -> PathBuf {
    pro_data_dir().join("token")
}

/// `/var/lib/vigil/extra-sigs`: Arbeitsordner der zusätzlichen Signaturen (root, 0700).
pub fn extra_sigs_dir() -> PathBuf {
    data_dir().join("extra-sigs")
}

/// `/var/lib/vigil/extra-signatures.json`: Stand der zusätzlichen Signaturen (0644, für die App).
pub fn extra_sigs_state_path() -> PathBuf {
    data_dir().join("extra-signatures.json")
}

/// Konfiguration von freshclam, die Vigil für `Checks` ändern darf. Im Testbetrieb nur
/// `VIGIL_FRESHCLAM_CONF` (ohne diese Variable `None`: /etc wird im Testbetrieb nie geändert).
pub fn freshclam_conf_path() -> Option<PathBuf> {
    if is_dev() {
        return dev_override("VIGIL_FRESHCLAM_CONF");
    }
    #[cfg(unix)]
    return Some(PathBuf::from("/etc/clamav/freshclam.conf"));
    #[cfg(windows)]
    return Some(crate::win::clamav::freshclam_conf());
}

/// `/var/lib/vigil/job.lock`
pub fn lock_path() -> PathBuf {
    data_dir().join("job.lock")
}

/// `/var/lib/vigil/data.lock`: kurze Sperre für Lesen-Ändern-Schreiben von
/// quarantine.json, Berichten und config.json.
pub fn data_lock_path() -> PathBuf {
    data_dir().join("data.lock")
}

/// Ordner für Timer-Drop-ins. Im Testbetrieb `<VIGIL_CONFIG_DIR>/systemd`.
#[cfg(unix)]
pub fn systemd_unit_dir() -> PathBuf {
    if is_dev() {
        config_dir().join("systemd")
    } else {
        PathBuf::from("/etc/systemd/system")
    }
}

/// Gültige Kennung für Berichte, Funde und Quarantäne: nur Buchstaben, Ziffern, `-`, `_`.
/// Verhindert Pfadangriffe wie `../`.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && !id.starts_with('-')
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Wandelt einen Pfad in Text für JSON und Meldungen.
pub fn display(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// `C:\ProgramData\Vigil\results`: Ergebnisse von Helfer-Aufrufen mit Administratorrechten
/// (UAC), die keine Ausgabe an die App zurückgeben können. Für Benutzer lesbar.
#[cfg(windows)]
pub fn results_dir() -> PathBuf {
    data_dir().join("results")
}

/// `C:\ProgramData\Vigil\schedule.json`: letzte Läufe des Zeitplans im Vigil-Dienst.
#[cfg(windows)]
pub fn schedule_state_path() -> PathBuf {
    data_dir().join("schedule.json")
}

/// Liegt `p` in `prefix` (oder ist gleich)? Unter Windows ohne Unterschied der Groß- und
/// Kleinschreibung, unter Linux wie `Path::starts_with`.
pub fn starts_with(p: &Path, prefix: &Path) -> bool {
    #[cfg(windows)]
    return crate::win::starts_with_ci(p, prefix);
    #[cfg(unix)]
    return p.starts_with(prefix);
}
