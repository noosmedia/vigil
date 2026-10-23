//! Benutzereinstellungen und Wächter-Ereignisse im Home-Verzeichnis.
//! Unter Windows: Einstellungen unter `%APPDATA%\Vigil`, Ereignisse, Zwischenspeicher und Zustand
//! unter `%LOCALAPPDATA%\Vigil`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;

// Fehlende Felder (ältere settings.json) bekommen die Standardwerte
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub theme: String,
    pub watcher_enabled: bool,
    pub watcher_paths: Vec<String>,
    pub notifications: bool,
    pub language: String,
    pub look: String,
    pub palette: String,
    pub font: String,
    pub motion: String,
    pub update_notify: bool,
}

/// Sprache für Texte der App: Einstellung, bei "system" aus der Umgebung
pub fn lang() -> &'static str {
    let s = load();
    match s.language.as_str() {
        "de" => "de",
        "en" => "en",
        #[cfg(windows)]
        _ => crate::winapp::system_lang(),
        #[cfg(unix)]
        _ => {
            let env = std::env::var("LC_ALL")
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| std::env::var("LC_MESSAGES").ok().filter(|v| !v.is_empty()))
                .or_else(|| std::env::var("LANG").ok())
                .unwrap_or_default();
            if env.starts_with("de") {
                "de"
            } else {
                "en"
            }
        }
    }
}

/// Text in der eingestellten Sprache wählen
pub fn tr(de: &str, en: &str) -> String {
    if lang() == "de" {
        de.to_string()
    } else {
        en.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatcherEvent {
    pub at: String,
    pub path: String,
    pub verdict: String,
    pub detail: Option<String>,
    pub handled: bool,
}

#[cfg(unix)]
fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Windows: `%LOCALAPPDATA%\Vigil` (Ereignisse, Zwischenspeicher, Zustand)
#[cfg(windows)]
fn local_dir() -> PathBuf {
    vigil_core::win::known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData)
        .unwrap_or_else(std::env::temp_dir)
        .join("Vigil")
}

#[cfg(unix)]
fn settings_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("vigil/settings.json")
}

#[cfg(windows)]
fn settings_path() -> PathBuf {
    config_dir().join("settings.json")
}

#[cfg(unix)]
fn events_path() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share"))
        .join("vigil/watcher.json")
}

#[cfg(windows)]
fn events_path() -> PathBuf {
    local_dir().join("watcher.json")
}

/// Windows: Download-Ordner des Benutzers (bekannter Ordner, auch wenn er verschoben wurde)
#[cfg(windows)]
fn downloads_dir() -> String {
    vigil_core::win::known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Downloads)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// Download-Ordner laut xdg-user-dirs, sonst ~/Downloads (einmal ermittelt)
#[cfg(unix)]
fn downloads_dir() -> String {
    static DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if let Ok(out) = Command::new("xdg-user-dir").arg("DOWNLOAD").output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() && s != home().to_string_lossy() {
                return s;
            }
        }
        home().join("Downloads").to_string_lossy().into_owned()
    })
    .clone()
}

/// Ordner für Benutzerdaten von Vigil (~/.config/vigil)
#[cfg(unix)]
pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".config")).join("vigil")
}

/// Ordner für Benutzerdaten von Vigil (`%APPDATA%\Vigil`)
#[cfg(windows)]
pub fn config_dir() -> PathBuf {
    vigil_core::win::known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_RoamingAppData)
        .unwrap_or_else(std::env::temp_dir)
        .join("Vigil")
}

/// Ordner für den Zustand für Vigil Pro (`~/.local/state/vigil`, unter Windows
/// `%LOCALAPPDATA%\Vigil\state`). `None`, wenn kein Benutzerordner bekannt ist.
#[cfg(unix)]
pub fn state_dir() -> Option<PathBuf> {
    match std::env::var("XDG_STATE_HOME") {
        Ok(v) if v.starts_with('/') => Some(PathBuf::from(v).join("vigil")),
        _ => std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".local/state/vigil")),
    }
}

#[cfg(windows)]
pub fn state_dir() -> Option<PathBuf> {
    Some(local_dir().join("state"))
}

/// Ausgeblendeter Hinweis: Pfad und, falls bekannt, Prüfsumme der Datei
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dismissed {
    pub path: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

fn dismissed_path() -> PathBuf {
    config_dir().join("dismissed-hints.json")
}

pub fn load_dismissed() -> Vec<Dismissed> {
    std::fs::read_to_string(dismissed_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Hinweise ausblenden (Doppelte werden zusammengeführt)
pub fn add_dismissed(items: Vec<Dismissed>) -> Result<(), String> {
    let mut all = load_dismissed();
    for it in items {
        if !all.iter().any(|d| d.path == it.path && d.sha256 == it.sha256) {
            all.push(it);
        }
    }
    let data = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
    write_private(&dismissed_path(), &data)
}

/// Ist dieser Hinweis ausgeblendet? Bei bekannter Prüfsumme muss sie passen, damit eine geänderte Datei wieder erscheint.
pub fn is_dismissed(list: &[Dismissed], path: &str, sha256: Option<&str>) -> bool {
    list.iter().any(|d| d.path == path && (d.sha256.is_none() || sha256.is_none() || d.sha256.as_deref() == sha256))
}

/// Zwischenspeicher (~/.cache/vigil)
#[cfg(unix)]
pub fn cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".cache")).join("vigil")
}

/// Zwischenspeicher (`%LOCALAPPDATA%\Vigil\cache`)
#[cfg(windows)]
pub fn cache_dir() -> PathBuf {
    local_dir().join("cache")
}

/// Autostart-Datei des Benutzers, die den systemweiten Eintrag überschreibt
#[cfg(unix)]
pub fn autostart_override() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".config")).join("autostart/vigil.desktop")
}

/// Datei nur für den Benutzer lesbar schreiben (0600), atomar. Unter Windows sind Dateien im
/// Benutzerprofil ohnehin nur für den Benutzer (und Administratoren) lesbar.
pub fn write_private(path: &PathBuf, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Ordner {} nicht anlegbar: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o
        .open(&tmp)
        .map_err(|e| format!("{} nicht schreibbar: {e}", tmp.display()))?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().ok();
    std::fs::rename(&tmp, path).map_err(|e| format!("{} nicht schreibbar: {e}", path.display()))
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: "system".into(),
            watcher_enabled: true,
            watcher_paths: vec![downloads_dir()],
            language: "system".into(),
            look: "feld".into(),
            palette: "graphit".into(),
            font: "bricolage".into(),
            motion: "voll".into(),
            update_notify: true,
            notifications: true,
        }
    }
}

pub fn load() -> Settings {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// Atomar schreiben: erst Hilfsdatei, dann umbenennen
fn write_atomic(path: &PathBuf, data: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Ordner {} nicht anlegbar: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("{} nicht schreibbar: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{} nicht schreibbar: {e}", path.display()))
}

pub fn save(s: &Settings) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    write_atomic(&settings_path(), &data)
}

pub fn load_events() -> Vec<WatcherEvent> {
    std::fs::read_to_string(events_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_events(events: &[WatcherEvent]) {
    if let Ok(data) = serde_json::to_vec_pretty(events) {
        let _ = write_atomic(&events_path(), &data);
    }
}

// Neues Ereignis vorn einfügen, höchstens 100 behalten
pub fn push_event(ev: &WatcherEvent) {
    let mut all = load_events();
    all.insert(0, ev.clone());
    all.truncate(100);
    save_events(&all);
}

// Funde zu einem Pfad als erledigt markieren
pub fn mark_handled(path: &str) {
    let mut all = load_events();
    let mut changed = false;
    for e in all.iter_mut().filter(|e| e.path == path && !e.handled) {
        e.handled = true;
        changed = true;
    }
    if changed {
        save_events(&all);
    }
}
