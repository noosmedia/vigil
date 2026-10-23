//! Updates für Vigil selbst: beim eigenen Update-Server nachsehen, signiertes Paket laden und über den Helfer installieren

use crate::settings::{self, tr};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use vigil_core::paths;

/// Repository des Quellcodes (Link in den Einstellungen)
pub const UPDATE_REPO: &str = vigil_core::selfupdate::UPDATE_REPO;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current: String,
    pub latest: Option<String>,
    pub available: bool,
    pub notes: Option<String>,
    pub notes_en: Option<String>,
    pub published_at: Option<String>,
    pub checked_at: Option<String>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deb_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_url: Option<String>,
    #[serde(default)]
    pub notified: Option<String>,
}

pub fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn cache_file() -> PathBuf {
    settings::cache_dir().join("update.json")
}

fn api_url() -> String {
    if paths::is_dev() {
        if let Ok(u) = std::env::var("VIGIL_UPDATE_API") {
            return u;
        }
    }
    vigil_core::selfupdate::UPDATE_API.to_string()
}

// Versionen als Zahlenfolge vergleichen (0.10.0 kommt nach 0.9.3)
fn parse_ver(v: &str) -> Vec<u64> {
    v.trim_start_matches('v').split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    parse_ver(candidate) > parse_ver(current)
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("Vigil/{}", current_version()))
        .build()
        .into()
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    body: Option<String>,
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

// Neuerungen: oben Deutsch, nach einer Zeile "---" Englisch
fn split_notes(body: &str) -> (String, String) {
    let mut de = Vec::new();
    let mut en = Vec::new();
    let mut in_en = false;
    for line in body.lines() {
        if !in_en && line.trim() == "---" {
            in_en = true;
            continue;
        }
        if in_en {
            en.push(line);
        } else {
            de.push(line);
        }
    }
    let de = de.join("\n").trim().to_string();
    let en = en.join("\n").trim().to_string();
    let en = if en.is_empty() { de.clone() } else { en };
    (de, en)
}

fn load_cache() -> Option<UpdateInfo> {
    std::fs::read_to_string(cache_file()).ok().and_then(|s| serde_json::from_str(&s).ok())
}

fn save_cache(info: &UpdateInfo) {
    if let Ok(data) = serde_json::to_vec_pretty(info) {
        let _ = settings::write_private(&cache_file(), &data);
    }
}

fn fetch() -> Result<UpdateInfo, String> {
    let mut resp = agent()
        .get(&api_url())
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| match e {
            ureq::Error::StatusCode(404) => tr("Noch keine Version veröffentlicht.", "No version published yet."),
            other => format!("{}: {other}", tr("Update-Server nicht erreichbar", "Update server not reachable")),
        })?;
    let rel: GhRelease = resp.body_mut().read_json().map_err(|e| format!("{}: {e}", tr("Antwort des Update-Servers unlesbar", "Unreadable answer from the update server")))?;
    let latest = rel.tag_name.trim_start_matches('v').to_string();
    // Name der Paketdatei je System: .deb unter Linux, Installer unter Windows
    let deb_name = vigil_core::selfupdate::deb_asset_name(&latest);
    let deb_url = rel.assets.iter().find(|a| a.name == deb_name).map(|a| a.browser_download_url.clone());
    let sig_url = rel.assets.iter().find(|a| a.name == format!("{deb_name}.sig")).map(|a| a.browser_download_url.clone());
    let (notes, notes_en) = split_notes(rel.body.as_deref().unwrap_or(""));
    let current = current_version();
    Ok(UpdateInfo {
        available: is_newer(&latest, &current) && deb_url.is_some() && sig_url.is_some(),
        current,
        latest: Some(latest),
        notes: Some(notes),
        notes_en: Some(notes_en),
        published_at: rel.published_at,
        checked_at: Some(vigil_core::now_rfc3339()),
        error: None,
        deb_url,
        sig_url,
        notified: None,
    })
}

/// Letzter bekannter Stand ohne Netzabfrage (für Tray und Anzeige)
pub fn cached() -> UpdateInfo {
    load_cache().filter(|c| c.current == current_version()).unwrap_or_else(|| UpdateInfo { current: current_version(), ..Default::default() })
}

/// Update-Stand liefern: aus dem Zwischenspeicher (6 h, nach Fehler 1 h) oder frisch vom Update-Server
pub fn check(force: bool) -> UpdateInfo {
    let cached = load_cache();
    if !force {
        if let Some(c) = &cached {
            let age = c
                .checked_at
                .as_deref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| chrono::Utc::now().signed_duration_since(t).num_minutes())
                .unwrap_or(i64::MAX);
            let max = if c.error.is_some() { 60 } else { 360 };
            if age < max && c.current == current_version() {
                return c.clone();
            }
        }
    }
    let notified = cached.as_ref().and_then(|c| c.notified.clone());
    let mut info = fetch().unwrap_or_else(|e| UpdateInfo {
        current: current_version(),
        checked_at: Some(vigil_core::now_rfc3339()),
        error: Some(e),
        ..Default::default()
    });
    info.notified = notified;
    save_cache(&info);
    info
}

/// Fortschritt eines Updates an die Oberfläche melden.
/// part: "vigil" oder "pro"; phase: "download", "verify", "install", "done"; step/steps: Datei x von y
pub fn progress(app: &AppHandle, part: &str, phase: &str, done: u64, total: u64, step: u32, steps: u32) {
    let _ = app.emit(
        "update-progress",
        serde_json::json!({ "part": part, "phase": phase, "done": done, "total": total, "step": step, "steps": steps }),
    );
}

/// Antwort Stück für Stück lesen und dabei den Fortschritt melden (höchstens alle 150 ms)
pub fn read_with_progress(resp: &mut ureq::http::Response<ureq::Body>, app: &AppHandle, part: &str, step: u32, steps: u32) -> Result<Vec<u8>, String> {
    use std::io::Read;
    const LIMIT: u64 = 200 * 1024 * 1024;
    let total = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let mut reader = resp.body_mut().with_config().limit(LIMIT).reader();
    let mut data = Vec::with_capacity(total.min(LIMIT) as usize);
    let mut buf = vec![0u8; 64 * 1024];
    let mut last = std::time::Instant::now();
    progress(app, part, "download", 0, total, step, steps);
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("{}: {e}", tr("Download fehlgeschlagen", "Download failed")))?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if last.elapsed() > Duration::from_millis(150) {
            last = std::time::Instant::now();
            progress(app, part, "download", data.len() as u64, total, step, steps);
        }
    }
    progress(app, part, "download", data.len() as u64, total.max(data.len() as u64), step, steps);
    Ok(data)
}

fn download(app: &AppHandle, url: &str, target: &PathBuf, step: u32, steps: u32) -> Result<Vec<u8>, String> {
    let mut resp = agent().get(url).call().map_err(|e| format!("{}: {e}", tr("Download fehlgeschlagen", "Download failed")))?;
    let data = read_with_progress(&mut resp, app, "vigil", step, steps)?;
    settings::write_private(target, &data)?;
    Ok(data)
}

/// Neueste Version laden, Signatur prüfen und über den Helfer installieren. Liefert bei Erfolg die neue Version.
pub fn install(app: &AppHandle) -> Result<String, String> {
    let info = check(true);
    if let Some(e) = info.error {
        return Err(e);
    }
    if !info.available {
        return Err(tr("Vigil ist bereits aktuell.", "Vigil is already up to date."));
    }
    let latest = info.latest.clone().unwrap_or_default();
    let dir = settings::cache_dir().join("update");
    let deb_name = vigil_core::selfupdate::deb_asset_name(&latest);
    let deb_path = dir.join(&deb_name);
    let sig_path = dir.join(format!("{deb_name}.sig"));
    let deb = download(app, info.deb_url.as_deref().unwrap_or_default(), &deb_path, 1, 2)?;
    let sig = download(app, info.sig_url.as_deref().unwrap_or_default(), &sig_path, 2, 2)?;
    progress(app, "vigil", "verify", 0, 0, 0, 0);
    let sig_text = String::from_utf8_lossy(&sig).trim().to_string();
    if !crate::crypto::verify_release(&deb, &sig_text) {
        let _ = std::fs::remove_file(&deb_path);
        return Err(tr(
            "Die Signatur des Updates ist ungültig. Das Paket wurde verworfen.",
            "The update signature is invalid. The package was discarded.",
        ));
    }
    let args = vec![
        "self-update".to_string(),
        "--deb".to_string(),
        deb_path.to_string_lossy().into_owned(),
        "--sig".to_string(),
        sig_path.to_string_lossy().into_owned(),
    ];
    progress(app, "vigil", "install", 0, 0, 0, 0);
    let res = crate::commands::run_manage_blocking(&args)?;
    if res.ok {
        progress(app, "vigil", "done", 0, 0, 0, 0);
        Ok(latest)
    } else {
        Err(if res.message.is_empty() { tr("Update abgebrochen.", "Update cancelled.") } else { res.message })
    }
}

/// Hintergrundprüfung alle 6 h, Benachrichtigung einmal je neuer Version
pub fn watch(app: AppHandle) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));
        loop {
            let mut info = check(false);
            if info.available && settings::load().update_notify {
                let latest = info.latest.clone().unwrap_or_default();
                if info.notified.as_deref() != Some(latest.as_str()) {
                    crate::notify(
                        &app,
                        &tr(&format!("Vigil {latest} ist verfügbar"), &format!("Vigil {latest} is available")),
                        &tr("In Vigil unter Einstellungen aktualisieren.", "Update in Vigil under Settings."),
                        false,
                    );
                    info.notified = Some(latest);
                    save_cache(&info);
                }
            }
            std::thread::sleep(Duration::from_secs(6 * 3600));
        }
    });
}
