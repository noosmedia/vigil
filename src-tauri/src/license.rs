//! Vigil Pro: Lizenz freischalten und erneuern, Pro-Paket laden und prüfen, Pro-Agent betreiben

use crate::crypto::{self, read_token};
use crate::settings::{self, tr};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use vigil_core::{paths, pro};

/// Adresse des Lizenzservers für Vigil Pro
pub const LICENSE_BASE: &str = "https://lizenz.noosmedia.de/vigil";

/// Dateien eines Pro-Pakets (Programmnamen je System, unter Windows mit .exe)
const BUNDLE_FILES: [&str; 4] = ["manifest.json", pro::PRO_BIN, pro::PRO_AGENT, pro::PRO_UI];
/// Dateien laut Manifest
const PRO_FILES: [&str; 3] = pro::PRO_FILES;

fn base() -> String {
    if paths::is_dev() {
        if let Ok(u) = std::env::var("VIGIL_LICENSE_BASE") {
            return u.trim_end_matches('/').to_string();
        }
    }
    LICENSE_BASE.to_string()
}

/// Ordner des installierten Pro-Pakets (im Testbetrieb wie der Helfer: VIGIL_LIB_DIR/pro)
pub fn pro_dir() -> PathBuf {
    paths::pro_dir()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct LicenseFile {
    pub key: String,
    pub installation_id: String,
    pub token: String,
    pub expires_at: Option<String>,
    pub features: Vec<String>,
    pub version: Option<String>,
    pub period_end: Option<String>,
    pub plan: Option<String>,
    pub cancel_at_period_end: bool,
    pub checked_at: Option<String>,
    pub last_error: Option<String>,
    /// Pro-Version, zu der schon eine Benachrichtigung gezeigt wurde (nur einmal je Version melden)
    pub pro_notified: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseInfo {
    pub active: bool,
    pub key: Option<String>,
    pub plan: Option<String>,
    pub period_end: Option<String>,
    pub cancel_at_period_end: bool,
    pub features: Vec<String>,
    pub pro_installed: bool,
    pub pro_version: Option<String>,
    /// Pro-Version, die der Lizenzserver zuletzt angeboten hat (für den Hinweis „Update verfügbar“)
    pub available_version: Option<String>,
    pub agent_running: bool,
    pub error: Option<String>,
}

fn license_path() -> PathBuf {
    settings::config_dir().join("license.json")
}

pub fn load() -> LicenseFile {
    std::fs::read_to_string(license_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save(l: &LicenseFile) -> Result<(), String> {
    settings::write_private(&license_path(), &serde_json::to_vec_pretty(l).map_err(|e| e.to_string())?)
}

// Kennung dieser Installation, einmal erzeugt und dann beibehalten
fn installation_id(l: &mut LicenseFile) -> String {
    if l.installation_id.len() < 16 {
        l.installation_id = crypto::random_id(32);
    }
    l.installation_id.clone()
}

fn mask(key: &str) -> String {
    let last = key.rsplit('-').next().unwrap_or("");
    format!("VGPRO-…-{last}")
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("Vigil/{}", env!("CARGO_PKG_VERSION")))
        .http_status_as_error(false)
        .build()
        .into()
}

fn post(path: &str, body: Value) -> Result<(u16, Value), String> {
    let mut resp = agent()
        .post(&format!("{}{path}", base()))
        .send_json(body)
        .map_err(|e| format!("{}: {e}", tr("Lizenzserver nicht erreichbar", "License server not reachable")))?;
    let status = resp.status().as_u16();
    let value: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
    Ok((status, value))
}

// Fehlermeldung des Servers in der eingestellten Sprache (errorEn, sonst error)
fn server_error(v: &Value, fallback_de: &str, fallback_en: &str) -> String {
    let field = if settings::lang() == "en" { v.get("errorEn").or_else(|| v.get("error")) } else { v.get("error") };
    field.and_then(|e| e.as_str()).map(String::from).unwrap_or_else(|| tr(fallback_de, fallback_en))
}

/// Ist ein gültig signiertes, vollständiges Pro-Paket installiert? Liefert die Version.
pub fn installed_version() -> Option<String> {
    let dir = pro_dir();
    let manifest = verified_file(&dir, "manifest.json")?;
    let m: Value = serde_json::from_slice(&manifest).ok()?;
    for f in PRO_FILES {
        verified_file(&dir, f)?;
        let want = m.get("files")?.get(f)?.as_str()?;
        let data = std::fs::read(dir.join(f)).ok()?;
        if crypto::sha256_hex(&data) != want {
            return None;
        }
    }
    m.get("version").and_then(|v| v.as_str()).map(String::from)
}

// Datei nur liefern, wenn die Signatur daneben passt
fn verified_file(dir: &Path, name: &str) -> Option<Vec<u8>> {
    let data = std::fs::read(dir.join(name)).ok()?;
    let sig = std::fs::read_to_string(dir.join(format!("{name}.sig"))).ok()?;
    crypto::verify_license(&data, sig.trim()).then_some(data)
}

/// Neuere Pro-Version auf dem Lizenzserver, nur bei gültiger Pro-Freigabe und installiertem Pro.
/// Wer nur das kostenlose Vigil nutzt, bekommt hier nie etwas.
pub fn pro_update_available() -> Option<String> {
    active_token()?;
    let installed = installed_version()?;
    let offered = load().version?;
    crate::update::is_newer(&offered, &installed).then_some(offered)
}

/// Pro gilt als aktiv, wenn eine gültige Freigabe vorliegt
pub fn active_token() -> Option<crypto::TokenPayload> {
    let l = load();
    if l.token.is_empty() {
        return None;
    }
    read_token(&l.token)
}

pub fn status(state: &crate::AppState) -> LicenseInfo {
    let l = load();
    let token = if l.token.is_empty() { None } else { read_token(&l.token) };
    LicenseInfo {
        active: token.is_some(),
        key: (!l.key.is_empty()).then(|| mask(&l.key)),
        plan: l.plan.clone(),
        period_end: l.period_end.clone(),
        cancel_at_period_end: l.cancel_at_period_end,
        features: token.as_ref().map(|t| t.features.clone()).unwrap_or_default(),
        pro_installed: installed_version().is_some(),
        pro_version: installed_version(),
        available_version: if token.is_some() { l.version.clone() } else { None },
        agent_running: state.pro_agent.lock().unwrap().is_some(),
        error: l.last_error.clone(),
    }
}

// Pro-Paket der freigegebenen Version laden, prüfen und über den Helfer installieren
fn download_and_install(app: &AppHandle, token: &str, version: &str) -> Result<(), String> {
    let dir = settings::cache_dir().join("pro").join(version);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let steps = BUNDLE_FILES.len() as u32;
    for (i, f) in BUNDLE_FILES.iter().enumerate() {
        let mut resp = agent()
            .get(&format!("{}/api/bundle/{f}", base()))
            .header("Authorization", &format!("Bearer {token}"))
            .call()
            .map_err(|e| format!("{}: {e}", tr("Pro-Paket nicht ladbar", "Could not download Pro package")))?;
        if resp.status().as_u16() != 200 {
            let v: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
            return Err(server_error(&v, "Pro-Paket nicht ladbar.", "Could not download Pro package."));
        }
        let sig = resp.headers().get("X-Vigil-Signature").and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
        let data = crate::update::read_with_progress(&mut resp, app, "pro", i as u32 + 1, steps)?;
        if !crypto::verify_license(&data, &sig) {
            return Err(tr("Die Signatur des Pro-Pakets ist ungültig.", "The Pro package signature is invalid."));
        }
        settings::write_private(&dir.join(f), &data)?;
        settings::write_private(&dir.join(format!("{f}.sig")), sig.as_bytes())?;
    }
    // Prüfsummen laut Manifest
    crate::update::progress(app, "pro", "verify", 0, 0, 0, 0);
    let manifest: Value = serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    for f in PRO_FILES {
        let want = manifest.get("files").and_then(|x| x.get(f)).and_then(|x| x.as_str()).unwrap_or("");
        let data = std::fs::read(dir.join(f)).map_err(|e| e.to_string())?;
        if crypto::sha256_hex(&data) != want {
            return Err(tr("Das Pro-Paket ist beschädigt (Prüfsumme).", "The Pro package is damaged (checksum)."));
        }
    }
    let args = vec!["pro-install".to_string(), "--dir".to_string(), dir.to_string_lossy().into_owned(), "--token".to_string(), token.to_string()];
    crate::update::progress(app, "pro", "install", 0, 0, 0, 0);
    let res = crate::commands::run_manage_blocking(&args)?;
    if res.ok {
        crate::update::progress(app, "pro", "done", 0, 0, 0, 0);
        Ok(())
    } else {
        Err(if res.message.is_empty() { tr("Installation abgebrochen.", "Installation cancelled.") } else { res.message })
    }
}

/// Schlüssel beim Lizenzserver freischalten; Pro-Paket bei Bedarf installieren, sonst Freigabe weitergeben
pub fn activate(app: &AppHandle, key: &str, interactive: bool) -> Result<(), String> {
    let mut l = load();
    // Leerer Schlüssel: den gespeicherten verwenden (z. B. Pro-Paket nachinstallieren)
    let stored = l.key.clone();
    let key = if key.trim().is_empty() { stored.as_str() } else { key };
    if key.trim().is_empty() {
        return Err(tr("Bitte einen Schlüssel eingeben.", "Please enter a key."));
    }
    let inst = installation_id(&mut l);
    // Das System bestimmt das Pro-Paket (linux oder windows); ältere Kerne senden es nicht und gelten als Linux
    let (status, v) = post(
        "/api/activate",
        json!({ "key": key.trim(), "installationId": inst, "appVersion": env!("CARGO_PKG_VERSION"), "os": std::env::consts::OS }),
    )?;
    if status != 200 || v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        let msg = server_error(&v, "Freischalten fehlgeschlagen.", "Activation failed.");
        // Ein ungültiger oder abgelaufener Schlüssel beendet Pro, Netzfehler nicht
        if matches!(v.get("code").and_then(|c| c.as_str()), Some("invalid") | Some("expired")) {
            l.token.clear();
            l.last_error = Some(msg.clone());
            let _ = save(&l);
            stop_agent(app);
        }
        return Err(msg);
    }
    let token = v.get("token").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let payload = read_token(&token).ok_or_else(|| tr("Die Freigabe des Servers ist ungültig.", "The server's authorization is invalid."))?;
    l.key = key.trim().to_uppercase();
    l.token = token.clone();
    l.expires_at = v.get("expiresAt").and_then(|x| x.as_str()).map(String::from);
    l.features = payload.features.clone();
    l.version = Some(payload.version.clone());
    l.period_end = v.get("periodEnd").and_then(|x| x.as_str()).map(String::from);
    l.plan = v.get("plan").and_then(|x| x.as_str()).map(String::from);
    l.cancel_at_period_end = v.get("cancelAtPeriodEnd").and_then(|x| x.as_bool()).unwrap_or(false);
    l.checked_at = Some(vigil_core::now_rfc3339());
    l.last_error = None;
    save(&l)?;

    if installed_version().as_deref() != Some(payload.version.as_str()) {
        // Neues oder anderes Paket: braucht das Administrator-Passwort, nur auf Wunsch des Nutzers
        if interactive {
            download_and_install(app, &token, &payload.version)?;
        } else {
            return Ok(());
        }
    } else {
        // Nur die Freigabe erneuern (ohne Passwort)
        let _ = crate::commands::run_scan_blocking(&["pro-token".to_string(), "--token".to_string(), token]);
    }
    start_agent(app);
    Ok(())
}

/// Lizenz auf diesem Rechner abmelden und Pro entfernen
pub fn deactivate(app: &AppHandle) -> Result<(), String> {
    let l = load();
    if !l.key.is_empty() {
        let _ = post("/api/deactivate", json!({ "key": l.key, "installationId": l.installation_id }));
    }
    stop_agent(app);
    if installed_version().is_some() || pro_dir().exists() {
        let res = crate::commands::run_manage_blocking(&["pro-remove".to_string()])?;
        if !res.ok {
            return Err(if res.message.is_empty() { tr("Entfernen abgebrochen.", "Removal cancelled.") } else { res.message });
        }
    }
    let keep = LicenseFile { installation_id: l.installation_id, ..Default::default() };
    save(&keep)
}

/// Kasse öffnen (Link im Browser)
pub fn checkout(plan: &str) -> Result<String, String> {
    let (status, v) = post("/api/checkout", json!({ "plan": plan, "lang": settings::lang() }))?;
    match v.get("url").and_then(|u| u.as_str()) {
        Some(url) if status == 200 => Ok(url.to_string()),
        _ => Err(server_error(&v, "Die Kasse ist gerade nicht erreichbar.", "Checkout is currently unavailable.")),
    }
}

/// Kundenportal (kündigen, Zahlungsart ändern)
pub fn portal() -> Result<String, String> {
    let l = load();
    if l.key.is_empty() {
        return Err(tr("Kein Schlüssel hinterlegt.", "No key stored."));
    }
    let (status, v) = post("/api/portal", json!({ "key": l.key }))?;
    match v.get("url").and_then(|u| u.as_str()) {
        Some(url) if status == 200 => Ok(url.to_string()),
        _ => Err(server_error(&v, "Das Kundenportal ist gerade nicht erreichbar.", "The customer portal is currently unavailable.")),
    }
}

pub fn plans() -> Result<Value, String> {
    let mut resp = agent()
        .get(&format!("{}/api/plans", base()))
        .call()
        .map_err(|e| format!("{}: {e}", tr("Lizenzserver nicht erreichbar", "License server not reachable")))?;
    resp.body_mut().read_json().map_err(|e| e.to_string())
}

/// Inhalt der Pro-Oberfläche, nur mit gültiger Signatur und Prüfsumme
pub fn ui_source() -> Result<String, String> {
    if installed_version().is_none() {
        return Err(tr("Vigil Pro ist nicht installiert.", "Vigil Pro is not installed."));
    }
    let data = verified_file(&pro_dir(), "pro-ui.js").ok_or_else(|| tr("Pro-Oberfläche nicht vertrauenswürdig.", "Pro interface not trusted."))?;
    String::from_utf8(data).map_err(|e| e.to_string())
}

// --- Pro-Agent (läuft als Benutzer) ---

pub struct AgentHandle {
    child: Child,
    stdin: ChildStdin,
}

pub fn agent_send(app: &AppHandle, line: &str) -> Result<(), String> {
    let state = app.state::<crate::AppState>();
    let mut guard = state.pro_agent.lock().unwrap();
    let h = guard.as_mut().ok_or_else(|| tr("Der Pro-Dienst läuft nicht.", "The Pro service is not running."))?;
    writeln!(h.stdin, "{line}").map_err(|e| e.to_string())
}

pub fn stop_agent(app: &AppHandle) {
    let state = app.state::<crate::AppState>();
    let mut guard = state.pro_agent.lock().unwrap();
    if let Some(mut h) = guard.take() {
        let _ = h.child.kill();
        let _ = h.child.wait();
    }
}

/// Agent starten, wenn Pro aktiv und das Programm signiert ist
pub fn start_agent(app: &AppHandle) {
    if active_token().is_none() || installed_version().is_none() {
        return;
    }
    stop_agent(app);
    let bin = pro_dir().join(pro::PRO_AGENT);
    let mut command = Command::new(&bin);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(vigil_core::win::CREATE_NO_WINDOW);
    }
    let child = command
        .args(["--lang", settings::lang(), "--clamd"])
        .arg(vigil_core::clamd::clamd_socket())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return };
    let Some(stdin) = child.stdin.take() else { return };
    let stdout = child.stdout.take();
    {
        let state = app.state::<crate::AppState>();
        *state.pro_agent.lock().unwrap() = Some(AgentHandle { child, stdin });
    }
    // Ereignisse des Agents weiterreichen und bei Funden benachrichtigen
    if let Some(out) = stdout {
        let app = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let Ok(ev) = serde_json::from_str::<Value>(&line) else { continue };
                let _ = app.emit("pro-event", &ev);
                match ev.get("type").and_then(|t| t.as_str()) {
                    Some("usb-result") => {
                        let n = ev
                            .get("threats")
                            .and_then(|t| t.as_array())
                            .map(|a| a.iter().filter(|t| !t.get("signature").and_then(|s| s.as_str()).map(crate::commands::is_hint_signature).unwrap_or(false)).count())
                            .unwrap_or(0);
                        if n > 0 {
                            crate::notify(&app, &tr("USB-Wächter: Bedrohung gefunden", "USB guard: threat found"), &tr(&format!("{n} verdächtige Dateien auf dem Datenträger."), &format!("{n} suspicious files on the drive.")), true);
                        }
                    }
                    // Allgemeine Meldung des Agents, etwa vom Mailschutz
                    Some("notify") => {
                        let field = |de: &str, en: &str| {
                            let pick = if settings::lang() == "en" { en } else { de };
                            ev.get(pick).or_else(|| ev.get(de)).and_then(|v| v.as_str()).unwrap_or_default().to_string()
                        };
                        let title = field("title", "titleEn");
                        if !title.is_empty() {
                            let critical = ev.get("critical").and_then(|c| c.as_bool()).unwrap_or(false);
                            crate::notify(&app, &title, &field("body", "bodyEn"), critical);
                        }
                    }
                    Some("realtime-hit") if !ev.get("signature").and_then(|s| s.as_str()).map(crate::commands::is_hint_signature).unwrap_or(false) => {
                        let path = ev.get("path").and_then(|p| p.as_str()).unwrap_or_default();
                        crate::notify(&app, &tr("Echtzeitschutz: Bedrohung gefunden", "Real-time protection: threat found"), path, true);
                    }
                    _ => {}
                }
            }
        });
    }
}

/// Einmaliger Aufruf des Agents (z. B. Rechner-Übersicht)
pub fn agent_run(args: &[String]) -> Result<(bool, String, String, i32), String> {
    if active_token().is_none() || installed_version().is_none() {
        return Err(tr("Vigil Pro ist nicht aktiv.", "Vigil Pro is not active."));
    }
    let mut command = Command::new(pro_dir().join(pro::PRO_AGENT));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(vigil_core::win::CREATE_NO_WINDOW);
    }
    let out = command
        .args(["--lang", settings::lang()])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    ))
}

/// Freigabe alle 6 h erneuern; Agent beim Start anwerfen
pub fn watch(app: AppHandle) {
    std::thread::spawn(move || {
        start_agent(&app);
        loop {
            let l = load();
            if !l.key.is_empty() {
                if let Err(e) = activate(&app, &l.key, false) {
                    let mut l2 = load();
                    l2.last_error = Some(e);
                    let _ = save(&l2);
                }
                // Neues Pro einmal je Version melden
                if let Some(v) = pro_update_available() {
                    let mut l3 = load();
                    if l3.pro_notified.as_deref() != Some(v.as_str()) && settings::load().update_notify {
                        crate::notify(
                            &app,
                            &tr(&format!("Vigil Pro {v} ist verfügbar"), &format!("Vigil Pro {v} is available")),
                            &tr("In Vigil oben rechts auf „Update verfügbar“ klicken.", "Click “Update available” at the top right in Vigil."),
                            false,
                        );
                        l3.pro_notified = Some(v);
                        let _ = save(&l3);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(6 * 3600));
        }
    });
}

pub type AgentSlot = Mutex<Option<AgentHandle>>;
