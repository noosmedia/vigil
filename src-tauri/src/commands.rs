//! Befehle, die die Oberfläche aufruft: Zustand lesen, Helfer starten, Einstellungen

use crate::settings::{self, Settings, WatcherEvent};
use crate::AppState;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use vigil_core::paths;

#[cfg(unix)]
const POLICY: &str = "/usr/share/polkit-1/actions/de.vigil.policy";

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Signatures {
    version: u64,
    date: Option<String>,
    engine: String,
    /// Wann zuletzt nach neuen Virendaten gesucht wurde (Änderungszeit des Datenbankordners)
    checked_at: Option<String>,
}

#[derive(Serialize, Clone, Copy)]
pub struct Services {
    clamd: bool,
    freshclam: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Live {
    installed: bool,
    dev: bool,
    state: Option<Value>,
    signatures: Option<Signatures>,
    services: Services,
    watcher_active: bool,
    watcher_last: Option<WatcherEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    #[serde(flatten)]
    live: Live,
    setup_command: Option<String>,
    system: Option<Value>,
    quarantine: Vec<Value>,
    config: Value,
    settings: Settings,
    watcher_events: Vec<WatcherEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenThreat {
    report_id: String,
    report_kind: String,
    found_at: String,
    threat: Value,
    hint: bool,
}

/// Heuristische Erkennung von ClamAV: nur ein Hinweis, keine Bedrohung
pub fn is_hint_signature(sig: &str) -> bool {
    sig.starts_with("Heuristics.")
}

// Fund aus einem Bericht: Feld severity (ab 0.2.0), sonst nach Signaturname
fn is_hint_value(t: &Value) -> bool {
    t.get("severity").and_then(|s| s.as_str()) == Some("hint") || t.get("signature").and_then(|s| s.as_str()).map(is_hint_signature).unwrap_or(false)
}

#[derive(Serialize)]
pub struct HelperResult {
    pub ok: bool,
    pub message: String,
}

// Ordner mit den Helferprogrammen: im Testbetrieb frei wählbar, sonst /usr/lib/vigil
#[cfg(unix)]
fn helper_dir() -> PathBuf {
    if paths::is_dev() {
        if let Some(d) = std::env::var_os("VIGIL_HELPER_DIR") {
            return PathBuf::from(d);
        }
    }
    PathBuf::from(paths::LIB_DIR)
}

#[cfg(unix)]
fn helper_bin(manage: bool) -> PathBuf {
    helper_dir().join(if manage { "vigil-helper" } else { "vigil-scan" })
}

/// Sind Helfer und Rechte-Regeln installiert?
pub fn is_installed() -> bool {
    installed()
}

#[cfg(unix)]
fn installed() -> bool {
    helper_bin(true).exists() && helper_bin(false).exists() && (paths::is_dev() || Path::new(POLICY).exists())
}

/// Windows: Helfer im Installationsordner und Vigil-Dienst eingerichtet.
#[cfg(windows)]
fn installed() -> bool {
    crate::winapp::helper_exe().exists() && (paths::is_dev() || crate::winapp::service_installed())
}

/// Ausgabe eines Helfer-Aufrufs. `code` ist `None`, wenn der Helfer durch ein Signal endete
/// (Linux) bzw. die Administratorabfrage abgebrochen wurde (Windows, wie Code 126 bei pkexec).
pub struct HelperOutput {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl HelperOutput {
    fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Helfer aufrufen und auf das Ende warten: unter Linux über pkexec (vigil-helper mit,
/// vigil-scan ohne Passwort), unter Windows über die UAC-Abfrage bzw. den Vigil-Dienst.
fn exec_helper(manage: bool, args: &[String]) -> Result<HelperOutput, String> {
    #[cfg(unix)]
    {
        let out = helper_command(manage, args).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        Ok(HelperOutput {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
    #[cfg(windows)]
    {
        let lang = crate::settings::lang();
        let out = if manage { crate::winapp::call_elevated(lang, args)? } else { crate::winapp::call_service(lang, args)? };
        // Abgebrochene Abfrage wie unter Linux (pkexec Code 126)
        Ok(HelperOutput { code: Some(out.code.unwrap_or(126)), stdout: out.stdout, stderr: out.stderr })
    }
}

// Aufruf des Helfers: im Testbetrieb direkt, sonst über pkexec mit Rechteprüfung durch polkit
#[cfg(unix)]
fn helper_command(manage: bool, args: &[String]) -> Command {
    let bin = helper_bin(manage);
    let mut cmd = if paths::is_dev() {
        Command::new(bin)
    } else {
        let mut c = Command::new("pkexec");
        c.arg(bin);
        c
    };
    // Sprache der Meldungen passend zur Oberfläche
    cmd.args(["--lang", crate::settings::lang()]);
    cmd.args(args);
    cmd
}

// Antwort des Helfers auswerten: Erfolgszeile oder vollständige Fehlermeldung
fn helper_result(out: HelperOutput) -> HelperResult {
    let stdout = out.stdout.clone();
    let stderr = out.stderr.trim().to_string();
    let en = crate::settings::lang() == "en";
    if out.success() {
        let v = stdout.lines().rev().find_map(|l| serde_json::from_str::<Value>(l).ok());
        let message = v
            .as_ref()
            .and_then(|v| if en { v.get("messageEn").or_else(|| v.get("message")) } else { v.get("message") })
            .and_then(|m| m.as_str())
            .map(String::from)
            .unwrap_or_default();
        return HelperResult { ok: true, message };
    }
    let message = match out.code {
        Some(126) => String::new(),
        Some(127) => crate::settings::tr("Keine Berechtigung. Das Passwort wurde nicht akzeptiert.", "Not authorized. The password was not accepted."),
        _ if !stderr.is_empty() => stderr,
        c => crate::settings::tr(
            &format!("Der Helfer endete mit Code {}.", c.map(|c| c.to_string()).unwrap_or_else(|| "unbekannt".into())),
            &format!("The helper exited with code {}.", c.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into())),
        ),
    };
    HelperResult { ok: false, message }
}

/// Befehl über vigil-helper (mit Passwort) ausführen und auf das Ende warten
pub fn run_manage_blocking(args: &[String]) -> Result<HelperResult, String> {
    if !installed() {
        return Err(crate::settings::tr("Vigil ist noch nicht installiert.", "Vigil is not installed yet."));
    }
    Ok(helper_result(exec_helper(true, args)?))
}

/// Befehl über vigil-scan (ohne Passwort) ausführen und auf das Ende warten
pub fn run_scan_blocking(args: &[String]) -> Result<HelperResult, String> {
    if !installed() {
        return Err(crate::settings::tr("Vigil ist noch nicht installiert.", "Vigil is not installed yet."));
    }
    Ok(helper_result(exec_helper(false, args)?))
}

/// Rohausgabe eines Pro-Aufrufs für die Pro-Oberfläche
#[derive(Serialize)]
pub struct RawResult {
    ok: bool,
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_raw(manage: bool, args: Vec<String>) -> Result<RawResult, String> {
    if !installed() {
        return Err(crate::settings::tr("Vigil ist noch nicht installiert.", "Vigil is not installed yet."));
    }
    let out = exec_helper(manage, &args)?;
    Ok(RawResult { ok: out.success(), code: out.code.unwrap_or(-1), stdout: out.stdout, stderr: out.stderr })
}

fn read_json(p: &Path) -> Option<Value> {
    std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok())
}

// Windows: Signaturstand direkt aus den Virendaten (kein Konsolenaufruf von clamscan)
#[cfg(windows)]
fn read_signatures() -> Option<Signatures> {
    let s = vigil_core::sysinfo::signature_info()?;
    Some(Signatures {
        version: s.version,
        date: Some(s.date),
        engine: s.engine.unwrap_or_default(),
        checked_at: vigil_core::win::clamav::last_check(),
    })
}

// Signaturstand aus "clamscan --version", z. B. "ClamAV 1.5.4/27800/Thu Oct 23 08:20:00 2026"
#[cfg(unix)]
fn read_signatures() -> Option<Signatures> {
    let bin = if paths::is_dev() { std::env::var("VIGIL_CLAMSCAN").unwrap_or_else(|_| "clamscan".into()) } else { "clamscan".into() };
    let out = Command::new(bin).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut parts = text.splitn(3, '/');
    let engine = parts.next()?.trim().trim_start_matches("ClamAV").trim().to_string();
    let version = parts.next().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    let date = parts.next().and_then(|d| {
        let d = d.split_whitespace().collect::<Vec<_>>().join(" ");
        chrono::NaiveDateTime::parse_from_str(&d, "%a %b %d %H:%M:%S %Y")
            .ok()
            .and_then(|n| n.and_local_timezone(chrono::Local).single())
            .map(|t| t.to_rfc3339())
    });
    Some(Signatures { version, date, engine, checked_at: signatures_checked_at() })
}

// freshclam legt bei jeder Suche nach Updates Dateien im Datenbankordner an oder ändert sie;
// die Änderungszeit des Ordners zeigt deshalb, wann zuletzt nachgesehen wurde
#[cfg(unix)]
fn signatures_checked_at() -> Option<String> {
    let dir = std::fs::read_to_string("/etc/clamav/freshclam.conf")
        .ok()
        .and_then(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| l.strip_prefix("DatabaseDirectory"))
                .map(|v| v.trim().to_string())
                .find(|v| v.starts_with('/'))
        })
        .unwrap_or_else(|| "/var/lib/clamav".into());
    let modified = std::fs::metadata(dir).and_then(|m| m.modified()).ok()?;
    Some(chrono::DateTime::<chrono::Local>::from(modified).to_rfc3339())
}

/// Windows: clamd antwortet; „freshclam“ steht für den Vigil-Dienst, der die Virendaten lädt.
#[cfg(windows)]
fn read_services() -> Services {
    let ping = vigil_core::clamd::ping(&vigil_core::clamd::clamd_socket());
    if paths::is_dev() {
        return Services { clamd: ping, freshclam: true };
    }
    Services { clamd: ping, freshclam: crate::winapp::service_running() }
}

#[cfg(unix)]
fn read_services() -> Services {
    let socket = vigil_core::clamd::clamd_socket();
    let ping = vigil_core::clamd::ping(&socket);
    if paths::is_dev() {
        return Services { clamd: ping, freshclam: true };
    }
    let active = |unit: &str| {
        Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    Services { clamd: ping || active("clamav-daemon"), freshclam: active("clamav-freshclam") }
}

fn build_live(state: &AppState) -> Live {
    // Signaturen höchstens jede Minute, Dienste alle paar Sekunden neu lesen
    let signatures = {
        let mut c = state.sig_cache.lock().unwrap();
        if c.0.map(|t| t.elapsed() > Duration::from_secs(60)).unwrap_or(true) {
            *c = (Some(Instant::now()), read_signatures());
        }
        c.1.clone()
    };
    let services = {
        let mut c = state.svc_cache.lock().unwrap();
        if c.0.map(|t| t.elapsed() > Duration::from_secs(5)).unwrap_or(true) {
            *c = (Some(Instant::now()), Some(read_services()));
        }
        c.1.unwrap_or(Services { clamd: false, freshclam: false })
    };
    Live {
        installed: installed(),
        dev: paths::is_dev(),
        state: read_json(&paths::state_path()),
        signatures,
        services,
        watcher_active: state.watcher.lock().unwrap().is_some() && services.clamd,
        watcher_last: state.watcher_last.lock().unwrap().clone(),
    }
}

// Windows: Einrichtung erledigt der Installer, es gibt keinen Befehl
#[cfg(windows)]
fn setup_command() -> Option<String> {
    None
}

// Installationsbefehl für das zuletzt gebaute Paket
#[cfg(unix)]
fn setup_command() -> Option<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/release/bundle/deb");
    let newest = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "deb").unwrap_or(false))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())?;
    let path = newest.path().canonicalize().ok()?;
    Some(format!("sudo apt install --no-install-recommends {}", path.display()))
}

/// Version der Virendaten, ihr Alter in Stunden und wie viele Minuten die letzte Suche her ist
pub fn cached_signatures(state: &AppState) -> Option<(u64, Option<f64>, Option<f64>)> {
    let mut c = state.sig_cache.lock().unwrap();
    if c.0.map(|t| t.elapsed() > Duration::from_secs(60)).unwrap_or(true) {
        *c = (Some(Instant::now()), read_signatures());
    }
    c.1.as_ref().map(|s| {
        let age = s
            .date
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
            .map(|d| (chrono::Utc::now().timestamp() - d.timestamp()) as f64 / 3600.0);
        let checked = s
            .checked_at
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
            .map(|d| (chrono::Utc::now().timestamp() - d.timestamp()).max(0) as f64 / 60.0);
        (s.version, age, checked)
    })
}

/// Dienste clamd und freshclam aus dem Zwischenspeicher
pub fn cached_services(state: &AppState) -> (bool, bool) {
    let mut c = state.svc_cache.lock().unwrap();
    if c.0.map(|t| t.elapsed() > Duration::from_secs(5)).unwrap_or(true) {
        *c = (Some(Instant::now()), Some(read_services()));
    }
    c.1.map(|s| (s.clamd, s.freshclam)).unwrap_or((false, false))
}

/// Zahl der offenen Funde (Berichte und Download-Wächter)
/// Zahl der offenen Bedrohungen (Berichte und Download-Wächter), Hinweise zählen nicht
pub fn open_threat_count() -> usize {
    let watcher = settings::load_events().iter().filter(|e| e.verdict == "infected" && !e.handled && std::fs::symlink_metadata(&e.path).is_ok()).count();
    open_threats_list().iter().filter(|o| !o.hint).count() + watcher
}

#[tauri::command]
pub async fn live(state: State<'_, AppState>) -> Result<Live, String> {
    Ok(build_live(&state))
}

#[tauri::command]
pub async fn snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let live = build_live(&state);
    let quarantine = read_json(&paths::quarantine_index_path())
        .and_then(|v| v.get("items").and_then(|i| i.as_array()).cloned())
        .unwrap_or_default();
    // Konfiguration mit Standardwerten für fehlende Felder
    let config = serde_json::to_value(vigil_core::config::load_config().unwrap_or_default()).unwrap_or(Value::Null);
    // Wächterfunde, deren Datei nicht mehr existiert, gelten als erledigt
    let mut events = settings::load_events();
    let mut changed = false;
    for e in events.iter_mut().filter(|e| (e.verdict == "infected" || e.verdict == "hint") && !e.handled) {
        if std::fs::symlink_metadata(&e.path).is_err() {
            e.handled = true;
            changed = true;
        }
    }
    if changed {
        settings::save_events(&events);
    }
    Ok(Snapshot {
        setup_command: if live.installed { None } else { setup_command() },
        live,
        system: read_json(&paths::system_path()),
        quarantine,
        config,
        settings: settings::load(),
        watcher_events: events,
    })
}

/// Zeitpunkt der letzten abgeschlossenen Prüfung (Schnell, Vollständig oder Ordner)
pub fn last_scan_at() -> Option<String> {
    load_reports().into_iter().find_map(|r| {
        let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or_default();
        if !["quick", "full", "custom"].contains(&kind) {
            return None;
        }
        r.get("finishedAt").or_else(|| r.get("startedAt")).and_then(|v| v.as_str()).map(String::from)
    })
}

fn load_reports() -> Vec<Value> {
    let mut out: Vec<Value> = std::fs::read_dir(paths::reports_dir())
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
                .filter_map(|e| read_json(&e.path()))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| {
        let ka = a.get("startedAt").and_then(|v| v.as_str()).unwrap_or("");
        let kb = b.get("startedAt").and_then(|v| v.as_str()).unwrap_or("");
        kb.cmp(ka)
    });
    out.truncate(200);
    out
}

#[tauri::command]
pub async fn reports() -> Result<Vec<Value>, String> {
    Ok(load_reports())
}

// Offene Funde: neuester Stand je Pfad, ohne Maßnahme, Datei noch vorhanden
#[tauri::command]
pub async fn open_threats() -> Result<Vec<OpenThreat>, String> {
    Ok(open_threats_list())
}

fn open_threats_list() -> Vec<OpenThreat> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let dismissed = settings::load_dismissed();
    for r in load_reports() {
        let rid = r.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let at = r.get("finishedAt").and_then(|v| v.as_str()).or_else(|| r.get("startedAt").and_then(|v| v.as_str())).unwrap_or_default().to_string();
        for t in r.get("threats").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let path = t.get("path").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            if !seen.insert(path.clone()) {
                continue;
            }
            if t.get("action").and_then(|v| v.as_str()) != Some("none") {
                continue;
            }
            match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                _ => {}
            }
            let hint = is_hint_value(&t);
            // Ausgeblendete Hinweise erscheinen nicht mehr
            if hint && settings::is_dismissed(&dismissed, &path, t.get("sha256").and_then(|s| s.as_str()).filter(|s| !s.is_empty())) {
                continue;
            }
            out.push(OpenThreat { report_id: rid.clone(), report_kind: kind.clone(), found_at: at.clone(), threat: t, hint });
        }
    }
    out
}

pub fn spawn_job(app: &AppHandle, kind: &str, paths_in: &[String]) -> Result<(), String> {
    use crate::settings::tr;
    let args: Vec<String> = match kind {
        "quick" | "full" => vec!["scan".into(), "--kind".into(), kind.into(), "--trigger".into(), "manual".into()],
        "custom" => {
            if paths_in.is_empty() {
                return Err(tr("Kein Ordner gewählt.", "No folder selected."));
            }
            let mut a = vec!["scan".into(), "--kind".into(), "custom".into(), "--trigger".into(), "manual".into()];
            for p in paths_in {
                a.push("--path".into());
                a.push(p.clone());
            }
            a
        }
        "systemcheck" => vec!["systemcheck".into(), "--trigger".into(), "manual".into()],
        "update" => vec!["update-signatures".into()],
        "cancel" => vec!["cancel".into()],
        "pause" => vec!["pause".into()],
        "resume" => vec!["resume".into()],
        other => return Err(tr(&format!("Unbekannter Auftrag: {other}"), &format!("Unknown task: {other}"))),
    };
    if !installed() {
        return Err(tr(
            "Vigil ist noch nicht installiert. Den Befehl auf der Übersicht im Terminal ausführen.",
            "Vigil is not installed yet. Run the command shown on the overview in a terminal.",
        ));
    }
    // Windows: Auftrag läuft im Vigil-Dienst weiter, auch wenn die App geschlossen wird
    #[cfg(windows)]
    {
        let app = app.clone();
        std::thread::spawn(move || {
            let msg = match exec_helper(false, &args) {
                Ok(out) if out.success() => return,
                Ok(out) if !out.stderr.trim().is_empty() => out.stderr.trim().to_string(),
                Ok(out) => tr(
                    &format!("Der Helfer endete mit Code {}.", out.code.map(|c| c.to_string()).unwrap_or_else(|| "unbekannt".into())),
                    &format!("The helper exited with code {}.", out.code.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into())),
                ),
                Err(e) => e,
            };
            let _ = app.emit("helper-failed", msg);
        });
        Ok(())
    }
    // Eigene Prozessgruppe, damit der Auftrag auch nach dem Schließen der App weiterläuft
    #[cfg(unix)]
    {
    let mut child = helper_command(false, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("{}: {e}", tr("Helfer nicht startbar", "Helper could not be started")))?;
    let app = app.clone();
    std::thread::spawn(move || {
        let mut err = String::new();
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        if let Ok(status) = child.wait() {
            if !status.success() {
                let msg = match status.code() {
                    Some(126) => tr("Die Rechteabfrage wurde abgebrochen.", "The authorization prompt was cancelled."),
                    Some(127) => tr("Keine Berechtigung für diesen Auftrag.", "Not authorized for this task."),
                    _ if !err.trim().is_empty() => err.trim().to_string(),
                    c => tr(
                        &format!("Der Helfer endete mit Code {}.", c.map(|c| c.to_string()).unwrap_or_else(|| "unbekannt".into())),
                        &format!("The helper exited with code {}.", c.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into())),
                    ),
                };
                let _ = app.emit("helper-failed", msg);
            }
        }
    });
    Ok(())
    }
}

#[tauri::command]
pub async fn start_job(app: AppHandle, kind: String, paths: Vec<String>) -> Result<(), String> {
    spawn_job(&app, &kind, &paths)
}

/// Laufende Prüfung anhalten (ohne Passwort)
#[tauri::command]
pub async fn pause_job() -> Result<HelperResult, String> {
    tauri::async_runtime::spawn_blocking(|| run_scan_blocking(&["pause".to_string()])).await.map_err(|e| e.to_string())?
}

/// Angehaltene Prüfung fortsetzen (ohne Passwort)
#[tauri::command]
pub async fn resume_job() -> Result<HelperResult, String> {
    tauri::async_runtime::spawn_blocking(|| run_scan_blocking(&["resume".to_string()])).await.map_err(|e| e.to_string())?
}

// Befehle, die mit Passwort über vigil-helper laufen
const MANAGE: [&str; 10] = [
    "quarantine",
    "quarantine-path",
    "restore",
    "delete",
    "delete-threat",
    "allow",
    "allow-quarantined",
    "unallow",
    "set-config",
    "fix",
];

#[tauri::command]
pub async fn run_helper(args: Vec<String>) -> Result<HelperResult, String> {
    let first = args.first().cloned().unwrap_or_default();
    if !MANAGE.contains(&first.as_str()) {
        return Err(format!("{}: {first}", crate::settings::tr("Befehl nicht erlaubt", "Command not allowed")));
    }
    let args2 = args.clone();
    let res = tauri::async_runtime::spawn_blocking(move || run_manage_blocking(&args2)).await.map_err(|e| e.to_string())??;
    // Wächterfund erledigt, sobald die Datei in Quarantäne ist
    if res.ok && first == "quarantine-path" {
        if let Some(p) = args.iter().skip_while(|a| *a != "--path").nth(1) {
            settings::mark_handled(p);
        }
    }
    Ok(res)
}

#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    let before = settings::load();
    settings::save(&settings)?;
    crate::apply_watcher(&app, &settings);
    // Sprache gewechselt: Tray-Texte und Pro-Agent folgen
    if before.language != settings.language {
        crate::tray::refresh_now(&app);
        crate::license::start_agent(&app);
    }
    Ok(())
}

#[tauri::command]
pub async fn pick_folders(app: AppHandle) -> Result<Option<Vec<String>>, String> {
    let picked = app.dialog().file().set_title(crate::settings::tr("Ordner wählen", "Choose folders")).blocking_pick_folders();
    Ok(picked.map(|v| v.into_iter().filter_map(|p| p.into_path().ok()).map(|p| p.to_string_lossy().into_owned()).collect()))
}

/// Windows: Windows Update in den Einstellungen öffnen
#[cfg(windows)]
#[tauri::command]
pub async fn open_update_manager() -> Result<(), String> {
    crate::winapp::open("ms-settings:windowsupdate")
}

/// Windows-Sicherheit (Defender) öffnen
#[tauri::command]
pub async fn open_windows_security() -> Result<(), String> {
    #[cfg(windows)]
    return crate::winapp::open("windowsdefender:");
    #[cfg(unix)]
    return Err(crate::settings::tr("Nur unter Windows verfügbar.", "Only available on Windows."));
}

#[cfg(unix)]
#[tauri::command]
pub async fn open_update_manager() -> Result<(), String> {
    // Mint, dann Ubuntu, dann GNOME Software
    for (bin, args) in [("mintupdate", vec![]), ("update-manager", vec![]), ("gnome-software", vec!["--mode", "updates"])] {
        if Command::new(bin).args(&args).process_group(0).spawn().is_ok() {
            return Ok(());
        }
    }
    Err(crate::settings::tr("Keine Aktualisierungsverwaltung gefunden.", "No update manager found."))
}

/// Windows: Autostart über den Eintrag unter HKCU\…\Run
#[cfg(windows)]
#[tauri::command]
pub async fn get_autostart() -> Result<bool, String> {
    Ok(crate::winapp::autostart_enabled())
}

#[cfg(windows)]
#[tauri::command]
pub async fn set_autostart(enabled: bool) -> Result<(), String> {
    crate::winapp::set_autostart(enabled)
}

/// Autostart bei der Anmeldung: an, solange keine abschaltende Benutzerdatei existiert
#[cfg(unix)]
#[tauri::command]
pub async fn get_autostart() -> Result<bool, String> {
    let f = settings::autostart_override();
    Ok(match std::fs::read_to_string(&f) {
        Ok(s) => !s.lines().any(|l| l.trim() == "Hidden=true" || l.trim() == "X-GNOME-Autostart-enabled=false"),
        Err(_) => true,
    })
}

#[cfg(unix)]
#[tauri::command]
pub async fn set_autostart(enabled: bool) -> Result<(), String> {
    let f = settings::autostart_override();
    if enabled {
        match std::fs::remove_file(&f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
        Ok(())
    } else {
        let content = "[Desktop Entry]\nType=Application\nName=Vigil\nExec=vigil --hidden\nHidden=true\nX-GNOME-Autostart-enabled=false\n";
        settings::write_private(&f, content.as_bytes())
    }
}

#[tauri::command]
pub async fn check_update(force: bool) -> Result<crate::update::UpdateInfo, String> {
    tauri::async_runtime::spawn_blocking(move || crate::update::check(force)).await.map_err(|e| e.to_string())
}

/// Update laden, prüfen, installieren und Vigil neu starten
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<HelperResult, String> {
    let a = app.clone();
    let res = tauri::async_runtime::spawn_blocking(move || crate::update::install(&a)).await.map_err(|e| e.to_string())?;
    match res {
        Ok(v) => {
            restart_after_update(&app, 800);
            Ok(HelperResult { ok: true, message: crate::settings::tr(&format!("Vigil {v} ist installiert. Vigil startet neu."), &format!("Vigil {v} is installed. Vigil is restarting.")) })
        }
        Err(e) => Ok(HelperResult { ok: false, message: e }),
    }
}

#[tauri::command]
pub async fn license_status(state: State<'_, AppState>) -> Result<crate::license::LicenseInfo, String> {
    Ok(crate::license::status(&state))
}

/// Nach einem Update von Vigil neu starten. Unter Windows beendet sich die App nur: Der
/// Installer läuft dann im Hintergrund, ersetzt die Dateien und startet Vigil selbst wieder.
fn restart_after_update(app: &AppHandle, delay_ms: u64) {
    let app2 = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        #[cfg(unix)]
        app2.restart();
        #[cfg(windows)]
        app2.exit(0);
    });
}

/// Alles auf einmal aktualisieren: zuerst Vigil Pro (falls neu), dann Vigil selbst (falls neu, danach Neustart).
/// Das Administrator-Passwort fragt das System dabei nur einmal ab (polkit merkt es sich kurz).
#[tauri::command]
pub async fn install_all(app: AppHandle) -> Result<HelperResult, String> {
    use crate::settings::tr;
    let a = app.clone();
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<(bool, Vec<String>), String> {
        let mut done = Vec::new();
        if let Some(v) = crate::license::pro_update_available() {
            crate::license::activate(&a, "", true)?;
            done.push(format!("Vigil Pro {v}"));
        }
        let core = crate::update::check(true);
        if core.available {
            let v = crate::update::install(&a)?;
            done.push(format!("Vigil {v}"));
            return Ok((true, done));
        }
        Ok((false, done))
    })
    .await
    .map_err(|e| e.to_string())?;
    match res {
        Ok((restart, done)) => {
            if restart {
                restart_after_update(&app, 1200);
            }
            let list = done.join(", ");
            Ok(HelperResult {
                ok: true,
                message: if done.is_empty() {
                    tr("Alles ist schon aktuell.", "Everything is already up to date.")
                } else if restart {
                    tr(&format!("{list} installiert. Vigil startet neu."), &format!("{list} installed. Vigil is restarting."))
                } else {
                    tr(&format!("{list} installiert."), &format!("{list} installed."))
                },
            })
        }
        Err(e) => Ok(HelperResult { ok: false, message: e }),
    }
}

/// Beim Lizenzserver nachfragen, ob es eine neuere Pro-Version gibt (ohne zu installieren)
#[tauri::command]
pub async fn license_refresh(app: AppHandle) -> Result<(), String> {
    if crate::license::load().key.is_empty() {
        return Ok(());
    }
    tauri::async_runtime::spawn_blocking(move || crate::license::activate(&app, "", false)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn license_activate(app: AppHandle, key: String) -> Result<HelperResult, String> {
    let r = tauri::async_runtime::spawn_blocking(move || crate::license::activate(&app, &key, true)).await.map_err(|e| e.to_string())?;
    Ok(match r {
        Ok(()) => HelperResult { ok: true, message: crate::settings::tr("Vigil Pro ist freigeschaltet.", "Vigil Pro is activated.") },
        Err(e) => HelperResult { ok: false, message: e },
    })
}

#[tauri::command]
pub async fn license_deactivate(app: AppHandle) -> Result<HelperResult, String> {
    let r = tauri::async_runtime::spawn_blocking(move || crate::license::deactivate(&app)).await.map_err(|e| e.to_string())?;
    Ok(match r {
        Ok(()) => HelperResult { ok: true, message: crate::settings::tr("Vigil Pro ist auf diesem Rechner abgemeldet.", "Vigil Pro is deactivated on this computer.") },
        Err(e) => HelperResult { ok: false, message: e },
    })
}

fn open_https(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(crate::settings::tr("Nur sichere Adressen werden geöffnet.", "Only secure addresses are opened."));
    }
    #[cfg(unix)]
    return Command::new("xdg-open").arg(url).process_group(0).spawn().map(|_| ()).map_err(|e| e.to_string());
    #[cfg(windows)]
    return crate::winapp::open(url);
}

#[tauri::command]
pub async fn license_checkout(plan: String) -> Result<(), String> {
    let url = tauri::async_runtime::spawn_blocking(move || crate::license::checkout(&plan)).await.map_err(|e| e.to_string())??;
    open_https(&url)
}

#[tauri::command]
pub async fn license_portal() -> Result<(), String> {
    let url = tauri::async_runtime::spawn_blocking(crate::license::portal).await.map_err(|e| e.to_string())??;
    open_https(&url)
}

#[tauri::command]
pub async fn license_plans() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(crate::license::plans).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn pro_ui_source() -> Result<String, String> {
    crate::license::ui_source()
}

#[tauri::command]
pub async fn pro_ro(args: Vec<String>) -> Result<RawResult, String> {
    let mut a = vec!["pro-ro".to_string()];
    a.extend(args);
    tauri::async_runtime::spawn_blocking(move || run_raw(false, a)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn pro_rw(args: Vec<String>) -> Result<RawResult, String> {
    let mut a = vec!["pro".to_string()];
    a.extend(args);
    tauri::async_runtime::spawn_blocking(move || run_raw(true, a)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn pro_agent_run(args: Vec<String>) -> Result<RawResult, String> {
    let (ok, stdout, stderr, code) = tauri::async_runtime::spawn_blocking(move || crate::license::agent_run(&args)).await.map_err(|e| e.to_string())??;
    Ok(RawResult { ok, stdout, stderr, code })
}

#[tauri::command]
pub async fn pro_agent_send(app: AppHandle, line: String) -> Result<(), String> {
    crate::license::agent_send(&app, &line)
}

#[derive(Serialize)]
pub struct AppInfo {
    version: String,
    license: String,
    repo: String,
}

#[tauri::command]
pub async fn app_info() -> Result<AppInfo, String> {
    Ok(AppInfo { version: env!("CARGO_PKG_VERSION").into(), license: "GPL-3.0-or-later".into(), repo: format!("https://github.com/{}", crate::update::UPDATE_REPO) })
}

/// Hinweise ausblenden (z. B. alle Phishing-Hinweise eines Mail-Archivs)
#[tauri::command]
pub async fn dismiss_hints(app: AppHandle, items: Vec<settings::Dismissed>) -> Result<(), String> {
    settings::add_dismissed(items.clone())?;
    // Wächter-Hinweise zu diesen Pfaden gelten damit als erledigt
    for it in &items {
        settings::mark_handled(&it.path);
    }
    crate::tray::refresh_now(&app);
    Ok(())
}

#[tauri::command]
pub async fn open_url(url: String) -> Result<(), String> {
    open_https(&url)
}

/// Hintergrundprüfung neuer Berichte für Benachrichtigungen bei geschlossenem Fenster
pub fn watch_reports(app: AppHandle) {
    std::thread::spawn(move || {
        let mut known: HashSet<String> = load_reports().iter().filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(String::from)).collect();
        loop {
            std::thread::sleep(Duration::from_secs(15));
            for r in load_reports() {
                let Some(id) = r.get("id").and_then(|v| v.as_str()).map(String::from) else { continue };
                if !known.insert(id) {
                    continue;
                }
                // Nur echte Bedrohungen melden, keine Hinweise der Heuristik
                let n = r.get("threats").and_then(|v| v.as_array()).map(|a| a.iter().filter(|t| !is_hint_value(t)).count()).unwrap_or(0);
                let visible = app.get_webview_window("main").and_then(|w| w.is_visible().ok()).unwrap_or(false);
                if n > 0 && !visible {
                    crate::notify(&app, &crate::settings::tr(&format!("Vigil: {n} {}", if n == 1 { "Fund" } else { "Funde" }), &format!("Vigil: {n} {}", if n == 1 { "finding" } else { "findings" })), &crate::settings::tr("Eine Prüfung hat verdächtige Dateien gefunden. In Vigil unter Funde entscheiden.", "A scan found suspicious files. Decide in Vigil under Findings."), true);
                }
            }
        }
    });
}
