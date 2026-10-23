//! Tray: Statusfarbe, drehender Ring während einer Prüfung, Prozentangabe und Live-Menü

use crate::settings::tr;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, Wry};
use vigil_core::paths;

// Symbole, beim Bauen eingebunden
const SAFE: &[u8] = include_bytes!("../icons/tray/safe.png");
const WARN: &[u8] = include_bytes!("../icons/tray/warn.png");
const THREAT: &[u8] = include_bytes!("../icons/tray/threat.png");
const SETUP: &[u8] = include_bytes!("../icons/tray/setup.png");
const PAUSED: &[u8] = include_bytes!("../icons/tray/paused.png");
const FRAMES: [&[u8]; 12] = [
    include_bytes!("../icons/tray/scan-00.png"),
    include_bytes!("../icons/tray/scan-01.png"),
    include_bytes!("../icons/tray/scan-02.png"),
    include_bytes!("../icons/tray/scan-03.png"),
    include_bytes!("../icons/tray/scan-04.png"),
    include_bytes!("../icons/tray/scan-05.png"),
    include_bytes!("../icons/tray/scan-06.png"),
    include_bytes!("../icons/tray/scan-07.png"),
    include_bytes!("../icons/tray/scan-08.png"),
    include_bytes!("../icons/tray/scan-09.png"),
    include_bytes!("../icons/tray/scan-10.png"),
    include_bytes!("../icons/tray/scan-11.png"),
];

// Fortschrittsring in 5-Prozent-Schritten, je mit großem und kleinem Mittelpunkt (Pulsieren)
const PROG: [[&[u8]; 2]; 21] = [
    [include_bytes!("../icons/tray/prog-00-a.png"), include_bytes!("../icons/tray/prog-00-b.png")],
    [include_bytes!("../icons/tray/prog-01-a.png"), include_bytes!("../icons/tray/prog-01-b.png")],
    [include_bytes!("../icons/tray/prog-02-a.png"), include_bytes!("../icons/tray/prog-02-b.png")],
    [include_bytes!("../icons/tray/prog-03-a.png"), include_bytes!("../icons/tray/prog-03-b.png")],
    [include_bytes!("../icons/tray/prog-04-a.png"), include_bytes!("../icons/tray/prog-04-b.png")],
    [include_bytes!("../icons/tray/prog-05-a.png"), include_bytes!("../icons/tray/prog-05-b.png")],
    [include_bytes!("../icons/tray/prog-06-a.png"), include_bytes!("../icons/tray/prog-06-b.png")],
    [include_bytes!("../icons/tray/prog-07-a.png"), include_bytes!("../icons/tray/prog-07-b.png")],
    [include_bytes!("../icons/tray/prog-08-a.png"), include_bytes!("../icons/tray/prog-08-b.png")],
    [include_bytes!("../icons/tray/prog-09-a.png"), include_bytes!("../icons/tray/prog-09-b.png")],
    [include_bytes!("../icons/tray/prog-10-a.png"), include_bytes!("../icons/tray/prog-10-b.png")],
    [include_bytes!("../icons/tray/prog-11-a.png"), include_bytes!("../icons/tray/prog-11-b.png")],
    [include_bytes!("../icons/tray/prog-12-a.png"), include_bytes!("../icons/tray/prog-12-b.png")],
    [include_bytes!("../icons/tray/prog-13-a.png"), include_bytes!("../icons/tray/prog-13-b.png")],
    [include_bytes!("../icons/tray/prog-14-a.png"), include_bytes!("../icons/tray/prog-14-b.png")],
    [include_bytes!("../icons/tray/prog-15-a.png"), include_bytes!("../icons/tray/prog-15-b.png")],
    [include_bytes!("../icons/tray/prog-16-a.png"), include_bytes!("../icons/tray/prog-16-b.png")],
    [include_bytes!("../icons/tray/prog-17-a.png"), include_bytes!("../icons/tray/prog-17-b.png")],
    [include_bytes!("../icons/tray/prog-18-a.png"), include_bytes!("../icons/tray/prog-18-b.png")],
    [include_bytes!("../icons/tray/prog-19-a.png"), include_bytes!("../icons/tray/prog-19-b.png")],
    [include_bytes!("../icons/tray/prog-20-a.png"), include_bytes!("../icons/tray/prog-20-b.png")],
];

static FORCE: AtomicBool = AtomicBool::new(false);

/// Menütexte sofort neu setzen (z. B. nach Sprachwechsel)
pub fn refresh_now(_app: &AppHandle) {
    FORCE.store(true, Ordering::Relaxed);
}

/// Handgriffe auf die veränderlichen Menüeinträge
pub struct TrayItems {
    status: MenuItem<Wry>,
    detail: MenuItem<Wry>,
    sig: MenuItem<Wry>,
    update: MenuItem<Wry>,
    open: MenuItem<Wry>,
    action: MenuItem<Wry>,
    cancel: MenuItem<Wry>,
    quit: MenuItem<Wry>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Setup,
    Scanning,
    Paused,
    Threat,
    Warn,
    Safe,
}

/// Was der Tray gerade zeigen soll
struct View {
    mode: Mode,
    percent: Option<u32>,
    status: String,
    detail: String,
    sig: String,
    update: String,
}

fn read_json(p: &std::path::Path) -> Option<Value> {
    std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok())
}

fn job_active(job: &Value) -> bool {
    matches!(job.get("phase").and_then(|p| p.as_str()), Some("counting" | "scanning" | "paused"))
        && matches!(job.get("kind").and_then(|k| k.as_str()), Some("quick" | "full" | "custom"))
}

fn compute(app: &AppHandle, threats: usize) -> View {
    let state = app.state::<crate::AppState>();
    let installed = crate::commands::is_installed();
    let job = read_json(&paths::state_path()).and_then(|s| s.get("job").cloned()).filter(|j| !j.is_null());
    let sig = crate::commands::cached_signatures(&state);
    let sig_text = match &sig {
        Some((_, _, Some(m))) if *m < 90.0 => tr(&format!("Virendaten geprüft vor {} Min.", m.round()), &format!("Virus data checked {} min ago", m.round())),
        Some((_, _, Some(m))) => tr(&format!("Virendaten geprüft vor {} Std.", (m / 60.0).round()), &format!("Virus data checked {} h ago", (m / 60.0).round())),
        Some((v, _, None)) => tr(&format!("Virendaten Version {v}"), &format!("Virus data version {v}")),
        None => tr("Keine Virendaten gefunden", "No virus data found"),
    };
    let update = crate::update::cached();
    let pro_update = crate::license::pro_update_available();
    let update_text = if update.available {
        tr(&format!("Update verfügbar: Vigil {}", update.latest.clone().unwrap_or_default()), &format!("Update available: Vigil {}", update.latest.clone().unwrap_or_default()))
    } else if let Some(v) = &pro_update {
        tr(&format!("Update verfügbar: Vigil Pro {v}"), &format!("Update available: Vigil Pro {v}"))
    } else {
        format!("Vigil {}", crate::update::current_version())
    };

    if !installed {
        return View { mode: Mode::Setup, percent: None, status: tr("Nicht eingerichtet", "Not set up"), detail: tr("Installation abschließen", "Finish installation"), sig: sig_text, update: update_text };
    }
    if let Some(j) = job.as_ref().filter(|j| job_active(j)) {
        let total = j.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
        let scanned = j.get("scanned").and_then(|x| x.as_u64()).unwrap_or(0);
        let pct = if total > 0 { Some(((scanned * 100) / total).min(100) as u32) } else { None };
        let paused = j.get("phase").and_then(|p| p.as_str()) == Some("paused");
        let detail = tr(&format!("{scanned} von {total} Dateien"), &format!("{scanned} of {total} files"));
        return View {
            mode: if paused { Mode::Paused } else { Mode::Scanning },
            percent: pct,
            status: if paused { tr("Prüfung pausiert", "Scan paused") } else { tr(&format!("Prüft, {} %", pct.unwrap_or(0)), &format!("Scanning, {} %", pct.unwrap_or(0))) },
            detail,
            sig: sig_text,
            update: update_text,
        };
    }
    if threats > 0 {
        return View { mode: Mode::Threat, percent: None, status: tr(&format!("{threats} offene Funde"), &format!("{threats} open findings")), detail: tr("In Vigil unter Funde entscheiden", "Decide in Vigil under Findings"), sig: sig_text, update: update_text };
    }
    let services = crate::commands::cached_services(&state);
    let old = matches!(sig, Some((_, Some(age), _)) if age > 48.0);
    let critical = read_json(&paths::system_path())
        .and_then(|s| s.get("items").and_then(|i| i.as_array()).cloned())
        .map(|items| items.iter().any(|i| i.get("status").and_then(|s| s.as_str()) == Some("critical")))
        .unwrap_or(false);
    let last = job
        .as_ref()
        .and_then(|j| j.get("finishedAt").and_then(|f| f.as_str()).map(String::from))
        .and_then(|f| chrono::DateTime::parse_from_rfc3339(&f).ok())
        .map(|t| t.with_timezone(&chrono::Local).format("%d.%m. %H:%M").to_string());
    let detail = match last {
        Some(t) => tr(&format!("Letzter Auftrag {t}"), &format!("Last task {t}")),
        None => tr("Noch keine Prüfung", "No scan yet"),
    };
    if !services.0 || !services.1 || old || critical {
        return View { mode: Mode::Warn, percent: None, status: tr("Achtung: Schutz eingeschränkt", "Attention: protection limited"), detail, sig: sig_text, update: update_text };
    }
    View { mode: Mode::Safe, percent: None, status: tr("Geschützt", "Protected"), detail, sig: sig_text, update: update_text }
}

fn icon(bytes: &[u8]) -> Option<Image<'static>> {
    Image::from_bytes(bytes).ok().map(|i| i.to_owned())
}

/// Tray anlegen und den Aktualisierungs-Thread starten
pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Vigil", false, None::<&str>)?;
    let detail = MenuItem::with_id(app, "detail", "", false, None::<&str>)?;
    let sig = MenuItem::with_id(app, "sig", "", false, None::<&str>)?;
    let update = MenuItem::with_id(app, "update", "", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Vigil", true, None::<&str>)?;
    let action = MenuItem::with_id(app, "action", "", true, None::<&str>)?;
    let cancel = MenuItem::with_id(app, "cancel", "", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "", true, None::<&str>)?;
    let s1 = PredefinedMenuItem::separator(app)?;
    let s2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&status, &detail, &sig, &update, &s1, &open, &action, &cancel, &s2, &quit])?;

    let tray = TrayIconBuilder::with_id("vigil")
        .menu(&menu)
        .icon(icon(SAFE).expect("Tray-Symbol"))
        .on_menu_event(|app, ev| match ev.id.as_ref() {
            "open" => crate::show_main(app),
            // Update: Fenster zeigen und direkt die Einstellungen mit den Updates öffnen
            "update" => {
                crate::show_main(app);
                let _ = app.emit("open-page", "settings");
            }
            "action" => {
                let job = read_json(&paths::state_path()).and_then(|s| s.get("job").cloned()).filter(|j| !j.is_null());
                let phase = job.as_ref().filter(|j| job_active(j)).and_then(|j| j.get("phase").and_then(|p| p.as_str()).map(String::from));
                let result = match phase.as_deref() {
                    Some("paused") => crate::commands::spawn_job(app, "resume", &[]),
                    Some(_) => crate::commands::spawn_job(app, "pause", &[]),
                    None => crate::commands::spawn_job(app, "quick", &[]),
                };
                if let Err(e) = result {
                    crate::notify(app, &tr("Auftrag nicht gestartet", "Task not started"), &e, false);
                }
                FORCE.store(true, Ordering::Relaxed);
            }
            "cancel" => {
                let _ = crate::commands::spawn_job(app, "cancel", &[]);
                FORCE.store(true, Ordering::Relaxed);
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    let _ = tray.set_tooltip(Some("Vigil"));

    let items = TrayItems { status, detail, sig, update, open, action, cancel, quit };
    let app = app.clone();
    std::thread::spawn(move || run(app, tray, items));
    Ok(())
}

/// Kurze Zustandsdatei für den Pro-Dienst (Geräteübersicht): ~/.local/state/vigil/status.json.
/// Nur Zahlen und Zeitpunkte, keine Pfade oder Dateinamen.
fn write_status(app: &AppHandle, view: &View, threats: usize) {
    let Some(dir) = crate::settings::state_dir() else { return };
    let now = chrono::Local::now();
    let ago = |minutes: f64| (now - chrono::Duration::seconds((minutes * 60.0) as i64)).to_rfc3339();
    let state = crate::commands::cached_signatures(&app.state::<crate::AppState>());
    let core = crate::update::cached();
    let v = serde_json::json!({
        "updatedAt": now.to_rfc3339(),
        "version": crate::update::current_version(),
        "mode": format!("{:?}", view.mode).to_lowercase(),
        "percent": view.percent,
        "openThreats": threats,
        "lastScanAt": crate::commands::last_scan_at(),
        "signaturesCheckedAt": state.and_then(|(_, _, m)| m).map(ago),
        "signaturesAgeHours": state.and_then(|(_, h, _)| h),
        "coreUpdate": core.available.then(|| core.latest.clone()).flatten(),
        "proUpdate": crate::license::pro_update_available(),
    });
    let _ = std::fs::create_dir_all(&dir);
    let tmp = dir.join(".status.json.tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join("status.json"));
    }
}

// 10 Bilder je Sekunde: Ring drehen; Zustand und Texte jede Sekunde, Funde alle 5 s neu lesen
fn run(app: AppHandle, tray: tauri::tray::TrayIcon, items: TrayItems) {
    let mut frame = 0usize;
    let mut pulse_tick = 0u32;
    let mut last_icon = 0usize;
    let mut last_mode: Option<Mode> = None;
    let mut last_texts = String::new();
    let mut last_title: Option<String> = None;
    let mut view_at = Instant::now() - Duration::from_secs(10);
    let mut threats_at = Instant::now() - Duration::from_secs(10);
    let mut threats = 0usize;
    let mut view = compute(&app, 0);
    let mut status_at = Instant::now() - Duration::from_secs(600);
    loop {
        let force = FORCE.swap(false, Ordering::Relaxed);
        if force || threats_at.elapsed() > Duration::from_secs(5) {
            threats = crate::commands::open_threat_count();
            threats_at = Instant::now();
        }
        if force || view_at.elapsed() > Duration::from_secs(1) {
            view = compute(&app, threats);
            view_at = Instant::now();
            // Texte nur bei Änderung setzen
            let action_text = match view.mode {
                Mode::Scanning => tr("Prüfung pausieren", "Pause scan"),
                Mode::Paused => tr("Prüfung fortsetzen", "Resume scan"),
                _ => tr("Schnellprüfung starten", "Start quick scan"),
            };
            let texts = format!("{}|{}|{}|{}|{action_text}|{:?}", view.status, view.detail, view.sig, view.update, view.mode);
            if force || texts != last_texts || status_at.elapsed() > Duration::from_secs(300) {
                write_status(&app, &view, threats);
                status_at = Instant::now();
            }
            if force || texts != last_texts {
                let _ = items.status.set_text(&view.status);
                let _ = items.detail.set_text(&view.detail);
                let _ = items.sig.set_text(&view.sig);
                let _ = items.update.set_text(&view.update);
                let _ = items.update.set_enabled(crate::update::cached().available || crate::license::pro_update_available().is_some());
                let _ = items.open.set_text(tr("Vigil öffnen", "Open Vigil"));
                let _ = items.action.set_text(&action_text);
                let _ = items.action.set_enabled(view.mode != Mode::Setup);
                let _ = items.cancel.set_text(tr("Prüfung abbrechen", "Cancel scan"));
                let _ = items.cancel.set_enabled(matches!(view.mode, Mode::Scanning | Mode::Paused));
                let _ = items.quit.set_text(tr("Beenden", "Quit"));
                let _ = tray.set_tooltip(Some(format!("Vigil: {}", view.status)));
                last_texts = texts;
            }
            // Beschriftung neben dem Symbol
            let title = match view.mode {
                Mode::Scanning => view.percent.map(|p| format!("{p} %")),
                Mode::Paused => Some(tr("Pause", "Paused")),
                _ => None,
            };
            if title != last_title {
                let _ = tray.set_title(title.as_deref());
                last_title = title;
            }
        }
        // Symbol: beim Prüfen füllt sich der Ring mit dem Fortschritt und der Punkt pulsiert;
        // solange gezählt wird (noch kein Fortschritt), dreht sich der Ring
        if view.mode == Mode::Scanning {
            pulse_tick = pulse_tick.wrapping_add(1);
            let bytes = match view.percent {
                Some(p) => PROG[(p.min(100) / 5) as usize][((pulse_tick / 5) % 2) as usize],
                None => {
                    frame = (frame + 1) % FRAMES.len();
                    FRAMES[frame]
                }
            };
            let key = bytes.as_ptr() as usize;
            if key != last_icon {
                if let Some(i) = icon(bytes) {
                    let _ = tray.set_icon(Some(i));
                }
                last_icon = key;
            }
            last_mode = Some(Mode::Scanning);
        } else if last_mode != Some(view.mode) {
            let bytes = match view.mode {
                Mode::Setup => SETUP,
                Mode::Paused => PAUSED,
                Mode::Threat => THREAT,
                Mode::Warn => WARN,
                _ => SAFE,
            };
            if let Some(i) = icon(bytes) {
                let _ = tray.set_icon(Some(i));
            }
            last_icon = bytes.as_ptr() as usize;
            last_mode = Some(view.mode);
        }
        std::thread::sleep(Duration::from_millis(if view.mode == Mode::Scanning { 100 } else { 500 }));
    }
}
