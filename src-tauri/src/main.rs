//! Vigil: Fenster, Tray, Download-Wächter, Updates und Pro-Anbindung
// Unter Windows ein Fensterprogramm ohne zusätzliches Konsolenfenster (im Release-Build)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod crypto;
mod license;
mod settings;
mod tray;
mod update;
mod watcher;
#[cfg(windows)]
mod winapp;

#[cfg(unix)]
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;
use tauri::{AppHandle, Manager, WindowEvent};

/// Kleinste Fenstergröße, bei der alle Seiten sauber aufgebaut sind
const MIN_WIDTH: f64 = 1080.0;
const MIN_HEIGHT: f64 = 740.0;

/// Gemeinsamer Zustand der App
pub struct AppState {
    pub watcher: Mutex<Option<notify::RecommendedWatcher>>,
    pub watcher_last: Mutex<Option<settings::WatcherEvent>>,
    pub sig_cache: Mutex<(Option<Instant>, Option<commands::Signatures>)>,
    pub svc_cache: Mutex<(Option<Instant>, Option<commands::Services>)>,
    pub pro_agent: license::AgentSlot,
}

/// Desktop-Benachrichtigung über notify-send, sofern eingeschaltet
#[cfg(unix)]
pub fn notify(_app: &AppHandle, title: &str, body: &str, critical: bool) {
    if !settings::load().notifications {
        return;
    }
    let _ = Command::new("notify-send")
        .args(["-a", "Vigil", "-i", "vigil", "-u", if critical { "critical" } else { "normal" }, title, body])
        .spawn();
}

/// Windows: Benachrichtigung im Infobereich (Toast), sofern eingeschaltet
#[cfg(windows)]
pub fn notify(app: &AppHandle, title: &str, body: &str, _critical: bool) {
    use tauri_plugin_notification::NotificationExt;
    if !settings::load().notifications {
        return;
    }
    let _ = app.notification().builder().title(title).body(body).show();
}

/// Wächter passend zu den Einstellungen starten, neu starten oder anhalten
pub fn apply_watcher(app: &AppHandle, s: &settings::Settings) {
    let state = app.state::<AppState>();
    let mut slot = state.watcher.lock().unwrap();
    *slot = None;
    if s.watcher_enabled {
        match watcher::start(app.clone(), &s.watcher_paths) {
            Ok(w) => *slot = Some(w),
            Err(e) => eprintln!("Download-Wächter: {e}"),
        }
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
        set_webview_visible(&w, true);
    }
}

/// Windows: WebView2 mitteilen, ob das Fenster zu sehen ist. Sonst laufen die Animationen auch
/// bei verstecktem oder minimiertem Fenster weiter und nehmen einer Prüfung Rechenzeit weg
/// (`document.hidden` bleibt sonst false). Unter Linux ohne Wirkung.
pub fn set_webview_visible(w: &tauri::WebviewWindow, visible: bool) {
    #[cfg(windows)]
    let _ = w.with_webview(move |wv| {
        // SAFETY: Aufruf auf dem Controller der eigenen WebView im Hauptthread von Tauri
        unsafe {
            let _ = wv.controller().SetIsVisible(visible);
        }
    });
    #[cfg(unix)]
    let _ = (w, visible);
}

fn main() {
    let builder = tauri::Builder::default()
        // Zweiter Start holt das laufende Fenster nach vorn
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|a| a == "--hidden") {
                show_main(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init());
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_notification::init());
    builder
        .manage(AppState {
            watcher: Mutex::new(None),
            watcher_last: Mutex::new(settings::load_events().into_iter().next()),
            sig_cache: Mutex::new((None, None)),
            svc_cache: Mutex::new((None, None)),
            pro_agent: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::live,
            commands::snapshot,
            commands::reports,
            commands::open_threats,
            commands::start_job,
            commands::pause_job,
            commands::resume_job,
            commands::run_helper,
            commands::save_settings,
            commands::pick_folders,
            commands::open_update_manager,
            commands::open_windows_security,
            commands::get_autostart,
            commands::set_autostart,
            commands::check_update,
            commands::install_update,
            commands::license_status,
            commands::license_activate,
            commands::license_refresh,
            commands::install_all,
            commands::license_deactivate,
            commands::license_checkout,
            commands::license_portal,
            commands::license_plans,
            commands::pro_ui_source,
            commands::pro_ro,
            commands::pro_rw,
            commands::pro_agent_run,
            commands::pro_agent_send,
            commands::app_info,
            commands::open_url,
            commands::dismiss_hints,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            tray::setup(&handle)?;
            // Windows: beim ersten Start Autostart einschalten (danach gilt die Wahl des Benutzers)
            #[cfg(windows)]
            winapp::init_autostart();

            // Fenster schließen versteckt es nur, Vigil wacht im Tray weiter
            if let Some(w) = app.get_webview_window("main") {
                // Mindestgröße zusätzlich zur Konfiguration direkt setzen (unter Cinnamon sonst nicht verlässlich)
                let _ = w.set_min_size(Some(tauri::LogicalSize::new(MIN_WIDTH, MIN_HEIGHT)));
                let w2 = w.clone();
                w.on_window_event(move |e| match e {
                    WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        let _ = w2.hide();
                        set_webview_visible(&w2, false);
                    }
                    // Minimieren, Wiederherstellen, Fokus (auch durch das Menü im Infobereich bei
                    // verstecktem Fenster): die WebView ist nur aktiv, wenn das Fenster zu sehen ist
                    WindowEvent::Resized(_) | WindowEvent::Focused(_) => {
                        let shown = !w2.is_minimized().unwrap_or(false) && w2.is_visible().unwrap_or(true);
                        set_webview_visible(&w2, shown);
                    }
                    _ => {}
                });
                if !std::env::args().any(|a| a == "--hidden") {
                    let _ = w.show();
                }
            }

            apply_watcher(&handle, &settings::load());
            commands::watch_reports(handle.clone());
            update::watch(handle.clone());
            license::watch(handle);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Vigil konnte nicht starten")
        .run(|app, ev| {
            // Pro-Agent beim Beenden sauber stoppen
            if let tauri::RunEvent::Exit = ev {
                license::stop_agent(app);
            }
        });
}
