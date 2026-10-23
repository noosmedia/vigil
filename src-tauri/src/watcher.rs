//! Download-Wächter: prüft neue Dateien in den beobachteten Ordnern über clamd

use crate::settings::{self, WatcherEvent};
use notify::event::{AccessKind, AccessMode, CreateKind, ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};
use tauri::{AppHandle, Emitter, Manager};

// Halbfertige Downloads der Browser werden erst nach dem Umbenennen geprüft
const PARTIAL: [&str; 6] = [".part", ".crdownload", ".download", ".tmp", ".partial", ".opdownload"];

// Ruhezeit, nach der eine Datei als fertig geschrieben gilt
const SETTLE: Duration = Duration::from_millis(1500);

fn relevant(kind: &EventKind) -> bool {
    // Windows meldet Schreibvorgänge nur allgemein als Änderung (ReadDirectoryChangesW)
    #[cfg(windows)]
    if matches!(kind, EventKind::Modify(ModifyKind::Any)) {
        return true;
    }
    matches!(
        kind,
        EventKind::Create(CreateKind::File)
            | EventKind::Create(CreateKind::Any)
            | EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Name(RenameMode::To))
            | EventKind::Modify(ModifyKind::Name(RenameMode::Both))
            | EventKind::Access(AccessKind::Close(AccessMode::Write))
    )
}

fn skip_name(p: &Path) -> bool {
    let name = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    name.starts_with('.') || PARTIAL.iter().any(|s| name.ends_with(s))
}

/// Startet den Wächter für die angegebenen Ordner. Der Wächter läuft, bis das
/// zurückgegebene Objekt verworfen wird.
pub fn start(app: AppHandle, paths: &[String]) -> Result<RecommendedWatcher, String> {
    let (tx, rx) = channel::<PathBuf>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        if let Ok(ev) = res {
            if relevant(&ev.kind) {
                for p in ev.paths {
                    let _ = tx.send(p);
                }
            }
        }
    })
    .map_err(|e| format!("Dateibeobachtung nicht startbar: {e}"))?;

    let mut watched = 0;
    for p in paths {
        let path = Path::new(p);
        if path.is_dir() && watcher.watch(path, RecursiveMode::Recursive).is_ok() {
            watched += 1;
        }
    }
    if watched == 0 {
        return Err("Keiner der Ordner für den Download-Wächter ist vorhanden.".into());
    }

    // Verarbeitung in eigenem Thread: sammeln, Ruhezeit abwarten, prüfen
    std::thread::spawn(move || {
        let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
        let mut seen: HashMap<PathBuf, (u64, SystemTime)> = HashMap::new();
        loop {
            match rx.recv_timeout(Duration::from_millis(400)) {
                Ok(p) => {
                    pending.insert(p, Instant::now());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let ready: Vec<PathBuf> = pending.iter().filter(|(_, t)| t.elapsed() >= SETTLE).map(|(p, _)| p.clone()).collect();
            for p in ready {
                pending.remove(&p);
                if skip_name(&p) {
                    continue;
                }
                let Ok(meta) = std::fs::metadata(&p) else { continue };
                if !meta.is_file() || meta.len() == 0 {
                    continue;
                }
                // Gleiche Datei mit gleicher Größe und Zeit nicht zweimal prüfen
                let sig = (meta.len(), meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
                if seen.get(&p) == Some(&sig) {
                    continue;
                }
                if seen.len() > 2000 {
                    seen.clear();
                }
                seen.insert(p.clone(), sig);
                check(&app, &p);
            }
        }
    });

    Ok(watcher)
}

fn check(app: &AppHandle, p: &Path) {
    let socket = vigil_core::clamd::clamd_socket();
    let (verdict, detail) = match vigil_core::clamd::scan_file_stream(&socket, p) {
        Ok(vigil_core::clamd::Verdict::Clean) => ("clean", None),
        // Heuristische Erkennungen sind nur Hinweise
        Ok(vigil_core::clamd::Verdict::Infected(sig)) if crate::commands::is_hint_signature(&sig) => ("hint", Some(sig)),
        Ok(vigil_core::clamd::Verdict::Infected(sig)) => ("infected", Some(sig)),
        Ok(vigil_core::clamd::Verdict::Skipped(why)) => ("skipped", Some(why)),
        Err(e) => ("error", Some(e)),
    };
    let ev = WatcherEvent {
        at: vigil_core::now_rfc3339(),
        path: p.to_string_lossy().into_owned(),
        verdict: verdict.into(),
        detail,
        handled: false,
    };
    settings::push_event(&ev);
    if let Some(state) = app.try_state::<crate::AppState>() {
        *state.watcher_last.lock().unwrap() = Some(ev.clone());
    }
    let _ = app.emit("watcher-event", &ev);
    if verdict == "infected" {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        crate::notify(
            app,
            "Bedrohung im Download gefunden",
            &format!("{name}: {}. In Vigil unter Funde in Quarantäne verschieben.", ev.detail.clone().unwrap_or_default()),
            true,
        );
    }
}
