//! state.json lesen und gedrosselt schreiben (höchstens alle 250 ms).

use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::types::{Job, JobKind, Phase, State, Trigger};
use std::time::{Duration, Instant};

/// Mindestabstand zwischen zwei Schreibvorgängen.
pub const STATE_INTERVAL: Duration = Duration::from_millis(250);

/// Liest state.json. Fehlt die Datei, ist `job` null.
pub fn read_state() -> Result<State, Text> {
    Ok(fsutil::read_json(&paths::state_path())?.unwrap_or_else(|| State { updated_at: crate::now_rfc3339(), job: None }))
}

/// Neuer Auftrag mit Kennung `JJJJMMTT-hhmmss-<art>`.
pub fn new_job(kind: JobKind, trigger: Trigger, paths: Vec<String>) -> Job {
    let now = chrono::Local::now();
    let mut id = format!("{}-{}", now.format("%Y%m%d-%H%M%S"), kind.as_str());
    // Zwei Aufträge in derselben Sekunde: Kennung eindeutig machen
    let mut n = 2;
    while paths::report_path(&id).map(|p| p.exists()).unwrap_or(false) {
        id = format!("{}-{}-{}", now.format("%Y%m%d-%H%M%S"), kind.as_str(), n);
        n += 1;
    }
    Job {
        id,
        kind,
        trigger,
        phase: if kind.is_scan() { Phase::Counting } else { Phase::Running },
        started_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        finished_at: None,
        paths,
        engine: None,
        total: 0,
        counted: false,
        scanned: 0,
        skipped: 0,
        errors: 0,
        bytes: 0,
        current: None,
        current_en: None,
        threats: Vec::new(),
        message: None,
        message_en: None,
        segments: Vec::new(),
        segment_index: 0,
    }
}

/// Schreibt state.json höchstens alle 250 ms (außer erzwungen).
pub struct StateWriter {
    last: Option<Instant>,
}

impl StateWriter {
    pub fn new() -> Self {
        StateWriter { last: None }
    }

    /// Ist der nächste Schreibvorgang fällig (mindestens 250 ms seit dem letzten)?
    pub fn due(&self) -> bool {
        self.last.map(|t| t.elapsed() >= STATE_INTERVAL).unwrap_or(true)
    }

    /// Schreibt, wenn seit dem letzten Mal mindestens 250 ms vergangen sind.
    pub fn update(&mut self, job: &Job) {
        if self.due() {
            self.force(job);
        }
    }

    /// Schreibt auf jeden Fall, wartet aber den Mindestabstand ab
    /// (Fehler werden ignoriert, ein Auftrag soll daran nicht scheitern).
    pub fn force(&mut self, job: &Job) {
        if let Some(t) = self.last {
            let since = t.elapsed();
            if since < STATE_INTERVAL {
                std::thread::sleep(STATE_INTERVAL - since);
            }
        }
        let state = State { updated_at: crate::now_rfc3339(), job: Some(job.clone()) };
        let _ = fsutil::write_json(&paths::state_path(), &state, 0o644);
        self.last = Some(Instant::now());
    }
}

impl Default for StateWriter {
    fn default() -> Self {
        Self::new()
    }
}
