//! Signaturen aktualisieren unter Windows (Gegenstück zu `update.rs` unter Linux): freshclam
//! aus dem mitgelieferten ClamAV einmal ausführen und das Ergebnis auswerten. freshclam meldet
//! clamd das Neuladen selbst (`NotifyClamd`). Zusätzliche Signaturen gibt es unter Windows nicht.

use crate::extrasigs;
use crate::i18n::Text;
use crate::paths;
use crate::state::{new_job, StateWriter};
use crate::sysinfo;
use crate::tr;
use crate::types::{Job, JobKind, Phase, Trigger};
use crate::win::clamav;
use std::time::Duration;

/// Wartezeit auf freshclam.
pub const UPDATE_TIMEOUT: Duration = clamav::FRESHCLAM_TIMEOUT;

/// Ergebnis der ClamAV-Signaturen bei `update-signatures`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClamavResult {
    /// Neue Signaturen geladen.
    Updated,
    /// Bereits aktuell.
    Current,
    Failed,
}

impl ClamavResult {
    /// Name für die Erfolgszeile des Helfers.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClamavResult::Updated => "updated",
            ClamavResult::Current => "current",
            ClamavResult::Failed => "failed",
        }
    }
}

/// Ergebnis von [`run_update`]: Auftrag, ClamAV-Teil und (unter Windows immer `None`)
/// zusätzliche Signaturen.
pub struct UpdateResult {
    pub job: Job,
    pub clamav: ClamavResult,
    pub extra: Option<extrasigs::Outcome>,
}

/// Führt die Aktualisierung als Auftrag `update` aus (state.json wird geschrieben).
pub fn run_update(trigger: Trigger) -> UpdateResult {
    let mut writer = StateWriter::new();
    let mut job = new_job(JobKind::Update, trigger, Vec::new());
    job.set_current(Some(&tr!("freshclam lädt die Virendaten", "freshclam is downloading the virus data")));
    writer.force(&job);

    let result = update_inner();
    job.finished_at = Some(crate::now_rfc3339());
    job.set_current(None);
    let (clamav_result, msg) = match result {
        Ok((msg, updated)) => {
            job.phase = Phase::Finished;
            (if updated { ClamavResult::Updated } else { ClamavResult::Current }, msg)
        }
        Err(e) => {
            job.phase = Phase::Failed;
            let msg = tr!("Die Aktualisierung der Signaturen ist fehlgeschlagen: {}", "Updating the signatures failed: {}", e);
            (ClamavResult::Failed, msg)
        }
    };
    job.set_message(&msg);
    writer.force(&job);
    UpdateResult { job, clamav: clamav_result, extra: None }
}

/// Führt freshclam aus. `Ok((Meldung, neue Daten?))`.
fn update_inner() -> Result<(Text, bool), Text> {
    if paths::is_dev() {
        return Ok((tr!("Testbetrieb: freshclam wurde nicht ausgeführt.", "Test mode: freshclam was not run."), false));
    }
    let cfg = crate::config::load_config().unwrap_or_default();
    clamav::write_configs(cfg.signature_interval_hours)?;
    let before = sysinfo::signature_info().map(|s| s.version);
    let out = clamav::run_freshclam()?;
    let log = format!("{}\n{}", out.stdout, out.stderr);
    let lower = log.to_lowercase();
    let last = tail(&log, 5);
    if out.timed_out {
        return Err(tr!(
            "freshclam hat innerhalb von {} Minuten keine Rückmeldung gegeben. {}",
            "freshclam did not respond within {} minutes. {}",
            UPDATE_TIMEOUT.as_secs() / 60,
            last
        ));
    }
    if lower.contains("cool-down") || lower.contains("rate limit") || lower.contains("rate-limit") {
        return Err(tr!(
            "Der Signaturserver hat die Anfrage vorübergehend gesperrt. {}",
            "The signature server has temporarily blocked the request. {}",
            last
        ));
    }
    // freshclam: Exit 0 = aktualisiert, 1 = schon aktuell, alles andere ist ein Fehler
    if !matches!(out.code, Some(0) | Some(1)) {
        return Err(tr!("freshclam ist fehlgeschlagen: {}", "freshclam failed: {}", last));
    }
    let now = sysinfo::signature_info().map(|s| s.version);
    let unknown = tr!("unbekannt", "unknown");
    let v = now.map(|v| Text::same(v.to_string())).unwrap_or_else(|| unknown.clone());
    if now.is_some() && now != before || lower.contains("database updated") || lower.contains(" updated (version") {
        return Ok((tr!("Die Signaturen wurden aktualisiert (Version {}).", "The signatures were updated (version {}).", v), true));
    }
    Ok((tr!("Die Signaturen sind bereits aktuell (Version {}).", "The signatures are already up to date (version {}).", v), false))
}

/// Letzte Zeilen eines Textes, in einer Zeile zusammengefasst.
fn tail(text: &str, n: usize) -> Text {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    let t = lines[start..].join(" | ");
    if t.is_empty() {
        Text::default()
    } else {
        tr!("Letzte Meldungen: {}", "Last messages: {}", t)
    }
}
