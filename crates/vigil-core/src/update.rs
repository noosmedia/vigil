//! Signaturen aktualisieren: clamav-freshclam neu starten und bis zu 120 s auf das
//! Ergebnis warten (neue Version oder Meldung "up-to-date"). Sind die zusätzlichen
//! Signaturen eingeschaltet (`extraSignatures`), werden sie im selben Auftrag mit abgerufen.

use crate::cmd;
use crate::config;
use crate::extrasigs;
use crate::i18n::Text;
use crate::paths;
use crate::state::{new_job, StateWriter};
use crate::sysinfo;
use crate::tr;
use crate::types::{Job, JobKind, Phase, Trigger};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wartezeit auf freshclam.
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(120);

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

/// Ergebnis von [`run_update`]: Auftrag, ClamAV-Teil und (falls eingeschaltet) zusätzliche Signaturen.
pub struct UpdateResult {
    pub job: Job,
    pub clamav: ClamavResult,
    /// `None`, wenn die zusätzlichen Signaturen ausgeschaltet sind.
    pub extra: Option<extrasigs::Outcome>,
}

/// Führt die Aktualisierung als Auftrag `update` aus (state.json wird geschrieben).
/// Die Phase ist `failed`, wenn der ClamAV-Teil scheitert; ein Fehler der zusätzlichen
/// Signaturen steht nur in der Meldung (der ClamAV-Stand ist davon unabhängig).
pub fn run_update(trigger: Trigger) -> UpdateResult {
    let mut writer = StateWriter::new();
    let mut job = new_job(JobKind::Update, trigger, Vec::new());
    job.set_current(Some(&tr!("clamav-freshclam wird neu gestartet", "Restarting clamav-freshclam")));
    writer.force(&job);

    let result = update_inner(&mut job, &mut writer);
    let extra_on = config::load_config().map(|c| c.extra_signatures).unwrap_or(true);
    let extra = if extra_on {
        job.set_current(Some(&tr!(
            "Zusätzliche Signaturen von Sanesecurity werden abgerufen",
            "Fetching additional signatures from Sanesecurity"
        )));
        writer.force(&job);
        Some(extrasigs::run())
    } else {
        None
    };
    job.finished_at = Some(crate::now_rfc3339());
    job.set_current(None);
    let (clamav, clamav_msg) = match result {
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
    let msg = match &extra {
        Some(x) => Text::join(&[tr!("ClamAV: {}", "ClamAV: {}", clamav_msg), x.message.clone()]),
        None => clamav_msg,
    };
    job.set_message(&msg);
    writer.force(&job);
    UpdateResult { job, clamav, extra }
}

/// Startet freshclam neu und wartet auf das Ergebnis. `Ok((Meldung, neue Daten?))`.
fn update_inner(job: &mut Job, writer: &mut StateWriter) -> Result<(Text, bool), Text> {
    // Im Testbetrieb wird der Systemdienst nie angefasst
    if paths::is_dev() {
        return Ok((
            tr!("Testbetrieb: clamav-freshclam wurde nicht neu gestartet.", "Test mode: clamav-freshclam was not restarted."),
            false,
        ));
    }
    let before = sysinfo::signature_info().map(|s| s.version);
    let since = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let t = Duration::from_secs(60);

    let restart = cmd::run_named("systemctl", &["--no-ask-password", "restart", "clamav-freshclam"], t)?;
    if !restart.success() {
        return Err(tr!(
            "Der Dienst clamav-freshclam konnte nicht neu gestartet werden: {}",
            "Could not restart the clamav-freshclam service: {}",
            restart.error_text()
        ));
    }
    job.set_current(Some(&tr!("Warte auf freshclam", "Waiting for freshclam")));
    writer.force(job);

    let start = Instant::now();
    let since_arg = format!("@{since}");
    let mut last_journal = String::new();
    let unknown = tr!("unbekannt", "unknown");
    while start.elapsed() < UPDATE_TIMEOUT {
        thread::sleep(Duration::from_secs(2));
        writer.update(job);

        // Neue Signaturversion?
        let now = sysinfo::signature_info().map(|s| s.version);
        if let (Some(n), b) = (now, before) {
            if b != Some(n) {
                return Ok((tr!("Die Signaturen wurden aktualisiert (Version {}).", "The signatures were updated (version {}).", n), true));
            }
        }
        // Meldungen von freshclam seit dem Neustart
        if let Ok(j) = cmd::run_named(
            "journalctl",
            &["-u", "clamav-freshclam", "--since", &since_arg, "-o", "cat", "--no-pager"],
            Duration::from_secs(20),
        ) {
            last_journal = j.stdout;
        }
        let log = last_journal.to_lowercase();
        if log.contains("cool-down") || log.contains("rate limit") {
            return Err(tr!(
                "Der Signaturserver hat die Anfrage vorübergehend gesperrt. {}",
                "The signature server has temporarily blocked the request. {}",
                tail(&last_journal, 5)
            ));
        }
        if log.contains("database updated") {
            let v = sysinfo::signature_info().map(|s| Text::same(s.version.to_string())).unwrap_or_else(|| unknown.clone());
            return Ok((tr!("Die Signaturen wurden aktualisiert (Version {}).", "The signatures were updated (version {}).", v), true));
        }
        if log.contains("daily.cld database is up-to-date") || log.contains("daily.cvd database is up-to-date") {
            let v = now.map(|v| Text::same(v.to_string())).unwrap_or_else(|| unknown.clone());
            return Ok((tr!("Die Signaturen sind bereits aktuell (Version {}).", "The signatures are already up to date (version {}).", v), false));
        }
        // Dienst ausgefallen?
        if let Ok(a) = cmd::run_named("systemctl", &["is-active", "clamav-freshclam"], Duration::from_secs(10)) {
            if a.stdout.trim() == "failed" {
                return Err(tr!(
                    "Der Dienst clamav-freshclam ist ausgefallen. {}",
                    "The clamav-freshclam service has failed. {}",
                    tail(&last_journal, 5)
                ));
            }
        }
    }
    Err(tr!(
        "freshclam hat innerhalb von {} Sekunden keine Rückmeldung gegeben. {}",
        "freshclam did not respond within {} seconds. {}",
        UPDATE_TIMEOUT.as_secs(),
        tail(&last_journal, 5)
    ))
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
