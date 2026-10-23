//! Maßnahmen des Helfers an Funden, Quarantäne und Konfiguration.
//! Jede Maßnahme an einer Datei prüft sie unmittelbar vorher erneut.

use crate::config;
use crate::engine::Engine;
use crate::fsutil;
use crate::i18n::Text;
use crate::lock;
use crate::quarantine;
use crate::reports;
use crate::schedule;
use crate::tr;
use crate::types::{AllowEntry, Config, QuarantineItem, Threat, ThreatAction};
use std::path::Path;

/// Sucht einen Fund im Bericht.
fn find_threat(report_id: &str, threat_id: &str) -> Result<Threat, Text> {
    let report = reports::read_report(report_id)?;
    report.job.threats.into_iter().find(|t| t.id == threat_id).ok_or_else(|| {
        tr!(
            "Der Fund {} existiert im Bericht {} nicht.",
            "The finding {} does not exist in report {}.",
            threat_id,
            report_id
        )
    })
}

/// Maßnahmen sind nur an Funden möglich, die noch am Ursprungsort liegen.
fn ensure_in_place(t: &Threat) -> Result<(), Text> {
    match t.action {
        ThreatAction::Quarantined => Err(tr!(
            "Der Fund {} liegt bereits in der Quarantäne.",
            "The finding {} is already in quarantine.",
            t.path
        )),
        ThreatAction::Deleted => Err(tr!("Der Fund {} wurde bereits gelöscht.", "The finding {} has already been deleted.", t.path)),
        _ => Ok(()),
    }
}

fn set_action(report_id: Option<&str>, threat_id: Option<&str>, action: ThreatAction, qid: Option<String>) -> Result<(), Text> {
    let (Some(r), Some(t)) = (report_id, threat_id) else { return Ok(()) };
    let _l = lock::data_lock()?;
    match reports::update_threat(r, t, |th| {
        th.action = action;
        th.quarantine_id = qid.clone();
    }) {
        Ok(()) => Ok(()),
        // Bericht inzwischen gelöscht (Begrenzung auf 200): Maßnahme gilt trotzdem
        Err(_) if reports::read_report(r).is_err() => Ok(()),
        Err(e) => Err(e),
    }
}

/// `quarantine --report <id> --threat <tid>`
pub fn quarantine_threat(engine: &Engine, report_id: &str, threat_id: &str) -> Result<QuarantineItem, Text> {
    let t = find_threat(report_id, threat_id)?;
    ensure_in_place(&t)?;
    let item = quarantine::quarantine_path(engine, Path::new(&t.path), Some(report_id), Some(threat_id))?;
    set_action(Some(report_id), Some(threat_id), ThreatAction::Quarantined, Some(item.id.clone()))?;
    Ok(item)
}

/// `quarantine-path --path <p>` (Fund aus dem Download-Wächter).
pub fn quarantine_watcher_path(engine: &Engine, path: &Path) -> Result<QuarantineItem, Text> {
    quarantine::quarantine_path(engine, path, None, None)
}

/// `restore --id <qid>`
pub fn restore(qid: &str) -> Result<(QuarantineItem, Option<Text>), Text> {
    let (item, note) = quarantine::restore(qid)?;
    set_action(item.report_id.as_deref(), item.threat_id.as_deref(), ThreatAction::Restored, None)?;
    Ok((item, note))
}

/// `delete --id <qid>`
pub fn delete_quarantined(qid: &str) -> Result<QuarantineItem, Text> {
    let item = quarantine::delete(qid)?;
    set_action(item.report_id.as_deref(), item.threat_id.as_deref(), ThreatAction::Deleted, None)?;
    Ok(item)
}

/// `delete-threat --report <id> --threat <tid>` (erneut prüfen, dann löschen).
pub fn delete_threat(engine: &Engine, report_id: &str, threat_id: &str) -> Result<Threat, Text> {
    let t = find_threat(report_id, threat_id)?;
    ensure_in_place(&t)?;
    quarantine::delete_infected_path(engine, Path::new(&t.path))?;
    set_action(Some(report_id), Some(threat_id), ThreatAction::Deleted, None)?;
    Ok(t)
}

/// Ergänzt die allowlist (doppelte sha256 werden nicht erneut eingetragen).
fn add_allow(sha256: &str, path: &str, signature: &str) -> Result<(), Text> {
    if !fsutil::is_sha256(sha256) {
        return Err(tr!(
            "Für diesen Fund ist keine gültige Prüfsumme (sha256) bekannt.",
            "No valid checksum (sha256) is known for this finding."
        ));
    }
    let _l = lock::data_lock()?;
    let mut cfg = config::load_config()?;
    if !cfg.allowlist.iter().any(|a| a.sha256 == sha256) {
        cfg.allowlist.push(AllowEntry {
            sha256: sha256.into(),
            path: path.into(),
            signature: signature.into(),
            added_at: crate::now_rfc3339(),
        });
        config::save_config(&cfg)?;
    }
    Ok(())
}

/// `allow --report <id> --threat <tid>`
pub fn allow_threat(report_id: &str, threat_id: &str) -> Result<Threat, Text> {
    let t = find_threat(report_id, threat_id)?;
    ensure_in_place(&t)?;
    add_allow(&t.sha256, &t.path, &t.signature)?;
    set_action(Some(report_id), Some(threat_id), ThreatAction::Allowed, None)?;
    Ok(t)
}

/// `allow-quarantined --id <qid>` (wiederherstellen und freigeben).
pub fn allow_quarantined(qid: &str) -> Result<(QuarantineItem, Option<Text>), Text> {
    let idx = quarantine::load_index()?;
    let pre = idx.items.iter().find(|i| i.id == qid).ok_or_else(|| {
        tr!("Der Quarantäne-Eintrag {} existiert nicht.", "The quarantine entry {} does not exist.", qid)
    })?;
    if !fsutil::is_sha256(&pre.sha256) {
        return Err(tr!(
            "Für diesen Eintrag ist keine gültige Prüfsumme (sha256) bekannt.",
            "No valid checksum (sha256) is known for this entry."
        ));
    }
    let (item, note) = quarantine::restore(qid)?;
    add_allow(&item.sha256, &item.original_path, &item.signature)?;
    set_action(item.report_id.as_deref(), item.threat_id.as_deref(), ThreatAction::Allowed, None)?;
    Ok((item, note))
}

/// `unallow --sha256 <hash>`
pub fn unallow(sha256: &str) -> Result<AllowEntry, Text> {
    let sha = sha256.to_ascii_lowercase();
    let _l = lock::data_lock()?;
    let mut cfg = config::load_config()?;
    let pos = cfg.allowlist.iter().position(|a| a.sha256 == sha).ok_or_else(|| {
        tr!("Der Wert {} steht nicht in der Freigabeliste.", "The value {} is not in the allow list.", sha)
    })?;
    let removed = cfg.allowlist.remove(pos);
    config::save_config(&cfg)?;
    Ok(removed)
}

/// `set-config --json <json>`: prüfen, schreiben, Timer neu schreiben, daemon-reload.
/// Liefert die neue Konfiguration und Hinweise zu Teilfehlern beim Zeitplan.
pub fn set_config(json: &str) -> Result<(Config, Vec<Text>), SetConfigError> {
    let cfg = {
        let _l = lock::data_lock().map_err(SetConfigError::Failed)?;
        let current = config::load_config().map_err(SetConfigError::Failed)?;
        let cfg = config::parse_new_config(json, &current).map_err(SetConfigError::Invalid)?;
        config::save_config(&cfg).map_err(SetConfigError::Failed)?;
        cfg
    };
    let mut notes = schedule::apply(&cfg).map_err(SetConfigError::Failed)?;
    // Zusätzliche Signaturen ausgeschaltet: eigene Dateien sofort aus clamd entfernen
    if !cfg.extra_signatures {
        let before = crate::extrasigs::read_state();
        let had = before.enabled || before.sources.iter().any(|s| !s.files.is_empty());
        match crate::extrasigs::disable() {
            Ok(n) if had => notes.push(n),
            Ok(_) => {}
            Err(e) => notes.push(e),
        }
    }
    if let Err(e) = crate::extrasigs::refresh_state(&cfg) {
        notes.push(e);
    }
    Ok((cfg, notes))
}

/// Fehlerarten von `set-config`.
#[derive(Debug)]
pub enum SetConfigError {
    /// Ungültige Eingabe (Exit 2).
    Invalid(Text),
    /// Ausführung fehlgeschlagen (Exit 4).
    Failed(Text),
}

/// `fix --action firewall-enable|services-enable` unter Windows: Firewall für alle Profile
/// einschalten bzw. den Vigil-Dienst (und damit clamd) neu starten.
#[cfg(windows)]
pub fn run_fix(action: &str) -> Result<Text, Text> {
    use std::time::Duration;
    let (script, ok) = match action {
        "firewall-enable" => (
            "Set-NetFirewallProfile -All -Enabled True",
            tr!("Die Firewall ist eingeschaltet.", "The firewall is turned on."),
        ),
        "services-enable" => (
            "Set-Service -Name Vigil -StartupType Automatic; Restart-Service -Name Vigil -Force",
            tr!("Der Vigil-Dienst wurde neu gestartet.", "The Vigil service has been restarted."),
        ),
        other => return Err(tr!("Unbekannte Maßnahme: {}", "Unknown action: {}", other)),
    };
    crate::systemcheck::powershell(script, Duration::from_secs(120))
        .map(|_| ok)
        .map_err(|e| tr!("{} ist fehlgeschlagen: {}", "{} failed: {}", action, e))
}

/// `fix --action firewall-enable|services-enable|rkhunter-baseline`
#[cfg(unix)]
pub fn run_fix(action: &str) -> Result<Text, Text> {
    use crate::cmd;
    use std::time::Duration;
    let (prog, args, ok): (&str, Vec<&str>, Text) = match action {
        "firewall-enable" => (
            "ufw",
            vec!["--force", "enable"],
            tr!("Die Firewall ist eingeschaltet.", "The firewall is turned on."),
        ),
        "services-enable" => (
            "systemctl",
            vec!["--no-ask-password", "enable", "--now", "clamav-freshclam", "clamav-daemon"],
            tr!("Die ClamAV-Dienste sind eingeschaltet.", "The ClamAV services are turned on."),
        ),
        "rkhunter-baseline" => (
            "rkhunter",
            vec!["--propupd", "--nocolors"],
            tr!("Der Ausgangsstand von rkhunter wurde neu erfasst.", "The rkhunter baseline has been recorded again."),
        ),
        other => return Err(tr!("Unbekannte Maßnahme: {}", "Unknown action: {}", other)),
    };
    let out = cmd::run_named(prog, &args, Duration::from_secs(20 * 60))?;
    if out.success() {
        Ok(ok)
    } else {
        let a = args.join(" ");
        Err(tr!("{} {} ist fehlgeschlagen: {}", "{} {} failed: {}", prog, a, out.error_text()))
    }
}
