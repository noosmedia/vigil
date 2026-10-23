//! Berichte unter `/var/lib/vigil/reports/<id>.json` (höchstens 200, älteste zuerst löschen).

use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::tr;
use crate::types::{Report, State, Threat};
use std::fs;

/// Höchstzahl gespeicherter Berichte.
pub const MAX_REPORTS: usize = 200;

/// Kennungen aller Berichte, älteste zuerst (Kennungen beginnen mit Datum und Uhrzeit).
pub fn list_report_ids() -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir(paths::reports_dir())
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let id = name.strip_suffix(".json")?.to_string();
                    paths::valid_id(&id).then_some(id)
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

/// Liest einen Bericht.
pub fn read_report(id: &str) -> Result<Report, Text> {
    let p = paths::report_path(id).ok_or_else(|| tr!("Ungültige Berichtskennung: {}", "Invalid report ID: {}", id))?;
    fsutil::read_json(&p)?.ok_or_else(|| tr!("Der Bericht {} existiert nicht.", "The report {} does not exist.", id))
}

/// Alle Berichte, neueste zuerst. Unlesbare Berichte werden übersprungen.
pub fn list_reports() -> Vec<Report> {
    let mut v: Vec<Report> = list_report_ids().iter().filter_map(|id| read_report(id).ok()).collect();
    v.reverse();
    v
}

/// Schreibt einen Bericht und löscht die ältesten über der Höchstzahl.
pub fn write_report(report: &Report) -> Result<(), Text> {
    fsutil::ensure_dir(&paths::reports_dir(), 0o755)?;
    let p = paths::report_path(&report.job.id)
        .ok_or_else(|| tr!("Ungültige Berichtskennung: {}", "Invalid report ID: {}", report.job.id))?;
    fsutil::write_json(&p, report, 0o644)?;
    let ids = list_report_ids();
    if ids.len() > MAX_REPORTS {
        for id in &ids[..ids.len() - MAX_REPORTS] {
            if let Some(old) = paths::report_path(id) {
                let _ = fs::remove_file(old);
            }
        }
    }
    Ok(())
}

/// Ändert einen Fund im Bericht und, falls derselbe Auftrag noch in state.json steht, auch dort.
/// Aufrufer muss `data.lock` halten.
pub fn update_threat<F: Fn(&mut Threat)>(report_id: &str, threat_id: &str, f: F) -> Result<(), Text> {
    let mut report = read_report(report_id)?;
    let t = report.job.threats.iter_mut().find(|t| t.id == threat_id).ok_or_else(|| {
        tr!(
            "Der Fund {} existiert im Bericht {} nicht.",
            "The finding {} does not exist in report {}.",
            threat_id,
            report_id
        )
    })?;
    f(t);
    write_report(&report)?;

    // state.json nachziehen, damit die Anzeige des letzten Auftrags stimmt
    let sp = paths::state_path();
    if let Ok(Some(mut state)) = fsutil::read_json::<State>(&sp) {
        if let Some(job) = state.job.as_mut().filter(|j| j.id == report_id) {
            if let Some(t) = job.threats.iter_mut().find(|t| t.id == threat_id) {
                f(t);
                state.updated_at = crate::now_rfc3339();
                let _ = fsutil::write_json(&sp, &state, 0o644);
            }
        }
    }
    Ok(())
}
