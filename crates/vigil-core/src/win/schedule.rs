//! Zeitplan unter Windows (Gegenstück zu `schedule.rs` mit systemd-Timern unter Linux).
//!
//! Der Vigil-Dienst prüft jede halbe Minute mit [`take_due`], welche Aufgaben fällig sind:
//! Schnellprüfung, vollständige Prüfung, Systemcheck und automatische Updates zur eingestellten
//! Zeit, dazu die Virendaten im Abstand `signatureIntervalHours`. Wie `Persistent=true` bei
//! systemd wird eine verpasste Aufgabe (Rechner war aus) beim nächsten Start einmal nachgeholt.
//! Die letzten Läufe stehen in `C:\ProgramData\Vigil\schedule.json`.

use crate::config::parse_time;
use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::types::{Config, Day, ScheduleEntry};
use chrono::{DateTime, Datelike, Duration as ChronoDuration, Local, TimeZone, Timelike, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Name der Aufgabe „automatische Updates“ (wie der Timer unter Linux).
pub const SELFUPDATE_TIMER: &str = "selfupdate";
/// Name der Aufgabe „Virendaten aktualisieren“.
pub const SIGNATURES_TIMER: &str = "signatures";

/// Gespeicherte letzte Läufe je Aufgabe.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ScheduleState {
    last: BTreeMap<String, String>,
}

/// Geplante Aufgabe: Name, letzter geplanter Zeitpunkt, Befehl.
type Planned = (&'static str, Option<DateTime<Local>>, Vec<String>);

/// Eine fällige Aufgabe: Name und Befehl für den Helfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub name: &'static str,
    pub args: Vec<String>,
}

/// Alle Zeitpläne mit ihrem Eintrag (wie `timers` unter Linux).
pub fn timers(cfg: &Config) -> Vec<(&'static str, ScheduleEntry)> {
    let s = &cfg.schedule;
    vec![
        ("quick", s.quick.clone()),
        ("full", s.full.clone()),
        ("systemcheck", s.systemcheck.clone()),
        (
            SELFUPDATE_TIMER,
            ScheduleEntry { enabled: cfg.updates.auto, time: cfg.updates.time.clone(), days: Day::ALL.to_vec() },
        ),
    ]
}

fn weekday(d: Day) -> Weekday {
    match d {
        Day::Mon => Weekday::Mon,
        Day::Tue => Weekday::Tue,
        Day::Wed => Weekday::Wed,
        Day::Thu => Weekday::Thu,
        Day::Fri => Weekday::Fri,
        Day::Sat => Weekday::Sat,
        Day::Sun => Weekday::Sun,
    }
}

/// Letzter geplanter Zeitpunkt eines Eintrags bis `now` (höchstens 8 Tage zurück).
/// Keine Tage oder alle Tage heißt täglich (wie OnCalendar unter Linux).
pub fn last_occurrence(e: &ScheduleEntry, now: DateTime<Local>) -> Option<DateTime<Local>> {
    if !e.enabled {
        return None;
    }
    let (h, m) = parse_time(&e.time)?;
    let every_day = e.days.is_empty() || e.days.len() == 7;
    for back in 0..8 {
        let date = (now - ChronoDuration::days(back)).date_naive();
        if !every_day && !e.days.iter().any(|d| weekday(*d) == date.weekday()) {
            continue;
        }
        let t = Local.from_local_datetime(&date.and_hms_opt(h, m, 0)?).earliest()?;
        if t <= now {
            return Some(t);
        }
    }
    None
}

/// Letzter Zeitpunkt im Abstand von `hours` Stunden (volle Stunden ab Mitternacht).
fn last_interval(hours: u32, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let hours = hours.clamp(1, 24);
    let h = now.hour() - now.hour() % hours;
    Local.from_local_datetime(&now.date_naive().and_hms_opt(h, 0, 0)?).earliest()
}

fn load_state() -> ScheduleState {
    fsutil::read_json(&paths::schedule_state_path()).ok().flatten().unwrap_or_default()
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Ermittelt die fälligen Aufgaben, vermerkt sie als gelaufen und liefert sie in fester
/// Reihenfolge (Virendaten zuerst). Beim allerersten Aufruf wird nur der Stand gesetzt, damit
/// nach der Installation nicht sofort alles auf einmal startet.
pub fn take_due(cfg: &Config) -> Vec<Task> {
    let now = Local::now();
    let mut state = load_state();
    let first = state.last.is_empty();
    let mut plan: Vec<Planned> =
        vec![(SIGNATURES_TIMER, last_interval(cfg.signature_interval_hours, now), args(&["update-signatures", "--trigger", "schedule"]))];
    for (name, e) in timers(cfg) {
        let cmd = match name {
            "quick" => args(&["scan", "--kind", "quick", "--trigger", "schedule"]),
            "full" => args(&["scan", "--kind", "full", "--trigger", "schedule"]),
            "systemcheck" => args(&["systemcheck", "--trigger", "schedule"]),
            _ => args(&["self-update", "--auto"]),
        };
        plan.push((name, last_occurrence(&e, now), cmd));
    }
    let mut due = Vec::new();
    for (name, at, cmd) in plan {
        let Some(at) = at else { continue };
        let last = state.last.get(name).and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|t| t.with_timezone(&Local));
        let missed = match last {
            Some(l) => l < at,
            None => !first,
        };
        if missed {
            due.push(Task { name, args: cmd });
        }
        if missed || last.is_none() {
            state.last.insert(name.to_string(), now.to_rfc3339_opts(chrono::SecondsFormat::Secs, false));
        }
    }
    let _ = fsutil::write_json(&paths::schedule_state_path(), &state, 0o644);
    due
}

/// Wendet die Einstellungen an (`set-config`). Den Zeitplan liest der Vigil-Dienst bei jeder
/// Runde selbst aus config.json; hier werden nur die Konfigurationen von ClamAV für den
/// Abstand der Virendaten neu geschrieben. Liefert Hinweise zu Teilfehlern.
pub fn apply(cfg: &Config) -> Result<Vec<Text>, Text> {
    let mut notes = Vec::new();
    if let Err(e) = crate::win::clamav::write_configs(cfg.signature_interval_hours) {
        notes.push(e);
    }
    Ok(notes)
}
