//! Zeitplan: OnCalendar als systemd-Drop-in schreiben, Timer ein- oder ausschalten.

use crate::cmd;
use crate::config::parse_time;
use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::tr;
use crate::types::{Config, Day, ScheduleEntry};
use std::time::Duration;

/// Timer für die automatischen Updates von Vigil selbst.
pub const SELFUPDATE_TIMER: &str = "vigil-selfupdate.timer";

/// Timer für die zusätzlichen Signaturen (Sanesecurity), siehe `extrasigs`.
pub const EXTRA_TIMER: &str = "vigil-extrasigs.timer";

/// Alle Timer mit ihrem Zeitplan-Eintrag. Die automatischen Updates laufen täglich zur
/// eingestellten Uhrzeit und sind nur eingeschaltet, wenn `updates.auto` gilt.
pub fn timers(cfg: &Config) -> Vec<(&'static str, ScheduleEntry)> {
    let s = &cfg.schedule;
    vec![
        ("vigil-scan-quick.timer", s.quick.clone()),
        ("vigil-scan-full.timer", s.full.clone()),
        ("vigil-systemcheck.timer", s.systemcheck.clone()),
        (
            SELFUPDATE_TIMER,
            ScheduleEntry { enabled: cfg.updates.auto, time: cfg.updates.time.clone(), days: Day::ALL.to_vec() },
        ),
    ]
}

/// OnCalendar-Ausdruck, z. B. `Mon,Wed *-*-* 12:30:00` oder `*-*-* 12:30:00` für alle Tage.
pub fn on_calendar(e: &ScheduleEntry) -> Result<String, Text> {
    let (h, m) = parse_time(&e.time).ok_or_else(|| tr!("Ungültige Uhrzeit: {}", "Invalid time: {}", e.time))?;
    let days: Vec<&str> = Day::ALL.iter().filter(|d| e.days.contains(d)).map(|d| d.systemd_name()).collect();
    if days.len() == 7 || days.is_empty() {
        Ok(format!("*-*-* {h:02}:{m:02}:00"))
    } else {
        Ok(format!("{} *-*-* {h:02}:{m:02}:00", days.join(",")))
    }
}

/// Inhalt des Drop-ins `/etc/systemd/system/<timer>.d/vigil.conf`.
pub fn drop_in(e: &ScheduleEntry) -> Result<String, Text> {
    Ok(format!(
        "# Von Vigil geschrieben (set-config). Bitte nicht von Hand ändern.\n[Timer]\nOnCalendar=\nOnCalendar={}\n",
        on_calendar(e)?
    ))
}

/// OnCalendar-Ausdruck für den Abstand der zusätzlichen Signaturen, z. B. `*-*-* *:00:00`
/// (stündlich) oder `*-*-* 00/4:00:00` (alle 4 Stunden). Die zufällige Verzögerung steht in
/// der Unit (`RandomizedDelaySec`, `FixedRandomDelay`). Nie häufiger als stündlich, denn
/// Sanesecurity bittet, nicht mehrmals je Stunde zu laden.
pub fn interval_calendar(hours: u32) -> Result<String, Text> {
    if !crate::types::SIGNATURE_INTERVALS.contains(&hours) {
        return Err(tr!("Ungültiger Abstand: {} Stunden", "Invalid interval: {} hours", hours));
    }
    Ok(if hours == 1 { "*-*-* *:00:00".to_string() } else { format!("*-*-* 00/{hours}:00:00") })
}

/// Inhalt des Drop-ins für den Timer der zusätzlichen Signaturen.
pub fn interval_drop_in(hours: u32) -> Result<String, Text> {
    Ok(format!(
        "# Von Vigil geschrieben (set-config). Bitte nicht von Hand ändern.\n[Timer]\nOnCalendar=\nOnCalendar={}\n",
        interval_calendar(hours)?
    ))
}

/// Alle Timer mit Inhalt ihres Drop-ins und ob sie eingeschaltet sein sollen.
fn units(cfg: &Config) -> Result<Vec<(&'static str, String, bool)>, Text> {
    let mut v = Vec::new();
    for (timer, e) in timers(cfg) {
        v.push((timer, drop_in(&e)?, e.enabled));
    }
    v.push((EXTRA_TIMER, interval_drop_in(cfg.signature_interval_hours)?, cfg.extra_signatures));
    Ok(v)
}

/// Schreibt alle Drop-ins, lädt systemd neu und schaltet die Timer passend. Setzt außerdem
/// `Checks` in freshclam.conf passend zu `signatureIntervalHours`.
/// Im Testbetrieb werden nur die Dateien geschrieben (Ordner `<VIGIL_CONFIG_DIR>/systemd`,
/// freshclam.conf nur über `VIGIL_FRESHCLAM_CONF`), systemctl wird nicht aufgerufen.
/// Liefert Hinweise zu Teilfehlern.
pub fn apply(cfg: &Config) -> Result<Vec<Text>, Text> {
    let base = paths::systemd_unit_dir();
    let units = units(cfg)?;
    for (timer, content, _) in &units {
        let dir = base.join(format!("{timer}.d"));
        fsutil::ensure_dir(&dir, 0o755)?;
        fsutil::write_atomic(&dir.join("vigil.conf"), content.as_bytes(), 0o644)?;
    }
    let mut notes = Vec::new();
    match crate::extrasigs::apply_freshclam_interval(cfg.signature_interval_hours) {
        Ok(Some(n)) => notes.push(n),
        Ok(None) => {}
        Err(e) => notes.push(e),
    }
    if paths::is_dev() {
        notes.push(tr!("Testbetrieb: systemctl wurde nicht aufgerufen.", "Test mode: systemctl was not called."));
        return Ok(notes);
    }

    let t = Duration::from_secs(60);
    let reload = cmd::run_named("systemctl", &["--no-ask-password", "daemon-reload"], t)?;
    if !reload.success() {
        return Err(tr!(
            "systemctl daemon-reload ist fehlgeschlagen: {}",
            "systemctl daemon-reload failed: {}",
            reload.error_text()
        ));
    }
    for (timer, _, enabled) in &units {
        let steps: Vec<Vec<&str>> = if *enabled {
            vec![vec!["--no-ask-password", "enable", timer], vec!["--no-ask-password", "restart", timer]]
        } else {
            vec![vec!["--no-ask-password", "disable", "--now", timer]]
        };
        for args in steps {
            let out = cmd::run_named("systemctl", &args, t)?;
            if !out.success() {
                let a = args[1..].join(" ");
                notes.push(tr!("systemctl {} ist fehlgeschlagen: {}", "systemctl {} failed: {}", a, out.error_text()));
            }
        }
    }
    Ok(notes)
}
