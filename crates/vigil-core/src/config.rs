//! Konfiguration `/etc/vigil/config.json` mit Standardwerten.

use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::tr;
use crate::types::{Config, ScheduleEntry};

/// Liest die Konfiguration. Fehlt die Datei, gelten die Standardwerte.
pub fn load_config() -> Result<Config, Text> {
    Ok(fsutil::read_json(&paths::config_path())?.unwrap_or_default())
}

/// Schreibt die Konfiguration atomar (0644). Aufrufer hält `data.lock`.
pub fn save_config(cfg: &Config) -> Result<(), Text> {
    fsutil::ensure_dir(&paths::config_dir(), 0o755)?;
    fsutil::write_json(&paths::config_path(), cfg, 0o644)
}

/// Liest eine neue Konfiguration aus JSON (für `set-config`). Fehlt `allowlist`,
/// bleibt die bisherige erhalten, damit die App sie nicht versehentlich leert.
pub fn parse_new_config(json: &str, current: &Config) -> Result<Config, Text> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        tr!("Die Konfiguration ist kein gültiges JSON: {}", "The configuration is not valid JSON: {}", e)
    })?;
    if !value.is_object() {
        return Err(tr!("Die Konfiguration muss ein JSON-Objekt sein.", "The configuration must be a JSON object."));
    }
    let has_allowlist = value.get("allowlist").is_some();
    let mut cfg: Config = serde_json::from_value(value)
        .map_err(|e| tr!("Die Konfiguration ist ungültig: {}", "The configuration is invalid: {}", e))?;
    if !has_allowlist {
        cfg.allowlist = current.allowlist.clone();
    }
    validate(&cfg)?;
    Ok(cfg)
}

/// Prüft die Konfiguration auf gültige Werte.
pub fn validate(cfg: &Config) -> Result<(), Text> {
    for (name, e) in [
        (Text::new("die Schnellprüfung", "the quick scan"), &cfg.schedule.quick),
        (Text::new("die vollständige Prüfung", "the full scan"), &cfg.schedule.full),
        (Text::new("den Systemcheck", "the system check"), &cfg.schedule.systemcheck),
    ] {
        validate_entry(&name, e)?;
    }
    if parse_time(&cfg.updates.time).is_none() {
        return Err(tr!(
            "Ungültige Uhrzeit für die automatischen Updates: {} (erwartet HH:MM)",
            "Invalid time for automatic updates: {} (expected HH:MM)",
            cfg.updates.time
        ));
    }
    if !crate::types::SIGNATURE_INTERVALS.contains(&cfg.signature_interval_hours) {
        return Err(tr!(
            "Ungültiger Abstand für die Suche nach neuen Virendaten: {} Stunden (erlaubt: 1, 2, 4 oder 8)",
            "Invalid interval for checking for new virus data: {} hours (allowed: 1, 2, 4 or 8)",
            cfg.signature_interval_hours
        ));
    }
    for p in &cfg.scan.exclude_paths {
        if !p.starts_with('/') {
            return Err(tr!("Ausgeschlossene Pfade müssen absolut sein: {}", "Excluded paths must be absolute: {}", p));
        }
        if p.contains('\n') {
            return Err(tr!(
                "Ausgeschlossene Pfade dürfen keinen Zeilenumbruch enthalten.",
                "Excluded paths must not contain a line break."
            ));
        }
    }
    for a in &cfg.allowlist {
        if !fsutil::is_sha256(&a.sha256) {
            return Err(tr!(
                "Ungültiger sha256-Wert in der Freigabeliste: {}",
                "Invalid sha256 value in the allow list: {}",
                a.sha256
            ));
        }
    }
    Ok(())
}

fn validate_entry(name: &Text, e: &ScheduleEntry) -> Result<(), Text> {
    parse_time(&e.time).ok_or_else(|| {
        tr!("Ungültige Uhrzeit für {}: {} (erwartet HH:MM)", "Invalid time for {}: {} (expected HH:MM)", *name, e.time)
    })?;
    if e.enabled && e.days.is_empty() {
        return Err(tr!("Für {} ist kein Wochentag gewählt.", "No weekday is selected for {}.", *name));
    }
    Ok(())
}

/// Zerlegt `HH:MM` in Stunde und Minute.
pub fn parse_time(t: &str) -> Option<(u32, u32)> {
    let (h, m) = t.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let h: u32 = h.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    (h < 24 && m < 60).then_some((h, m))
}
