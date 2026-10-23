//! Stand der Virensignaturen und Version von ClamAV.

use crate::clamd;
use crate::cmd;
use crate::engine;
#[cfg(unix)]
use crate::paths;
use crate::types::SignatureInfo;
use chrono::{DateTime, FixedOffset, Local};
#[cfg(unix)]
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

/// Ordner der Signaturen: `DatabaseDirectory` aus /etc/clamav/freshclam.conf, sonst
/// /var/lib/clamav. Im Testbetrieb überschreibt `VIGIL_CLAMAV_DB`. Unter Windows der Ordner
/// des mitgelieferten ClamAV (`C:\ProgramData\Vigil\clamav\db`).
#[cfg(windows)]
pub fn database_dir() -> PathBuf {
    crate::win::clamav::database_dir()
}

/// Ordner der Signaturen (Linux).
#[cfg(unix)]
pub fn database_dir() -> PathBuf {
    if let Some(p) = paths::dev_override("VIGIL_CLAMAV_DB") {
        return p;
    }
    fs::read_to_string("/etc/clamav/freshclam.conf")
        .ok()
        .and_then(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| l.strip_prefix("DatabaseDirectory"))
                .map(|v| v.trim().to_string())
                .rfind(|v| !v.is_empty())
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/clamav"))
}

/// Liest Version und Erstellungszeit aus dem Kopf einer .cvd/.cld-Datei,
/// z. B. `ClamAV-VDB:22 Oct 2026 06-24 +0000:28161:355787:90:…`.
pub fn parse_cvd_header(header: &str) -> Option<(u64, DateTime<FixedOffset>)> {
    let rest = header.strip_prefix("ClamAV-VDB:")?;
    let mut parts = rest.split(':');
    let date = parts.next()?.trim();
    let version: u64 = parts.next()?.trim().parse().ok()?;
    let dt = DateTime::parse_from_str(date, "%d %b %Y %H-%M %z").ok()?;
    Some((version, dt))
}

/// Liest die Kopfzeile einer Datenbankdatei.
fn read_header(p: &PathBuf) -> Option<(u64, DateTime<FixedOffset>)> {
    let mut buf = [0u8; 512];
    let mut f = File::open(p).ok()?;
    let n = f.read(&mut buf).ok()?;
    parse_cvd_header(&String::from_utf8_lossy(&buf[..n]))
}

/// Stand der täglichen Signaturen (daily.cld oder daily.cvd, die neuere zählt).
/// `None`, wenn keine Signaturen gefunden werden.
pub fn signature_info() -> Option<SignatureInfo> {
    let dir = database_dir();
    let (version, date) = ["daily.cld", "daily.cvd"]
        .iter()
        .filter_map(|n| read_header(&dir.join(n)))
        .max_by_key(|(v, _)| *v)?;
    let age = Local::now().signed_duration_since(date.with_timezone(&Local));
    let age_hours = (age.num_minutes().max(0) as f64 / 60.0 * 10.0).round() / 10.0;
    Some(SignatureInfo {
        version,
        date: date.with_timezone(&Local).to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        age_hours,
        engine: engine_version(),
    })
}

/// Version von ClamAV (z. B. `1.5.4`): über clamd, sonst `clamscan --version`.
pub fn engine_version() -> Option<String> {
    let sock = clamd::clamd_socket();
    let text = clamd::version(&sock).ok().or_else(|| {
        cmd::run(&engine::clamscan_path(), &["--version"], Duration::from_secs(30))
            .ok()
            .filter(|o| o.success())
            .map(|o| o.stdout)
    })?;
    // Format: "ClamAV 1.5.4/28161/Thu Oct 22 06:24:00 2026"
    let v = text.trim().strip_prefix("ClamAV ")?.split('/').next()?.trim().to_string();
    (!v.is_empty()).then_some(v)
}
