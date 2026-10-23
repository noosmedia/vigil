//! Mitgeliefertes ClamAV unter Windows: Programme im Installationsordner
//! (`C:\Program Files\Vigil\clamav`), Konfiguration und Virendaten unter
//! `C:\ProgramData\Vigil\clamav`. clamd läuft als Kindprozess des Vigil-Dienstes und lauscht nur
//! auf 127.0.0.1; freshclam ruft der Dienst im eingestellten Abstand auf (kein eigener Dienst).

use crate::cmd::{self, CmdOutput};
use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::tr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// TCP-Port von clamd (nur 127.0.0.1).
pub const CLAMD_PORT: u16 = 3310;

/// Wartezeit auf einen Lauf von freshclam (erste Virendaten sind rund 350 MB groß).
pub const FRESHCLAM_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Programme von ClamAV (`<Installationsordner>\clamav`).
pub fn program_dir() -> PathBuf {
    paths::lib_dir().join("clamav")
}

/// Konfiguration, Protokolle und Virendaten (`C:\ProgramData\Vigil\clamav`).
pub fn data_dir() -> PathBuf {
    paths::data_dir().join("clamav")
}

/// Ordner der Virendaten (`C:\ProgramData\Vigil\clamav\db`). Im Testbetrieb überschreibt
/// `VIGIL_CLAMAV_DB` (wie unter Linux).
pub fn database_dir() -> PathBuf {
    paths::dev_override("VIGIL_CLAMAV_DB").unwrap_or_else(|| data_dir().join("db"))
}

/// `C:\ProgramData\Vigil\clamav\clamd.conf`
pub fn clamd_conf() -> PathBuf {
    data_dir().join("clamd.conf")
}

/// `C:\ProgramData\Vigil\clamav\freshclam.conf`
pub fn freshclam_conf() -> PathBuf {
    data_dir().join("freshclam.conf")
}

/// Protokoll von freshclam (für den Zeitpunkt der letzten Suche).
pub fn freshclam_log() -> PathBuf {
    data_dir().join("freshclam.log")
}

pub fn clamd_exe() -> PathBuf {
    program_dir().join("clamd.exe")
}

pub fn clamscan_exe() -> PathBuf {
    program_dir().join("clamscan.exe")
}

pub fn freshclam_exe() -> PathBuf {
    program_dir().join("freshclam.exe")
}

/// Ordner mit den Zertifikaten, mit denen ClamAV die Virendaten prüft.
pub fn certs_dir() -> PathBuf {
    program_dir().join("certs")
}

/// Zusätzliche Parameter für clamscan: eigene Virendaten und Zertifikate.
pub fn clamscan_args(c: &mut Command) {
    c.arg(format!("--database={}", database_dir().display()));
    c.arg(format!("--cvdcertsdir={}", certs_dir().display()));
}

/// Liest einen Wert aus einer ClamAV-Konfiguration (`Schlüssel Wert`, der letzte gilt).
pub fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.splitn(2, char::is_whitespace);
            let k = it.next()?;
            let v = it.next()?.trim();
            let v = v.trim_matches('"');
            (k == key && !v.is_empty()).then(|| v.to_string())
        })
        .next_back()
}

/// Schreibt clamd.conf und freshclam.conf neu (Vigil verwaltet beide vollständig) und legt die
/// Ordner an. Der Dienst ruft das bei jedem Start auf, set-config beim Ändern des Abstands.
pub fn write_configs(interval_hours: u32) -> Result<(), Text> {
    fsutil::ensure_dir(&data_dir(), 0o755)?;
    fsutil::ensure_dir(&database_dir(), 0o755)?;
    let db = database_dir();
    let data = data_dir();
    let clamd = format!(
        "# Von Vigil geschrieben. Bitte nicht von Hand ändern.\r\n\
         TCPSocket {CLAMD_PORT}\r\n\
         TCPAddr 127.0.0.1\r\n\
         DatabaseDirectory \"{db}\"\r\n\
         CVDCertsDirectory \"{certs}\"\r\n\
         LogFile \"{log}\"\r\n\
         LogFileMaxSize 2M\r\n\
         LogTime yes\r\n\
         LogRotate yes\r\n\
         StreamMaxLength 26M\r\n\
         MaxThreads 12\r\n\
         SelfCheck 3600\r\n\
         Foreground yes\r\n",
        db = db.display(),
        certs = certs_dir().display(),
        log = data.join("clamd.log").display(),
    );
    let checks = 24 / interval_hours.clamp(1, 24);
    let freshclam = format!(
        "# Von Vigil geschrieben. Bitte nicht von Hand ändern.\r\n\
         DatabaseDirectory \"{db}\"\r\n\
         CVDCertsDirectory \"{certs}\"\r\n\
         UpdateLogFile \"{log}\"\r\n\
         LogFileMaxSize 2M\r\n\
         LogTime yes\r\n\
         LogRotate yes\r\n\
         DatabaseMirror database.clamav.net\r\n\
         Checks {checks}\r\n\
         NotifyClamd \"{clamd_conf}\"\r\n",
        db = db.display(),
        certs = certs_dir().display(),
        log = freshclam_log().display(),
        clamd_conf = clamd_conf().display(),
    );
    fsutil::write_atomic(&clamd_conf(), clamd.as_bytes(), 0o644)?;
    fsutil::write_atomic(&freshclam_conf(), freshclam.as_bytes(), 0o644)?;
    Ok(())
}

/// Liegen schon Virendaten vor (main und daily)?
pub fn has_database() -> bool {
    let db = database_dir();
    let any = |names: &[&str]| names.iter().any(|n| db.join(n).is_file());
    any(&["main.cvd", "main.cld"]) && any(&["daily.cvd", "daily.cld"])
}

/// Führt freshclam einmal aus (lädt neue Virendaten, meldet clamd das Neuladen).
pub fn run_freshclam() -> Result<CmdOutput, Text> {
    let conf = format!("--config-file={}", freshclam_conf().display());
    if !freshclam_exe().is_file() {
        return Err(tr!(
            "freshclam fehlt ({}). Bitte Vigil neu installieren.",
            "freshclam is missing ({}). Please reinstall Vigil.",
            freshclam_exe().display()
        ));
    }
    cmd::run(&freshclam_exe(), &[&conf, "--stdout", "--no-warnings"], FRESHCLAM_TIMEOUT)
}

/// Zeitpunkt der letzten Suche von freshclam aus dessen Protokoll (RFC 3339), sonst `None`.
/// freshclam schreibt bei jedem Lauf Zeilen wie `Fri Oct 23 12:20:43 2026 -> daily.cvd database
/// is up-to-date …`; maßgeblich ist der Zeitstempel der letzten Zeile.
pub fn last_check() -> Option<String> {
    let text = std::fs::read_to_string(freshclam_log()).ok()?;
    let t = text.lines().rev().find_map(|l| {
        let stamp = l.split(" -> ").next()?.trim();
        chrono::NaiveDateTime::parse_from_str(stamp, "%a %b %e %H:%M:%S %Y").ok()
    })?;
    let local = t.and_local_timezone(chrono::Local).single()?;
    Some(local.to_rfc3339_opts(chrono::SecondsFormat::Secs, false))
}
