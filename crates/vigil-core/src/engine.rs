//! Prüfmotor: clamd (bevorzugt) oder clamscan als Ausweichweg.

use crate::clamd::{self, Verdict};
use crate::i18n::Text;
use crate::paths;
use crate::tr;
use crate::types::EngineKind;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Standardpfad von clamscan.
#[cfg(unix)]
pub const DEFAULT_CLAMSCAN: &str = "/usr/bin/clamscan";

/// Pfad von clamscan. Im Testbetrieb überschreibt `VIGIL_CLAMSCAN`.
pub fn clamscan_path() -> PathBuf {
    #[cfg(unix)]
    let default = || PathBuf::from(DEFAULT_CLAMSCAN);
    // Windows: clamscan.exe aus dem mitgelieferten ClamAV im Installationsordner
    #[cfg(windows)]
    let default = crate::win::clamav::clamscan_exe;
    paths::dev_override("VIGIL_CLAMSCAN").unwrap_or_else(default)
}

/// Gewählter Motor.
#[derive(Debug, Clone)]
pub enum Engine {
    Clamd(PathBuf),
    Clamscan(PathBuf),
}

impl Engine {
    /// clamd, wenn erreichbar, sonst clamscan.
    pub fn detect() -> Engine {
        let sock = clamd::clamd_socket();
        if clamd::ping(&sock) {
            Engine::Clamd(sock)
        } else {
            Engine::Clamscan(clamscan_path())
        }
    }

    /// Art für state.json.
    pub fn kind(&self) -> EngineKind {
        match self {
            Engine::Clamd(_) => EngineKind::Clamd,
            Engine::Clamscan(_) => EngineKind::Clamscan,
        }
    }

    /// Prüft eine bereits geöffnete Datei (ab Dateianfang).
    /// clamscan erhält die Datei über stdin, prüft also genau diesen Inhalt.
    pub fn scan_file(&self, file: &mut File) -> Result<Verdict, Text> {
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))
            .map_err(|e| tr!("Die Datei konnte nicht gelesen werden: {}", "Could not read the file: {}", e))?;
        match self {
            Engine::Clamd(sock) => clamd::scan_reader(sock, file),
            Engine::Clamscan(bin) => scan_with_clamscan_stdin(bin, file),
        }
    }
}

/// Einzelprüfung über `clamscan -` mit der Datei als stdin.
fn scan_with_clamscan_stdin(bin: &PathBuf, file: &File) -> Result<Verdict, Text> {
    let dup = file
        .try_clone()
        .map_err(|e| tr!("Die Datei konnte nicht weitergegeben werden: {}", "Could not pass on the file: {}", e))?;
    let mut command = Command::new(bin);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(crate::win::CREATE_NO_WINDOW);
        crate::win::clamav::clamscan_args(&mut command);
    }
    let mut child = command
        .args(["--no-summary", "--stdout", "-"])
        .stdin(Stdio::from(dup))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| tr!("Weder clamd noch clamscan ist verfügbar ({}: {}).", "Neither clamd nor clamscan is available ({}: {}).", bin.display(), e))?;
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut out);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    let status = child
        .wait()
        .map_err(|e| tr!("clamscan konnte nicht ausgeführt werden: {}", "Could not run clamscan: {}", e))?;
    for line in out.lines() {
        if let Some((_, res)) = line.rsplit_once(": ") {
            let res = res.trim();
            if res == "OK" || res == "Empty file" {
                return Ok(Verdict::Clean);
            }
            if let Some(sig) = res.strip_suffix(" FOUND") {
                return Ok(Verdict::Infected(sig.trim().to_string()));
            }
        }
    }
    let code = status.code().map(|c| Text::same(c.to_string())).unwrap_or_else(|| tr!("unbekannt", "unknown"));
    Err(tr!(
        "clamscan hat kein Ergebnis geliefert (Exit-Code {}): {} {}",
        "clamscan returned no result (exit code {}): {} {}",
        code,
        out.trim(),
        err.trim()
    ))
}
