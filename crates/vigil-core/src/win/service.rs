//! Vigil-Dienst unter Windows: gemeinsame Festlegungen für Dienst (Helfer) und App.
//!
//! Der Dienst `Vigil` läuft als LocalSystem und übernimmt, was unter Linux `pkexec vigil-scan`
//! ohne Passwort erledigt: Die App schickt einen Befehl über die benannte Pipe
//! `\\.\pipe\vigil-helper` (eine JSON-Zeile `{"lang":"de","args":["scan","--kind","quick"]}`),
//! der Dienst prüft, dass der Befehl zu den Prüfbefehlen gehört, startet
//! `vigil-helper.exe --lang <lang> <args…>` und antwortet nach dessen Ende mit
//! `{"code":0,"stdout":"…","stderr":"…"}`. Alles andere läuft über die UAC-Abfrage.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::Path;

/// Name des Windows-Dienstes.
pub const SERVICE_NAME: &str = "Vigil";
/// Anzeigename in der Diensteverwaltung.
pub const SERVICE_DISPLAY: &str = "Vigil Virenschutz";
/// Benannte Pipe des Dienstes.
pub const PIPE_NAME: &str = r"\\.\pipe\vigil-helper";
/// Größte Anfrage (eine Zeile).
pub const MAX_REQUEST: usize = 256 * 1024;

/// Anfrage der App an den Dienst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeRequest {
    pub lang: String,
    pub args: Vec<String>,
}

/// Antwort des Dienstes: Exit-Code, stdout und stderr des Helfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeResponse {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetNamedPipeServerSessionId(pipe: *mut core::ffi::c_void, session: *mut u32) -> i32;
}

/// Schickt einen Prüfbefehl an den Vigil-Dienst und wartet auf das Ergebnis. Vorher wird
/// geprüft, dass die Pipe von einem Dienst bereitgestellt wird (Sitzung 0, dort laufen nur
/// Dienste, die ein Administrator eingerichtet hat). Sonst könnte ein Programm des Benutzers die
/// Pipe vorher anlegen und Anfragen abfangen. `_helper` bleibt für spätere Prüfungen.
pub fn call(_helper: &Path, lang: &str, args: &[String]) -> Result<PipeResponse, String> {
    // Alle Instanzen kurz belegt (ERROR_PIPE_BUSY): bis zu 5 s erneut versuchen
    let start = std::time::Instant::now();
    let mut pipe = loop {
        match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(p) => break p,
            Err(e) if e.raw_os_error() == Some(231) && start.elapsed() < std::time::Duration::from_secs(5) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err("Der Vigil-Dienst läuft nicht.".to_string()),
            Err(e) => return Err(format!("Der Vigil-Dienst ist nicht erreichbar: {e}")),
        }
    };
    let mut session = u32::MAX;
    // SAFETY: gültiges Pipe-Handle
    if unsafe { GetNamedPipeServerSessionId(pipe.as_raw_handle(), &mut session) } == 0 {
        return Err("Der Vigil-Dienst konnte nicht geprüft werden.".into());
    }
    if session != 0 && !crate::paths::is_dev() {
        return Err("Die Verbindung zum Vigil-Dienst ist nicht vertrauenswürdig.".into());
    }
    let req = PipeRequest { lang: lang.to_string(), args: args.to_vec() };
    let mut line = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    pipe.write_all(&line).map_err(|e| format!("Der Vigil-Dienst ist nicht erreichbar: {e}"))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            // Der Dienst hat die Verbindung nach der Antwort getrennt (109, 233): Ende
            Err(e) if matches!(e.raw_os_error(), Some(109) | Some(233)) && !out.is_empty() => break,
            Err(e) => return Err(format!("Die Antwort des Vigil-Dienstes fehlt: {e}")),
        }
    }
    serde_json::from_slice(&out).map_err(|e| format!("Die Antwort des Vigil-Dienstes ist nicht lesbar: {e}"))
}
