//! Externe Programme mit Zeitgrenze ausführen.

use crate::i18n::Text;
use crate::tr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Ergebnis eines Programmaufrufs.
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CmdOutput {
    /// Erfolgreich beendet (Exit 0)?
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }

    /// Fehlertext für Meldungen: stderr, sonst stdout, sonst Exit-Code.
    pub fn error_text(&self) -> Text {
        if self.timed_out {
            return tr!("Zeitüberschreitung", "timed out");
        }
        let e = self.stderr.trim();
        if !e.is_empty() {
            return Text::same(e);
        }
        let o = self.stdout.trim();
        if !o.is_empty() {
            return Text::same(o);
        }
        match self.code {
            Some(c) => tr!("Exit-Code {}", "exit code {}", c),
            None => tr!("durch Signal beendet", "terminated by a signal"),
        }
    }
}

/// Sucht ein Programm in den Systemordnern (unabhängig von PATH, der unter pkexec knapp ist).
#[cfg(unix)]
pub fn find_program(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// Sucht ein Programm im Systemordner von Windows (`System32`, dazu der Ordner von
/// PowerShell), nie über PATH. `name` ohne `.exe`.
#[cfg(windows)]
pub fn find_program(name: &str) -> Option<PathBuf> {
    let sys = crate::win::system_dir();
    let file = format!("{name}.exe");
    [sys.clone(), sys.join(r"WindowsPowerShell\v1.0"), sys.join("wbem")]
        .iter()
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// Führt ein Programm aus, sammelt stdout/stderr und bricht nach `timeout` ab.
/// Ausgaben laufen mit `LC_ALL=C` und `LANGUAGE=C`, damit sie unabhängig von der Sprache auswertbar sind.
pub fn run(program: &Path, args: &[&str], timeout: Duration) -> Result<CmdOutput, Text> {
    run_env(program, args, &[], timeout)
}

/// Wie [`run`], mit zusätzlichen Umgebungsvariablen.
pub fn run_env(program: &Path, args: &[&str], env: &[(&str, &str)], timeout: Duration) -> Result<CmdOutput, Text> {
    let mut command = Command::new(program);
    #[cfg(unix)]
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        // Python-Programme wie ufw werten LANGUAGE vor LC_ALL aus
        .env("LANGUAGE", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Kein Konsolenfenster, auch wenn der Aufruf aus der App oder dem Dienst kommt
        command.creation_flags(crate::win::CREATE_NO_WINDOW);
    }
    let mut child = command
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| tr!("{} konnte nicht gestartet werden: {}", "Could not start {}: {}", program.display(), e))?;

    // Ausgaben in eigenen Threads lesen, damit volle Pipes nicht blockieren
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let t_out = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(_) => break None,
        }
        if start.elapsed() > timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait().ok();
        }
        thread::sleep(Duration::from_millis(100));
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    Ok(CmdOutput { code: status.and_then(|s| s.code()), stdout, stderr, timed_out })
}

/// Wie [`run`], sucht das Programm aber in den Systemordnern.
pub fn run_named(name: &str, args: &[&str], timeout: Duration) -> Result<CmdOutput, Text> {
    let p = find_program(name)
        .ok_or_else(|| tr!("Das Programm {} ist nicht installiert.", "The program {} is not installed.", name))?;
    run(&p, args, timeout)
}
