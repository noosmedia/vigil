//! Windows-Teil der App: Helfer über den Vigil-Dienst (Prüfbefehle) oder über die
//! Administratorabfrage (UAC, alle anderen Befehle) aufrufen, Zustand des Dienstes, Autostart,
//! Adressen öffnen und Systemsprache. Unter Linux erledigen das pkexec, polkit und xdg-open.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use vigil_core::paths;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_READ, KEY_WRITE, REG_SZ,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, ShellExecuteW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

const SW_HIDE: i32 = 0;
const SW_SHOWNORMAL: i32 = 1;
/// Abbruch der Administratorabfrage durch den Benutzer.
const ERROR_CANCELLED: u32 = 1223;
/// Autostart des angemeldeten Benutzers.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Vigil";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Ausgabe eines Helfer-Aufrufs: Exit-Code (`None`, wenn die Abfrage abgebrochen wurde), stdout, stderr.
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// `vigil-helper.exe` im Installationsordner (im Testbetrieb `VIGIL_HELPER_DIR`).
pub fn helper_exe() -> PathBuf {
    if paths::is_dev() {
        if let Some(d) = std::env::var_os("VIGIL_HELPER_DIR") {
            return PathBuf::from(d).join("vigil-helper.exe");
        }
    }
    paths::lib_dir().join("vigil-helper.exe")
}

/// Prüfbefehl über den Vigil-Dienst (ohne Abfrage).
pub fn call_service(lang: &str, args: &[String]) -> Result<Output, String> {
    let r = vigil_core::win::service::call(&helper_exe(), lang, args)?;
    Ok(Output { code: Some(r.code), stdout: r.stdout, stderr: r.stderr })
}

/// Setzt ein Argument für die Windows-Kommandozeile in Anführungszeichen (Regeln von
/// CommandLineToArgvW: Backslashes vor Anführungszeichen verdoppeln).
fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// Befehl mit Administratorrechten: Windows fragt per UAC nach, der Helfer schreibt sein
/// Ergebnis in `C:\ProgramData\Vigil\results\<kennung>.json`, das die App danach liest.
pub fn call_elevated(lang: &str, args: &[String]) -> Result<Output, String> {
    let id = format!("r-{}", crate::crypto::random_id(24));
    let result = paths::data_dir().join("results").join(format!("{id}.json"));
    let mut params = format!("--result {id} --lang {lang}");
    for a in args {
        params.push(' ');
        params.push_str(&quote_arg(a));
    }
    let file = helper_exe();
    let (verb, file_w, params_w) = (wide("runas"), wide(&file.to_string_lossy()), wide(&params));
    // SAFETY: Struktur mit gesetzter Größe, Zeichenketten leben bis zum Ende des Aufrufs
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file_w.as_ptr();
    info.lpParameters = params_w.as_ptr();
    info.nShow = SW_HIDE;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        // SAFETY: keine Vorbedingungen
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            return Ok(Output { code: None, stdout: String::new(), stderr: String::new() });
        }
        return Err(format!("Der Vigil-Helfer konnte nicht gestartet werden (Fehler {err})."));
    }
    let mut code = 0u32;
    if !info.hProcess.is_null() {
        // SAFETY: Prozess-Handle aus ShellExecuteExW
        unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
        }
    }
    // Ergebnisdatei lesen (kurz warten, falls sie gerade umbenannt wird)
    let start = Instant::now();
    loop {
        if let Some(v) = std::fs::read_to_string(&result).ok().and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()) {
            let text = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
            let c = v.get("code").and_then(|x| x.as_i64()).unwrap_or(code as i64) as i32;
            return Ok(Output { code: Some(c), stdout: text("stdout"), stderr: text("stderr") });
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Ok(Output { code: Some(code as i32), stdout: String::new(), stderr: String::new() });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Läuft der Vigil-Dienst?
pub fn service_running() -> bool {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return false };
    let Ok(s) = m.open_service(vigil_core::win::service::SERVICE_NAME, ServiceAccess::QUERY_STATUS) else { return false };
    s.query_status().map(|st| st.current_state == ServiceState::Running).unwrap_or(false)
}

/// Ist der Vigil-Dienst eingerichtet (installiert)?
pub fn service_installed() -> bool {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return false };
    m.open_service(vigil_core::win::service::SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok()
}

/// Öffnet eine Adresse (https, ms-settings:, windowsdefender:) mit dem zuständigen Programm.
pub fn open(target: &str) -> Result<(), String> {
    let (op, t) = (wide("open"), wide(target));
    // SAFETY: gültige Zeichenketten; Rückgabe > 32 heißt Erfolg
    let r = unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), t.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
    if (r as isize) > 32 {
        Ok(())
    } else {
        Err(format!("{target} konnte nicht geöffnet werden (Fehler {}).", r as isize))
    }
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: eigener Schlüssel
        unsafe { RegCloseKey(self.0) };
    }
}

fn run_key(write: bool) -> Option<Key> {
    let sub = wide(RUN_KEY);
    let mut k: HKEY = std::ptr::null_mut();
    // SAFETY: gültige Zeichenkette
    let r = unsafe {
        if write {
            RegCreateKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, std::ptr::null(), 0, KEY_WRITE, std::ptr::null(), &mut k, std::ptr::null_mut())
        } else {
            RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_READ, &mut k)
        }
    };
    (r == 0).then_some(Key(k))
}

/// Startet Vigil bei der Anmeldung (Eintrag unter HKCU\…\Run)?
pub fn autostart_enabled() -> bool {
    let Some(k) = run_key(false) else { return false };
    let name = wide(RUN_VALUE);
    let mut len = 0u32;
    // SAFETY: nur Größe abfragen
    unsafe { RegQueryValueExW(k.0, name.as_ptr(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), &mut len) == 0 }
}

/// Autostart ein- oder ausschalten (Wert `Vigil` = `"<vigil.exe>" --hidden`).
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let k = run_key(true).ok_or("Der Autostart-Eintrag ist nicht änderbar.")?;
    let name = wide(RUN_VALUE);
    if !enabled {
        // SAFETY: gültiger Schlüssel und Name
        let r = unsafe { RegDeleteValueW(k.0, name.as_ptr()) };
        return if r == 0 || r == 2 { Ok(()) } else { Err(format!("Autostart nicht abschaltbar (Fehler {r}).")) };
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let value = wide(&format!("\"{}\" --hidden", exe.display()));
    // SAFETY: Daten mit Länge in Byte einschließlich Nullzeichen
    let r = unsafe { RegSetValueExW(k.0, name.as_ptr(), 0, REG_SZ, value.as_ptr().cast(), (value.len() * 2) as u32) };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("Autostart nicht einschaltbar (Fehler {r})."))
    }
}

/// Beim ersten Start: Autostart einschalten (wie der systemweite Eintrag unter Linux). Danach
/// gilt die Wahl des Benutzers; die Markierung liegt in den Benutzerdaten von Vigil.
pub fn init_autostart() {
    let marker = crate::settings::config_dir().join("autostart-initialized");
    if marker.exists() {
        return;
    }
    if set_autostart(true).is_ok() {
        let _ = crate::settings::write_private(&marker, b"1\n");
    }
}

/// Sprache der Windows-Oberfläche (`de` oder `en`).
pub fn system_lang() -> &'static str {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    // SAFETY: Puffer mit Länge
    let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), buf.len() as i32) };
    let name = String::from_utf16_lossy(&buf[..(n.max(1) - 1) as usize]);
    if name.starts_with("de") {
        "de"
    } else {
        "en"
    }
}

