//! Vigil-Dienst unter Windows (`vigil-helper.exe service`, gestartet von der Diensteverwaltung
//! als LocalSystem). Übernimmt, was unter Linux systemd und polkit erledigen:
//!
//! - clamd aus dem mitgelieferten ClamAV starten und bei Ausfall neu starten; fehlen noch
//!   Virendaten, lädt freshclam sie zuerst.
//! - Zeitplan: alle 30 s fällige Aufgaben ermitteln (`schedule::take_due`) und als Kindprozess
//!   `vigil-helper.exe …` mit niedriger Priorität starten; Virendaten lädt freshclam direkt.
//! - Benannte Pipe `\\.\pipe\vigil-helper`: Prüfbefehle der App (wie `vigil-scan` unter Linux)
//!   ohne Administratorabfrage ausführen. Alle anderen Befehle lehnt der Dienst ab.
//!
//! Alle Kindprozesse laufen in einem Job-Objekt und enden mit dem Dienst. Dazu kommen
//! `service-install`, `service-remove` und `service-stop` für den Installer.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use vigil_core::i18n::Text;
use vigil_core::win::service::{PipeRequest, PipeResponse, MAX_REQUEST, PIPE_NAME, SERVICE_DISPLAY, SERVICE_NAME};
use vigil_core::win::{self as w, clamav};
use vigil_core::{config, extrasigs, fsutil, lock, paths, schedule, tr};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES,
};

/// Zugriff auf die Pipe: SYSTEM und Administratoren voll, angemeldete Benutzer lesen und schreiben.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";
/// Prozesspriorität für geplante Prüfungen (wie `Nice=15` unter Linux).
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
/// Fehlercode, wenn sich der Client schon vor ConnectNamedPipe verbunden hat.
const ERROR_PIPE_CONNECTED: u32 = 535;

// ---------------------------------------------------------------------------
// Protokoll
// ---------------------------------------------------------------------------

/// `C:\ProgramData\Vigil\service.log`, höchstens 1 MB (dann wird `service.log.1` daraus).
fn log(msg: &str) {
    let p = paths::data_dir().join("service.log");
    if std::fs::metadata(&p).map(|m| m.len() > 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::rename(&p, paths::data_dir().join("service.log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{} {}", vigil_core::now_rfc3339(), msg);
    }
}

// ---------------------------------------------------------------------------
// Job-Objekt: Kindprozesse enden mit dem Dienst
// ---------------------------------------------------------------------------

struct Job(HANDLE);

// SAFETY: Ein Job-Handle darf zwischen Threads geteilt werden (Kernel-Objekt).
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    fn new() -> Option<Job> {
        // SAFETY: unbenanntes Job-Objekt
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return None;
        }
        // SAFETY: Struktur vollständig initialisiert
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // Der Installer eines Updates darf aus dem Job ausbrechen (er hält den Dienst selbst an)
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        unsafe {
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        Some(Job(h))
    }

    fn assign(&self, child: &Child) {
        // SAFETY: gültige Handles
        unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle()) };
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: eigenes Handle; schließt alle Prozesse im Job
        unsafe { CloseHandle(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Kindprozesse
// ---------------------------------------------------------------------------

fn helper_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| paths::lib_dir().join("vigil-helper.exe"))
}

/// Startet `vigil-helper.exe --lang <lang> <args…>` und wartet auf das Ende.
fn run_helper(job: &Job, lang: &str, args: &[String], low_priority: bool) -> PipeResponse {
    let mut flags = w::CREATE_NO_WINDOW;
    if low_priority {
        flags |= BELOW_NORMAL_PRIORITY_CLASS;
    }
    let spawned = Command::new(helper_exe())
        .arg("--lang")
        .arg(lang)
        .args(args)
        .creation_flags(flags)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => return PipeResponse { code: 4, stdout: String::new(), stderr: format!("Der Vigil-Helfer konnte nicht gestartet werden: {e}") },
    };
    job.assign(&child);
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let t_out = thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let t_err = thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(4);
    PipeResponse { code, stdout: t_out.join().unwrap_or_default(), stderr: t_err.join().unwrap_or_default() }
}

// ---------------------------------------------------------------------------
// Vorbereitung: Ordner, Rechte, Konfiguration von ClamAV
// ---------------------------------------------------------------------------

/// Legt alle Ordner mit festen Zugriffsrechten an (auch vorhandene werden neu gesetzt), schreibt
/// die Konfiguration von ClamAV und räumt alte Ergebnisdateien auf.
pub fn prepare() -> Result<(), Text> {
    let data = paths::data_dir();
    std::fs::create_dir_all(&data)
        .map_err(|e| tr!("Der Ordner {} konnte nicht angelegt werden: {}", "Could not create the folder {}: {}", data.display(), e))?;
    w::set_dir_acl(&data, true)?;
    let dirs: [(PathBuf, bool); 8] = [
        (paths::reports_dir(), true),
        (paths::config_dir(), true),
        (paths::results_dir(), true),
        (clamav::data_dir(), true),
        (clamav::database_dir(), true),
        (paths::quarantine_dir(), false),
        (paths::updates_dir(), false),
        (paths::pro_data_dir(), false),
    ];
    for (dir, users_read) in dirs {
        std::fs::create_dir_all(&dir)
            .map_err(|e| tr!("Der Ordner {} konnte nicht angelegt werden: {}", "Could not create the folder {}: {}", dir.display(), e))?;
        w::set_dir_acl(&dir, users_read)?;
    }
    let cfg = config::load_config().unwrap_or_default();
    clamav::write_configs(cfg.signature_interval_hours)?;
    let _ = extrasigs::refresh_state(&cfg);
    // Ergebnisdateien älter als eine Stunde entfernen
    if let Ok(rd) = std::fs::read_dir(paths::results_dir()) {
        for e in rd.flatten() {
            let old = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok());
            if old.map(|a| a > Duration::from_secs(3600)).unwrap_or(false) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Installation (für den Installer, mit Administratorrechten)
// ---------------------------------------------------------------------------

fn svc_err(what: &str, e: windows_service::Error) -> Text {
    tr!("Der Vigil-Dienst: {} ist fehlgeschlagen: {}", "The Vigil service: {} failed: {}", what, e)
}

/// `service-install`: Ordner vorbereiten, Dienst anlegen oder aktualisieren und starten.
pub fn install() -> Result<Text, Text> {
    prepare()?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| svc_err("Diensteverwaltung öffnen", e))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: helper_exe(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::CHANGE_CONFIG;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(s) => {
            s.change_config(&info).map_err(|e| svc_err("Einstellungen ändern", e))?;
            s
        }
        Err(_) => manager.create_service(&info, access).map_err(|e| svc_err("anlegen", e))?,
    };
    let _ = service.set_description("Prüft den Rechner mit ClamAV nach Zeitplan und hält die Virendaten aktuell.");
    // Bei einem Absturz nach 10 s, 30 s und 60 s neu starten
    let actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(10) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
        ]),
    };
    let _ = service.update_failure_actions(actions);
    let state = service.query_status().map(|s| s.current_state).unwrap_or(ServiceState::Stopped);
    if state != ServiceState::Running && state != ServiceState::StartPending {
        service.start::<&str>(&[]).map_err(|e| svc_err("starten", e))?;
    }
    Ok(tr!("Der Vigil-Dienst ist eingerichtet und läuft.", "The Vigil service is set up and running."))
}

/// Hält den Dienst an und wartet bis zu 60 s darauf. `Ok(false)`, wenn es ihn nicht gibt.
fn stop_and_wait(manager: &ServiceManager) -> Result<bool, Text> {
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if service.query_status().map(|s| s.current_state).unwrap_or(ServiceState::Stopped) != ServiceState::Stopped {
        let _ = service.stop();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(60) {
            if service.query_status().map(|s| s.current_state).unwrap_or(ServiceState::Stopped) == ServiceState::Stopped {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(true)
}

/// Beendet übrig gebliebene Programme von ClamAV aus dem Installationsordner.
fn kill_clamav_leftovers() {
    let dir = clamav::program_dir();
    for (pid, name) in w::processes() {
        let n = name.to_ascii_lowercase();
        if n != "clamd.exe" && n != "freshclam.exe" && n != "clamscan.exe" {
            continue;
        }
        if w::process_image(pid).map(|p| w::starts_with_ci(&p, &dir)).unwrap_or(false) {
            let _ = Command::new(w::system_dir().join("taskkill.exe"))
                .args(["/F", "/PID", &pid.to_string()])
                .creation_flags(w::CREATE_NO_WINDOW)
                .output();
        }
    }
}

/// `service-stop`: Dienst anhalten (vor einem Update).
pub fn stop() -> Result<Text, Text> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| svc_err("Diensteverwaltung öffnen", e))?;
    let existed = stop_and_wait(&manager)?;
    kill_clamav_leftovers();
    Ok(if existed {
        tr!("Der Vigil-Dienst wurde angehalten.", "The Vigil service has been stopped.")
    } else {
        tr!("Der Vigil-Dienst ist nicht eingerichtet.", "The Vigil service is not set up.")
    })
}

/// `service-remove`: Dienst anhalten und entfernen (beim Deinstallieren). Daten bleiben.
pub fn remove() -> Result<Text, Text> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| svc_err("Diensteverwaltung öffnen", e))?;
    if !stop_and_wait(&manager)? {
        return Ok(tr!("Der Vigil-Dienst ist nicht eingerichtet.", "The Vigil service is not set up."));
    }
    kill_clamav_leftovers();
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE).map_err(|e| svc_err("öffnen", e))?;
    service.delete().map_err(|e| svc_err("entfernen", e))?;
    Ok(tr!("Der Vigil-Dienst wurde entfernt.", "The Vigil service has been removed."))
}

// ---------------------------------------------------------------------------
// Dienstbetrieb
// ---------------------------------------------------------------------------

define_windows_service!(ffi_service_main, service_main);

/// `service`: übergibt an die Diensteverwaltung (nur wenn Windows den Dienst startet).
pub fn run_dispatcher() -> Result<Text, Text> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| {
        tr!(
            "Der Befehl service ist nur für die Diensteverwaltung von Windows gedacht: {}",
            "The service command is only meant for the Windows service manager: {}",
            e
        )
    })?;
    Ok(tr!("Der Vigil-Dienst wurde beendet.", "The Vigil service has ended."))
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log(&format!("Dienst beendet mit Fehler: {e}"));
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, wait: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn run_service() -> windows_service::Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_h = Arc::clone(&stop);
    let handler = move |event| -> ServiceControlHandlerResult {
        match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_h.store(true, Ordering::Relaxed);
                // Blockierendes Warten auf eine Pipe-Verbindung lösen
                let _ = std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
    status_handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::ZERO,
    ))?;
    log(&format!("Vigil-Dienst {} gestartet.", vigil_core::VERSION));
    if let Err(e) = prepare() {
        log(&format!("Vorbereitung unvollständig: {}", e.de_text()));
    }

    let job = Arc::new(Job::new().expect("Job-Objekt"));
    let clamd: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let mut threads = Vec::new();
    {
        let (stop, job, clamd) = (Arc::clone(&stop), Arc::clone(&job), Arc::clone(&clamd));
        threads.push(thread::spawn(move || supervise_clamd(&stop, &job, &clamd)));
    }
    {
        let (stop, job) = (Arc::clone(&stop), Arc::clone(&job));
        threads.push(thread::spawn(move || scheduler(&stop, &job)));
    }
    {
        let (stop, job) = (Arc::clone(&stop), Arc::clone(&job));
        thread::spawn(move || pipe_server(&stop, &job));
    }

    while !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(500));
    }
    status_handle.set_service_status(status(ServiceState::StopPending, ServiceControlAccept::empty(), Duration::from_secs(20)))?;
    log("Vigil-Dienst wird beendet.");
    // Laufende Prüfung sauber abbrechen lassen (Bericht wird noch geschrieben)
    if lock::is_job_running() {
        let _ = fsutil::write_atomic(&paths::cancel_path(), b"", 0o644);
        let start = Instant::now();
        while lock::is_job_running() && start.elapsed() < Duration::from_secs(15) {
            thread::sleep(Duration::from_millis(250));
        }
    }
    if let Some(mut c) = clamd.lock().ok().and_then(|mut g| g.take()) {
        let _ = c.kill();
        let _ = c.wait();
    }
    for t in threads {
        let _ = t.join();
    }
    drop(job);
    status_handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::ZERO))?;
    Ok(())
}

/// Wartet bis zu `d`, bricht früher ab, wenn der Dienst endet. `true` bei Ende.
fn sleep_or_stop(stop: &AtomicBool, d: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < d {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        thread::sleep(Duration::from_millis(250));
    }
    stop.load(Ordering::Relaxed)
}

/// Hält clamd am Laufen. Ohne Virendaten lädt freshclam sie zuerst (alle 10 Minuten ein Versuch).
fn supervise_clamd(stop: &AtomicBool, job: &Job, slot: &Mutex<Option<Child>>) {
    let backoff = [10u64, 30, 60, 120, 300];
    let mut failures = 0usize;
    while !stop.load(Ordering::Relaxed) {
        if !clamav::has_database() {
            log("Keine Virendaten vorhanden, freshclam lädt sie.");
            match clamav::run_freshclam() {
                Ok(o) => log(&format!("freshclam beendet (Exit {:?}).", o.code)),
                Err(e) => log(&format!("freshclam: {}", e.de_text())),
            }
            if !clamav::has_database() {
                if sleep_or_stop(stop, Duration::from_secs(600)) {
                    return;
                }
                continue;
            }
        }
        let conf = format!("--config-file={}", clamav::clamd_conf().display());
        let spawned = Command::new(clamav::clamd_exe())
            .arg(conf)
            .creation_flags(w::CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let started = Instant::now();
        match spawned {
            Ok(child) => {
                job.assign(&child);
                log(&format!("clamd gestartet (PID {}).", child.id()));
                if let Ok(mut g) = slot.lock() {
                    *g = Some(child);
                }
                // Warten, bis clamd endet oder der Dienst beendet wird
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let exited = slot.lock().ok().and_then(|mut g| g.as_mut().and_then(|c| c.try_wait().ok().flatten()));
                    if let Some(st) = exited {
                        log(&format!("clamd ist beendet ({st})."));
                        break;
                    }
                    thread::sleep(Duration::from_millis(500));
                }
            }
            Err(e) => log(&format!("clamd konnte nicht gestartet werden: {e}")),
        }
        if started.elapsed() > Duration::from_secs(600) {
            failures = 0;
        }
        let wait = backoff[failures.min(backoff.len() - 1)];
        failures += 1;
        if sleep_or_stop(stop, Duration::from_secs(wait)) {
            return;
        }
    }
}

/// Zeitplan: alle 30 s fällige Aufgaben starten, jede in einem eigenen Thread (wie getrennte
/// Timer unter Linux; eine zweite Prüfung zur selben Zeit endet mit „läuft bereits“).
fn scheduler(stop: &AtomicBool, job: &Arc<Job>) {
    loop {
        let cfg = config::load_config().unwrap_or_default();
        for task in schedule::take_due(&cfg) {
            log(&format!("Zeitplan: {} ({})", task.name, task.args.join(" ")));
            let job = Arc::clone(job);
            thread::spawn(move || {
                if task.name == schedule::SIGNATURES_TIMER {
                    // Virendaten direkt laden, unabhängig von laufenden Prüfungen
                    match clamav::run_freshclam() {
                        Ok(o) => log(&format!("freshclam beendet (Exit {:?}).", o.code)),
                        Err(e) => log(&format!("freshclam: {}", e.de_text())),
                    }
                    let _ = extrasigs::refresh_state(&config::load_config().unwrap_or_default());
                    return;
                }
                let r = run_helper(&job, "de", &task.args, true);
                log(&format!("Zeitplan: {} beendet (Exit {}). {}", task.name, r.code, r.stderr.trim()));
            });
        }
        if sleep_or_stop(stop, Duration::from_secs(30)) {
            return;
        }
    }
}

/// Sicherheitsbeschreibung der Pipe (wird nie freigegeben, lebt so lange wie der Dienst).
fn pipe_security() -> Option<SECURITY_ATTRIBUTES> {
    let sddl = w::wide(std::ffi::OsStr::new(PIPE_SDDL));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: gültige Zeichenkette
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
        return None;
    }
    Some(SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 })
}

/// Nimmt Verbindungen der App an; jede Anfrage läuft in einem eigenen Thread.
fn pipe_server(stop: &AtomicBool, job: &Arc<Job>) {
    let Some(sa) = pipe_security() else {
        log("Pipe: Sicherheitsbeschreibung konnte nicht angelegt werden.");
        return;
    };
    let name = w::wide(std::ffi::OsStr::new(PIPE_NAME));
    let mut first = true;
    while !stop.load(Ordering::Relaxed) {
        let mut mode = PIPE_ACCESS_DUPLEX;
        if first {
            // Gehört der Name schon einem anderen Programm, scheitert das (Schutz vor Untermietern)
            mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: gültige Zeichenkette und Sicherheitsattribute
        let h = unsafe {
            CreateNamedPipeW(name.as_ptr(), mode, PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa)
        };
        if h == INVALID_HANDLE_VALUE {
            // SAFETY: keine Vorbedingungen
            log(&format!("Pipe konnte nicht angelegt werden (Fehler {}).", unsafe { GetLastError() }));
            if sleep_or_stop(stop, Duration::from_secs(5)) {
                break;
            }
            continue;
        }
        first = false;
        // SAFETY: gültiges Handle, blockiert bis zur Verbindung
        let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !ok || stop.load(Ordering::Relaxed) {
            unsafe { CloseHandle(h) };
            continue;
        }
        // SAFETY: eigenes, verbundenes Handle; File schließt es
        let file = unsafe { File::from_raw_handle(h as _) };
        let job = Arc::clone(job);
        thread::spawn(move || handle_client(file, &job));
    }
}

/// Liest eine Anfrage, prüft sie und antwortet mit dem Ergebnis des Helfers.
fn handle_client(mut pipe: File, job: &Job) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.contains(&b'\n') && buf.len() <= MAX_REQUEST {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let line = buf.split(|b| *b == b'\n').next().unwrap_or_default();
    let resp = match serde_json::from_slice::<PipeRequest>(line) {
        Err(e) => PipeResponse { code: 2, stdout: String::new(), stderr: format!("Ungültige Anfrage an den Vigil-Dienst: {e}") },
        Ok(req) => {
            let lang = if req.lang == "en" { "en" } else { "de" };
            let cmd = req.args.first().map(String::as_str).unwrap_or_default();
            if !crate::SCAN_COMMANDS.contains(&cmd) || req.args.len() > 300 || req.args.iter().any(|a| a.len() > 4096) {
                let msg: Text = tr!(
                    "Der Befehl {} ist über den Vigil-Dienst nicht erlaubt. Dafür sind Administratorrechte nötig.",
                    "The command {} is not allowed via the Vigil service. It requires administrator rights.",
                    cmd
                );
                PipeResponse { code: 3, stdout: String::new(), stderr: msg.get(vigil_core::i18n::Lang::parse(lang).unwrap_or(vigil_core::i18n::Lang::De)) }
            } else {
                run_helper(job, lang, &req.args, false)
            }
        }
    };
    if let Ok(data) = serde_json::to_vec(&resp) {
        let _ = pipe.write_all(&data);
    }
    // Erst warten, bis die App alles gelesen hat; danach schließt das Ende der Funktion die
    // Pipe (die App sieht das als Ende der Antwort)
    let _ = pipe.sync_all();
}
