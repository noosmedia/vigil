//! Vigil-Helfer. Läuft als root (über pkexec oder systemd) und führt alle Aufgaben
//! mit Rechten aus. Installiert als `/usr/lib/vigil/vigil-scan` (nur Prüfbefehle,
//! ohne Passwort) und `/usr/lib/vigil/vigil-helper` (alle Befehle, mit Passwort).
//!
//! Aufruf: `vigil-helper [--lang de|en] <befehl> [--name wert …]`. `--lang` wählt die
//! Sprache der Fehlermeldung auf stderr und der Erfolgszeile (`message`); die Erfolgszeile
//! enthält immer zusätzlich `messageEn`.
//!
//! Exit-Codes: 0 ok, 2 falsche Aufrufparameter, 3 nicht erlaubt, 4 Fehler,
//! 5 Vigil Pro nicht aktiv. `pro` und `pro-ro` reichen den Exit-Code von vigil-pro durch.
//!
//! Windows: `vigil-helper.exe` läuft als Vigil-Dienst (LocalSystem, siehe `winsvc.rs`) für die
//! Prüfbefehle und mit Administratorrechten über die UAC-Abfrage für alle anderen Befehle. Ein
//! über UAC gestarteter Helfer hat keine Ausgabe, die die App lesen könnte; mit dem globalen
//! Parameter `--result <kennung>` (vor `--lang`) schreibt er Exit-Code, stdout und stderr
//! stattdessen nach `C:\ProgramData\Vigil\results\<kennung>.json`.

mod net;
#[cfg(windows)]
mod winsvc;

use serde_json::{Map, Value};
#[cfg(unix)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use vigil_core::actions::{self, SetConfigError};
use vigil_core::engine::Engine;
use vigil_core::i18n::{Lang, Text};
use vigil_core::lock::{self, TryLock};
use vigil_core::pro::{self, Mode, ProError};
use vigil_core::scanner::{self, ScanRequest};
use vigil_core::types::{ExtraStatus, JobKind, Phase, Trigger};
use vigil_core::{config, extrasigs, fsutil, paths, selfupdate, state, systemcheck, tr, update};

const EXIT_USAGE: i32 = 2;
const EXIT_DENIED: i32 = 3;
const EXIT_ERROR: i32 = 4;
const EXIT_INACTIVE: i32 = 5;

/// Befehle, die unter `vigil-scan` erlaubt sind (ohne Passwort; unter Windows über den Dienst).
pub(crate) const SCAN_COMMANDS: &[&str] = &[
    "scan",
    "cancel",
    "pause",
    "resume",
    "update-signatures",
    "systemcheck",
    "pro-token",
    "pro-ro",
];
/// Zusätzliche Befehle unter `vigil-helper` (mit Passwort).
const MANAGE_COMMANDS: &[&str] = &[
    "quarantine",
    "quarantine-path",
    "restore",
    "delete",
    "delete-threat",
    "allow",
    "allow-quarantined",
    "unallow",
    "set-config",
    "fix",
    "self-update",
    "pro-install",
    "pro-remove",
    "pro",
    "extra-signatures",
    "extra-signatures-remove",
];
/// Nur unter Windows: Dienstbetrieb und Einrichtung durch den Installer.
#[cfg(windows)]
const WINDOWS_COMMANDS: &[&str] = &["service", "service-install", "service-remove", "service-stop"];
#[cfg(unix)]
const WINDOWS_COMMANDS: &[&str] = &[];

/// Fehler mit Exit-Code und vollständiger Meldung in beiden Sprachen.
struct Fail {
    code: i32,
    msg: Text,
}

fn usage(msg: Text) -> Fail {
    Fail { code: EXIT_USAGE, msg }
}
fn denied(msg: Text) -> Fail {
    Fail { code: EXIT_DENIED, msg }
}
fn error(msg: Text) -> Fail {
    Fail { code: EXIT_ERROR, msg }
}

impl From<ProError> for Fail {
    fn from(e: ProError) -> Self {
        match e {
            ProError::Inactive(t) => Fail { code: EXIT_INACTIVE, msg: t },
            ProError::Failed(t) => error(t),
        }
    }
}

/// Erfolg: Meldung plus optionale Zusatzfelder für die App.
struct Success {
    message: Text,
    extra: Map<String, Value>,
}

impl Success {
    fn new(message: Text) -> Self {
        Success { message, extra: Map::new() }
    }
    fn with(mut self, key: &str, v: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), v.into());
        self
    }
}

/// Ergebnis eines Befehls: Erfolgszeile oder durchgereichter Exit-Code mit Ausgabe (pro, pro-ro).
enum Done {
    Ok(Success),
    Exit(i32, String, String),
}

impl From<Success> for Done {
    fn from(s: Success) -> Self {
        Done::Ok(s)
    }
}

/// Rolle nach Programmname.
#[derive(PartialEq)]
enum Role {
    Scan,
    Manage,
}

fn main() {
    // Rechte neuer Dateien unabhängig von der Umgebung
    // SAFETY: umask hat keine Vorbedingungen
    #[cfg(unix)]
    unsafe {
        libc::umask(0o022)
    };
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result_id = match take_result(&mut args) {
        Ok(r) => r,
        Err(f) => {
            eprintln!("{}", f.msg.get(Lang::De));
            std::process::exit(f.code);
        }
    };
    let lang = match take_lang(&mut args) {
        Ok(l) => l,
        Err(f) => {
            finish(result_id.as_deref(), f.code, String::new(), format!("{}\n", f.msg.get(Lang::De)));
            return;
        }
    };
    let (code, out, err) = match run(args, lang) {
        Ok(Done::Ok(s)) => {
            let mut obj = Map::new();
            obj.insert("ok".into(), Value::Bool(true));
            obj.insert("message".into(), Value::String(s.message.get(lang)));
            obj.insert("messageEn".into(), Value::String(s.message.en_text()));
            obj.extend(s.extra);
            (0, format!("{}\n", Value::Object(obj)), String::new())
        }
        Ok(Done::Exit(code, out, err)) => (code, out, err),
        Err(f) => (f.code, String::new(), format!("{}\n", f.msg.get(lang))),
    };
    finish(result_id.as_deref(), code, out, err);
}

/// Gibt das Ergebnis aus (stdout, stderr) und beendet den Helfer. Unter Windows mit
/// `--result <kennung>` stattdessen als Datei für die App.
fn finish(result_id: Option<&str>, code: i32, out: String, err: String) {
    use std::io::Write;
    if let Some(id) = result_id {
        let v = serde_json::json!({ "code": code, "stdout": out, "stderr": err });
        let path = paths::data_dir().join("results").join(format!("{id}.json"));
        let _ = fsutil::write_atomic(&path, v.to_string().as_bytes(), 0o644);
    } else {
        print!("{out}");
        eprint!("{err}");
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
    std::process::exit(code);
}

/// Liest den optionalen globalen Parameter `--result <kennung>` (nur Windows, vor `--lang`).
fn take_result(args: &mut Vec<OsString>) -> Result<Option<String>, Fail> {
    if cfg!(unix) || args.first().map(|a| a == "--result") != Some(true) {
        return Ok(None);
    }
    args.remove(0);
    let id = if args.is_empty() { String::new() } else { args.remove(0).to_string_lossy().into_owned() };
    if !paths::valid_id(&id) {
        return Err(usage(tr!("Ungültige Kennung für --result.", "Invalid ID for --result.")));
    }
    Ok(Some(id))
}

/// Liest den optionalen globalen Parameter `--lang de|en` vor dem Befehl.
fn take_lang(args: &mut Vec<OsString>) -> Result<Lang, Fail> {
    if args.first().map(|a| a == "--lang") != Some(true) {
        return Ok(Lang::De);
    }
    args.remove(0);
    if args.is_empty() {
        return Err(usage(tr!("Für --lang fehlt ein Wert (de oder en).", "--lang needs a value (de or en).")));
    }
    let v = args.remove(0).to_string_lossy().into_owned();
    Lang::parse(&v).ok_or_else(|| usage(tr!("Ungültige Sprache: {}. Erlaubt: de, en.", "Invalid language: {}. Allowed: de, en.", v)))
}

/// Unter Windows gibt es nur `vigil-helper.exe`; die Prüfrechte ohne Abfrage vergibt der
/// Vigil-Dienst, der nur Prüfbefehle annimmt.
#[cfg(windows)]
fn detect_role() -> Result<Role, Fail> {
    let exe = std::env::current_exe().map_err(|e| {
        denied(tr!("Der eigene Programmpfad ist nicht lesbar: {}", "The own program path is not readable: {}", e))
    })?;
    let exe_name = exe.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if exe_name == "vigil-helper.exe" {
        return Ok(Role::Manage);
    }
    Err(denied(tr!(
        "Unbekannter Programmname {}. Erlaubt ist nur vigil-helper.exe.",
        "Unknown program name {}. Only vigil-helper.exe is allowed.",
        exe_name
    )))
}

/// Ermittelt die Rolle. Eine Verknüpfung namens vigil-scan bekommt ebenfalls nur Prüfrechte,
/// daher zählt auch argv[0].
#[cfg(unix)]
fn detect_role() -> Result<Role, Fail> {
    let exe = std::env::current_exe().map_err(|e| {
        denied(tr!("Der eigene Programmpfad ist nicht lesbar: {}", "The own program path is not readable: {}", e))
    })?;
    let exe_name = exe.file_name().map(OsStr::to_os_string).unwrap_or_default();
    let argv0 = std::env::args_os().next().unwrap_or_default();
    let argv0_name = Path::new(&argv0).file_name().map(OsStr::to_os_string).unwrap_or_default();
    if exe_name == "vigil-scan" || argv0_name == "vigil-scan" {
        Ok(Role::Scan)
    } else if exe_name == "vigil-helper" {
        Ok(Role::Manage)
    } else {
        let n = exe_name.to_string_lossy();
        Err(denied(tr!(
            "Unbekannter Programmname {}. Erlaubt sind nur vigil-scan und vigil-helper.",
            "Unknown program name {}. Only vigil-scan and vigil-helper are allowed.",
            n
        )))
    }
}

fn run(mut args: Vec<OsString>, lang: Lang) -> Result<Done, Fail> {
    let role = detect_role()?;

    // Nur als root, außer im Testbetrieb
    #[cfg(unix)]
    // SAFETY: geteuid hat keine Vorbedingungen
    if unsafe { libc::geteuid() } != 0 && !paths::is_dev() {
        return Err(denied(tr!(
            "Der Vigil-Helfer muss mit Administratorrechten laufen (über pkexec).",
            "The Vigil helper must run with administrator rights (via pkexec)."
        )));
    }
    // Windows: als Dienst (SYSTEM) oder nach Bestätigung der Administratorabfrage
    #[cfg(windows)]
    if !(vigil_core::win::is_elevated() || vigil_core::win::is_local_system() || paths::is_dev()) {
        return Err(denied(tr!(
            "Der Vigil-Helfer muss mit Administratorrechten laufen.",
            "The Vigil helper must run with administrator rights."
        )));
    }

    if args.is_empty() {
        let (s, m) = (SCAN_COMMANDS.join(", "), MANAGE_COMMANDS.join(", "));
        return Err(usage(tr!("Kein Befehl angegeben. Befehle: {}, {}.", "No command given. Commands: {}, {}.", s, m)));
    }
    let cmd = args.remove(0).to_string_lossy().into_owned();
    if !SCAN_COMMANDS.contains(&cmd.as_str()) && !MANAGE_COMMANDS.contains(&cmd.as_str()) && !WINDOWS_COMMANDS.contains(&cmd.as_str()) {
        return Err(usage(tr!("Unbekannter Befehl: {}", "Unknown command: {}", cmd)));
    }
    if role == Role::Scan && !SCAN_COMMANDS.contains(&cmd.as_str()) {
        return Err(denied(tr!(
            "Der Befehl {} ist über vigil-scan nicht erlaubt. Dafür ist vigil-helper mit Administratorpasswort nötig.",
            "The command {} is not allowed via vigil-scan. It requires vigil-helper with the administrator password.",
            cmd
        )));
    }

    // pro und pro-ro reichen ihre Argumente unverändert an vigil-pro weiter
    if cmd == "pro" || cmd == "pro-ro" {
        let pro_args = raw_args(&args)?;
        ensure_data_dirs()?;
        let mode = if cmd == "pro" { Mode::Rw } else { Mode::Ro };
        return cmd_pro_run(mode, lang, &pro_args);
    }
    // Windows: Dienst und Einrichtung (vor dem Anlegen der Datenordner, das erledigt der Dienst)
    #[cfg(windows)]
    if WINDOWS_COMMANDS.contains(&cmd.as_str()) {
        Opts::parse(&args)?.only(&[])?;
        let done = match cmd.as_str() {
            "service" => winsvc::run_dispatcher(),
            "service-install" => winsvc::install(),
            "service-remove" => winsvc::remove(),
            _ => winsvc::stop(),
        };
        return done.map(|m| Done::Ok(Success::new(m))).map_err(error);
    }
    // self-update --auto ist ein Schalter ohne Wert
    let auto = cmd == "self-update" && args.len() == 1 && args[0] == "--auto";
    let opts = if auto { Opts { pairs: Vec::new() } } else { Opts::parse(&args)? };

    ensure_data_dirs()?;

    let done: Success = match cmd.as_str() {
        "scan" => cmd_scan(&opts)?,
        "cancel" => {
            opts.only(&[])?;
            cmd_cancel()?
        }
        "pause" => {
            opts.only(&[])?;
            cmd_pause()?
        }
        "resume" => {
            opts.only(&[])?;
            cmd_resume()?
        }
        "update-signatures" => {
            opts.only(&["trigger"])?;
            cmd_update(parse_trigger(&opts)?)?
        }
        "systemcheck" => {
            opts.only(&["trigger"])?;
            cmd_systemcheck(parse_trigger(&opts)?)?
        }
        "quarantine" => {
            opts.only(&["report", "threat"])?;
            let (r, t) = (opts.id("report")?, opts.id("threat")?);
            let item = actions::quarantine_threat(&Engine::detect(), &r, &t).map_err(error)?;
            Success::new(moved_text(&item.original_path)).with("quarantineId", item.id)
        }
        "quarantine-path" => {
            opts.only(&["path"])?;
            let p = opts.abs_path("path")?;
            let item = actions::quarantine_watcher_path(&Engine::detect(), &p).map_err(error)?;
            Success::new(moved_text(&item.original_path)).with("quarantineId", item.id)
        }
        "restore" => {
            opts.only(&["id"])?;
            let (item, note) = actions::restore(&opts.id("id")?).map_err(error)?;
            let p = item.original_path;
            Success::new(with_note(tr!("Die Datei {} wurde wiederhergestellt.", "The file {} has been restored.", p), note))
        }
        "delete" => {
            opts.only(&["id"])?;
            let item = actions::delete_quarantined(&opts.id("id")?).map_err(error)?;
            Success::new(deleted_text(&item.original_path))
        }
        "delete-threat" => {
            opts.only(&["report", "threat"])?;
            let (r, t) = (opts.id("report")?, opts.id("threat")?);
            let th = actions::delete_threat(&Engine::detect(), &r, &t).map_err(error)?;
            Success::new(deleted_text(&th.path))
        }
        "allow" => {
            opts.only(&["report", "threat"])?;
            let (r, t) = (opts.id("report")?, opts.id("threat")?);
            let th = actions::allow_threat(&r, &t).map_err(error)?;
            Success::new(tr!(
                "Die Datei {} wurde freigegeben und gilt künftig nicht mehr als Fund.",
                "The file {} has been allowed and will no longer count as a finding.",
                th.path
            ))
        }
        "allow-quarantined" => {
            opts.only(&["id"])?;
            let (item, note) = actions::allow_quarantined(&opts.id("id")?).map_err(error)?;
            let p = item.original_path;
            Success::new(with_note(
                tr!("Die Datei {} wurde wiederhergestellt und freigegeben.", "The file {} has been restored and allowed.", p),
                note,
            ))
        }
        "unallow" => {
            opts.only(&["sha256"])?;
            let sha = opts.one("sha256")?.to_ascii_lowercase();
            if !fsutil::is_sha256(&sha) {
                return Err(usage(tr!("Ungültiger sha256-Wert: {}", "Invalid sha256 value: {}", sha)));
            }
            let removed = actions::unallow(&sha).map_err(error)?;
            Success::new(tr!("Die Freigabe für {} wurde entfernt.", "The allow entry for {} has been removed.", removed.path))
        }
        "set-config" => {
            opts.only(&["json"])?;
            let json = opts.one("json")?;
            let saved = tr!("Die Einstellungen wurden gespeichert.", "The settings have been saved.");
            match actions::set_config(&json) {
                Ok((_, notes)) => Success::new(Text::join(&[vec![saved], notes].concat())),
                Err(SetConfigError::Invalid(e)) => return Err(usage(e)),
                Err(SetConfigError::Failed(e)) => return Err(error(e)),
            }
        }
        "fix" => {
            opts.only(&["action"])?;
            let action = opts.one("action")?;
            if !["firewall-enable", "services-enable", "rkhunter-baseline"].contains(&action.as_str()) {
                return Err(usage(tr!(
                    "Unbekannte Maßnahme: {}. Erlaubt: firewall-enable, services-enable, rkhunter-baseline.",
                    "Unknown action: {}. Allowed: firewall-enable, services-enable, rkhunter-baseline.",
                    action
                )));
            }
            // Nicht parallel zu einem Systemcheck (rkhunter darf nicht gleichzeitig laufen)
            let _lock = job_lock()?;
            Success::new(actions::run_fix(&action).map_err(error)?)
        }
        "self-update" => cmd_self_update(auto, &opts)?,
        "pro-install" => {
            opts.only(&["dir", "token"])?;
            let dir = opts.abs_path("dir")?;
            let token = opts.one("token")?;
            cmd_pro_install(&dir, &token, lang)?
        }
        "pro-token" => {
            opts.only(&["token"])?;
            let claims = pro::update_token(&opts.one("token")?)?;
            Success::new(tr!("Die Freigabe für Vigil Pro wurde erneuert.", "The Vigil Pro activation token has been renewed."))
                .with("expiresAt", claims.exp)
        }
        "pro-remove" => {
            opts.only(&[])?;
            cmd_pro_remove(lang)?
        }
        "extra-signatures" => {
            // --trigger dient nur der Lesbarkeit der Unit; Ablauf und Mindestabstand sind gleich
            opts.only(&["trigger"])?;
            parse_trigger(&opts)?;
            install_signal_handlers();
            let o = extrasigs::run();
            if o.status == ExtraStatus::Failed {
                return Err(error(o.message));
            }
            extra_success(Success::new(o.message.clone()), &o)
        }
        "extra-signatures-remove" => {
            opts.only(&[])?;
            Success::new(extrasigs::remove_all().map_err(error)?)
        }
        _ => return Err(usage(tr!("Unbekannter Befehl: {}", "Unknown command: {}", cmd))),
    };
    Ok(Done::Ok(done))
}

fn moved_text(p: &str) -> Text {
    tr!("Die Datei {} wurde in die Quarantäne verschoben.", "The file {} has been moved to quarantine.", p)
}

fn deleted_text(p: &str) -> Text {
    tr!("Die Datei {} wurde endgültig gelöscht.", "The file {} has been permanently deleted.", p)
}

fn with_note(msg: Text, note: Option<Text>) -> Text {
    match note {
        Some(n) => tr!("{} Hinweis: {}", "{} Note: {}", msg, n),
        None => msg,
    }
}

/// Legt die Datenordner mit den richtigen Rechten an.
fn ensure_data_dirs() -> Result<(), Fail> {
    fsutil::ensure_dir(&paths::data_dir(), 0o755).map_err(error)?;
    fsutil::ensure_dir(&paths::reports_dir(), 0o755).map_err(error)?;
    fsutil::ensure_dir(&paths::quarantine_dir(), 0o700).map_err(error)?;
    Ok(())
}

/// Übernimmt `job.lock` oder meldet, dass schon etwas läuft.
fn job_lock() -> Result<lock::FileLock, Fail> {
    match lock::try_job_lock().map_err(error)? {
        TryLock::Acquired(l) => Ok(l),
        TryLock::Busy => Err(error(tr!("Es läuft bereits eine Prüfung.", "A scan is already running."))),
    }
}

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    vigil_core::TERMINATE.store(true, Ordering::Relaxed);
}

#[cfg(windows)]
unsafe extern "system" fn on_console_event(_: u32) -> i32 {
    vigil_core::TERMINATE.store(true, Ordering::Relaxed);
    1
}

/// Strg+C, Schließen der Konsole, Abmelden und Herunterfahren beenden einen Auftrag sauber.
#[cfg(windows)]
fn install_signal_handlers() {
    // SAFETY: der Handler setzt nur eine atomare Variable
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_console_event), 1) };
}

/// SIGTERM, SIGINT und SIGHUP beenden einen Auftrag sauber (wie ein Abbruch).
#[cfg(unix)]
fn install_signal_handlers() {
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: der Handler setzt nur eine atomare Variable (signal-sicher)
        unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
    }
}

/// Entfernt Abbruch- und Pausensignal (vor und nach einer Prüfung).
fn remove_signal_files() {
    let _ = std::fs::remove_file(paths::cancel_path());
    let _ = std::fs::remove_file(paths::pause_path());
}

fn parse_trigger(opts: &Opts) -> Result<Trigger, Fail> {
    match opts.optional("trigger")?.as_deref() {
        None | Some("manual") => Ok(Trigger::Manual),
        Some("schedule") => Ok(Trigger::Schedule),
        Some(o) => Err(usage(tr!("Ungültiger Auslöser: {}. Erlaubt: manual, schedule.", "Invalid trigger: {}. Allowed: manual, schedule.", o))),
    }
}

fn cmd_scan(opts: &Opts) -> Result<Success, Fail> {
    opts.only(&["kind", "trigger", "path"])?;
    let trigger = parse_trigger(opts)?;
    let kind = match opts.one("kind")?.as_str() {
        "quick" => JobKind::Quick,
        "full" => JobKind::Full,
        "custom" => JobKind::Custom,
        k => return Err(usage(tr!("Ungültige Prüfart: {}. Erlaubt: quick, full, custom.", "Invalid scan type: {}. Allowed: quick, full, custom.", k))),
    };
    let raw = opts.all("path");
    let mut paths_v = Vec::new();
    if kind == JobKind::Custom {
        if raw.is_empty() {
            return Err(usage(tr!("Für eine benutzerdefinierte Prüfung fehlt --path.", "A custom scan needs --path.")));
        }
        for p in raw {
            let pb = PathBuf::from(p);
            if !pb.is_absolute() {
                return Err(usage(tr!("Der Pfad muss absolut sein: {}", "The path must be absolute: {}", pb.display())));
            }
            let canon = std::fs::canonicalize(&pb).map_err(|e| {
                error(tr!(
                    "Der Pfad {} existiert nicht oder ist nicht erreichbar: {}",
                    "The path {} does not exist or is not reachable: {}",
                    pb.display(),
                    e
                ))
            })?;
            // Windows: canonicalize liefert \\?\C:\…; für Berichte und Ausschlüsse ohne Vorsilbe
            #[cfg(windows)]
            let canon = vigil_core::win::strip_verbatim(&canon);
            paths_v.push(canon);
        }
    } else if !raw.is_empty() {
        return Err(usage(tr!("--path ist nur bei --kind custom erlaubt.", "--path is only allowed with --kind custom.")));
    }

    let _lock = job_lock()?;
    remove_signal_files();
    install_signal_handlers();
    let job = scanner::run_scan(&ScanRequest { kind, trigger, paths: paths_v });
    remove_signal_files();
    let msg = Text::new(job.message.clone().unwrap_or_default(), job.message_en.clone().unwrap_or_default());
    match job.phase {
        Phase::Failed => Err(error(msg)),
        _ => Ok(Success::new(msg)
            .with("reportId", job.id.clone())
            .with("phase", serde_json::to_value(job.phase).unwrap_or(Value::Null))
            .with("threats", job.threats.iter().filter(|t| !t.is_hint()).count() as u64)
            .with("hints", job.threats.iter().filter(|t| t.is_hint()).count() as u64)),
    }
}

fn no_scan() -> Text {
    tr!("Es läuft keine Prüfung.", "No scan is running.")
}

fn cmd_cancel() -> Result<Success, Fail> {
    if !lock::is_job_running() {
        return Ok(Success::new(no_scan()));
    }
    let st = state::read_state().map_err(error)?;
    match st.job {
        Some(j) if !j.kind.is_scan() => Err(error(tr!(
            "Der laufende Systemcheck oder die Signaturaktualisierung lässt sich nicht abbrechen.",
            "The running system check or signature update cannot be cancelled."
        ))),
        _ => {
            fsutil::write_atomic(&paths::cancel_path(), b"", 0o644).map_err(error)?;
            Ok(Success::new(tr!("Der Abbruch wurde angefordert.", "Cancellation has been requested.")))
        }
    }
}

fn cmd_pause() -> Result<Success, Fail> {
    if !lock::is_job_running() {
        return Err(error(no_scan()));
    }
    let st = state::read_state().map_err(error)?;
    match st.job {
        Some(j) if !j.kind.is_scan() => Err(error(tr!(
            "Der laufende Systemcheck oder die Signaturaktualisierung lässt sich nicht anhalten.",
            "The running system check or signature update cannot be paused."
        ))),
        _ => {
            fsutil::write_atomic(&paths::pause_path(), b"", 0o644).map_err(error)?;
            Ok(Success::new(tr!("Die Prüfung wird angehalten.", "The scan is being paused.")))
        }
    }
}

fn cmd_resume() -> Result<Success, Fail> {
    let removed = match std::fs::remove_file(paths::pause_path()) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            let p = paths::pause_path();
            return Err(error(tr!(
                "Das Pausensignal {} konnte nicht entfernt werden: {}",
                "Could not remove the pause signal {}: {}",
                p.display(),
                e
            )));
        }
    };
    if !lock::is_job_running() {
        return Err(error(no_scan()));
    }
    if !removed {
        return Ok(Success::new(tr!("Die Prüfung ist nicht angehalten.", "The scan is not paused.")));
    }
    Ok(Success::new(tr!("Die Prüfung wird fortgesetzt.", "The scan is being resumed.")))
}

fn cmd_update(trigger: Trigger) -> Result<Success, Fail> {
    let _lock = job_lock()?;
    install_signal_handlers();
    let r = update::run_update(trigger);
    let job = &r.job;
    let msg = Text::new(job.message.clone().unwrap_or_default(), job.message_en.clone().unwrap_or_default());
    if job.phase != Phase::Finished {
        return Err(error(msg));
    }
    // Getrennte Rückmeldung: clamav = updated|current, extra = updated|current|waiting|partial|failed|off
    let s = Success::new(msg).with("clamav", r.clamav.as_str());
    Ok(match &r.extra {
        Some(o) => extra_success(s, o),
        None => s.with("extra", ExtraStatus::Off.as_str()),
    })
}

/// Zusatzfelder der Erfolgszeile für die zusätzlichen Signaturen.
fn extra_success(s: Success, o: &extrasigs::Outcome) -> Success {
    s.with("extra", o.status.as_str())
        .with("extraChanged", o.changed as u64)
        .with("extraSignatures", o.signatures)
}

fn cmd_systemcheck(trigger: Trigger) -> Result<Success, Fail> {
    let _lock = job_lock()?;
    install_signal_handlers();
    let job = systemcheck::run_systemcheck(trigger);
    let msg = Text::new(job.message.clone().unwrap_or_default(), job.message_en.clone().unwrap_or_default());
    match job.phase {
        Phase::Finished => Ok(Success::new(msg)),
        _ => Err(error(msg)),
    }
}

/// `self-update --deb <p> --sig <p>` oder `self-update --auto` (Timer).
fn cmd_self_update(auto: bool, opts: &Opts) -> Result<Success, Fail> {
    let _ulock = match lock::try_update_lock().map_err(error)? {
        TryLock::Acquired(l) => l,
        TryLock::Busy => {
            return Err(error(tr!("Es läuft bereits ein Update von Vigil.", "An update of Vigil is already running.")))
        }
    };
    if !auto {
        opts.only(&["deb", "sig"])?;
        let (deb, sig) = (opts.abs_path("deb")?, opts.abs_path("sig")?);
        let staged = selfupdate::stage_files(&deb, &sig).map_err(error)?;
        let msg = selfupdate::install_staged(&staged, None).map_err(error)?;
        return Ok(Success::new(msg).with("installed", true));
    }

    // Automatisch: nur wenn eingeschaltet
    let cfg = config::load_config().map_err(error)?;
    if !cfg.updates.auto {
        return Ok(Success::new(tr!("Automatische Updates sind ausgeschaltet.", "Automatic updates are turned off."))
            .with("installed", false));
    }
    let release = net::latest_release().map_err(error)?;
    let installed = selfupdate::installed_version().map_err(error)?;
    if !selfupdate::version_greater(&release.version, &installed).map_err(error)? {
        return Ok(Success::new(tr!("Vigil ist aktuell (Version {}).", "Vigil is up to date (version {}).", installed))
            .with("installed", false));
    }
    let staged = net::download_release(&release).map_err(error)?;
    let msg = selfupdate::install_staged(&staged, Some(&release.version)).map_err(error)?;
    Ok(Success::new(msg).with("installed", true).with("version", release.version))
}

/// Startet `vigil-pro` (nach Prüfung) mit erfasster Ausgabe, für install-hooks und remove-hooks.
fn run_pro_captured(lang: Lang, action: &str) -> Result<(), Text> {
    pro::read_verified(pro::PRO_BIN)?;
    let out = pro::command(Mode::Rw, lang, &[action.to_string()])
        .output()
        .map_err(|e| tr!("vigil-pro konnte nicht gestartet werden: {}", "Could not start vigil-pro: {}", e))?;
    if out.status.success() {
        return Ok(());
    }
    let text = [String::from_utf8_lossy(&out.stderr).trim(), String::from_utf8_lossy(&out.stdout).trim()]
        .into_iter()
        .find(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_default();
    let code = out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "-".into());
    Err(tr!("vigil-pro {} ist fehlgeschlagen (Exit-Code {}): {}", "vigil-pro {} failed (exit code {}): {}", action, code, text))
}

/// `pro-install --dir <ordner> --token <t>`
fn cmd_pro_install(dir: &Path, token: &str, lang: Lang) -> Result<Success, Fail> {
    let manifest = pro::install(dir, token)?;
    if let Err(e) = run_pro_captured(lang, "install-hooks") {
        return Err(error(tr!(
            "Vigil Pro {} wurde installiert, die Einrichtung ist aber fehlgeschlagen: {}",
            "Vigil Pro {} has been installed, but the setup failed: {}",
            manifest.version,
            e
        )));
    }
    Ok(Success::new(tr!("Vigil Pro {} wurde installiert.", "Vigil Pro {} has been installed.", manifest.version))
        .with("version", manifest.version))
}

/// `pro-remove`: remove-hooks (nur nach erfolgreicher Prüfung von vigil-pro), dann Dateien löschen.
fn cmd_pro_remove(lang: Lang) -> Result<Success, Fail> {
    if !pro::is_installed() && !paths::pro_token_path().exists() && !paths::pro_dir().exists() {
        return Ok(Success::new(tr!("Vigil Pro ist nicht installiert.", "Vigil Pro is not installed.")));
    }
    let mut notes = vec![tr!("Vigil Pro wurde entfernt.", "Vigil Pro has been removed.")];
    if pro::is_installed() {
        if let Err(e) = run_pro_captured(lang, "remove-hooks") {
            notes.push(tr!(
                "Hinweis: Die Einrichtungen von Vigil Pro konnten nicht entfernt werden: {}",
                "Note: The Vigil Pro setup could not be removed: {}",
                e
            ));
        }
    }
    pro::remove_files().map_err(error)?;
    Ok(Success::new(Text::join(&notes)))
}

/// `pro <args…>` und `pro-ro <args…>`: Freigabe und vigil-pro prüfen, dann starten;
/// stdout, stderr und Exit-Code werden durchgereicht.
fn cmd_pro_run(mode: Mode, lang: Lang, args: &[String]) -> Result<Done, Fail> {
    if !pro::is_installed() {
        return Err(ProError::Inactive(Text::join(&[
            tr!("Vigil Pro ist nicht aktiv.", "Vigil Pro is not active."),
            tr!("Vigil Pro ist nicht installiert.", "Vigil Pro is not installed."),
        ]))
        .into());
    }
    pro::check_active()?;
    pro::read_verified(pro::PRO_BIN).map_err(error)?;
    // Linux: stdout und stderr gehen direkt an den Aufrufer
    #[cfg(unix)]
    {
        let status = pro::command(mode, lang, args)
            .status()
            .map_err(|e| error(tr!("vigil-pro konnte nicht gestartet werden: {}", "Could not start vigil-pro: {}", e)))?;
        use std::os::unix::process::ExitStatusExt;
        Ok(Done::Exit(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)), String::new(), String::new()))
    }
    // Windows: Ausgabe sammeln (für die Pipe des Dienstes und die Ergebnisdatei nach UAC)
    #[cfg(windows)]
    {
        let out = pro::command(mode, lang, args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| error(tr!("vigil-pro konnte nicht gestartet werden: {}", "Could not start vigil-pro: {}", e)))?;
        let code = out.status.code().unwrap_or(EXIT_ERROR);
        Ok(Done::Exit(code, String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

/// Argumente für vigil-pro: gültiges UTF-8, höchstens 256 Stück zu je 4096 Byte.
fn raw_args(args: &[OsString]) -> Result<Vec<String>, Fail> {
    if args.len() > 256 {
        return Err(usage(tr!("Zu viele Argumente für vigil-pro.", "Too many arguments for vigil-pro.")));
    }
    args.iter()
        .map(|a| match a.to_str() {
            Some(s) if s.len() <= 4096 => Ok(s.to_string()),
            _ => Err(usage(tr!("Ungültiges Argument für vigil-pro.", "Invalid argument for vigil-pro."))),
        })
        .collect()
}

/// Aufrufparameter der Form `--name wert`.
struct Opts {
    pairs: Vec<(String, OsString)>,
}

impl Opts {
    fn parse(args: &[OsString]) -> Result<Opts, Fail> {
        let mut pairs = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let a = a.to_string_lossy();
            let Some(name) = a.strip_prefix("--").filter(|n| !n.is_empty()) else {
                return Err(usage(tr!("Unerwarteter Parameter: {}", "Unexpected parameter: {}", a)));
            };
            let v = it.next().ok_or_else(|| usage(tr!("Für --{} fehlt ein Wert.", "--{} needs a value.", name)))?;
            pairs.push((name.to_string(), v.clone()));
        }
        Ok(Opts { pairs })
    }

    /// Nur diese Namen sind erlaubt, jeder höchstens einmal (außer --path).
    fn only(&self, allowed: &[&str]) -> Result<(), Fail> {
        for (i, (n, _)) in self.pairs.iter().enumerate() {
            if !allowed.contains(&n.as_str()) {
                return Err(usage(tr!(
                    "Unbekannter Parameter für diesen Befehl: --{}",
                    "Unknown parameter for this command: --{}",
                    n
                )));
            }
            if n != "path" && self.pairs[..i].iter().any(|(m, _)| m == n) {
                return Err(usage(tr!("Der Parameter --{} ist doppelt angegeben.", "The parameter --{} is given twice.", n)));
            }
        }
        Ok(())
    }

    fn optional(&self, name: &str) -> Result<Option<String>, Fail> {
        match self.pairs.iter().find(|(n, _)| n == name) {
            None => Ok(None),
            Some((_, v)) => v
                .to_str()
                .map(|s| Some(s.to_string()))
                .ok_or_else(|| usage(tr!("Ungültige Zeichen in --{}.", "Invalid characters in --{}.", name))),
        }
    }

    fn one(&self, name: &str) -> Result<String, Fail> {
        self.optional(name)?.ok_or_else(|| usage(tr!("Der Parameter --{} fehlt.", "The parameter --{} is missing.", name)))
    }

    fn all(&self, name: &str) -> Vec<OsString> {
        self.pairs.iter().filter(|(n, _)| n == name).map(|(_, v)| v.clone()).collect()
    }

    /// Kennung für Bericht, Fund oder Quarantäne (nur Buchstaben, Ziffern, `-`, `_`).
    fn id(&self, name: &str) -> Result<String, Fail> {
        let v = self.one(name)?;
        if !paths::valid_id(&v) {
            return Err(usage(tr!("Ungültige Kennung für --{}: {}", "Invalid ID for --{}: {}", name, v)));
        }
        Ok(v)
    }

    fn abs_path(&self, name: &str) -> Result<PathBuf, Fail> {
        let v = self.pairs.iter().find(|(n, _)| n == name).map(|(_, v)| PathBuf::from(v));
        let p = v.ok_or_else(|| usage(tr!("Der Parameter --{} fehlt.", "The parameter --{} is missing.", name)))?;
        if !p.is_absolute() {
            return Err(usage(tr!("Der Pfad muss absolut sein: {}", "The path must be absolute: {}", p.display())));
        }
        Ok(p)
    }
}
