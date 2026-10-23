//! Ziele der Schnellprüfung (Benutzerordner, Systemorte, Programme laufender Prozesse)
//! und kurze Beschriftungen für Pfade (`~/.config`, unter Windows `~\Downloads`).

use crate::i18n::Text;
use crate::paths;
use crate::tr;
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Unterordner je Benutzer (nach Download- und Desktop-Ordner).
#[cfg(unix)]
const HOME_DIRS: &[&str] = &[".local/bin", "bin", ".local/share/applications", ".config/autostart", ".config/systemd/user"];

/// Startdateien je Benutzer.
#[cfg(unix)]
const HOME_FILES: &[&str] = &[
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zshrc",
    ".xprofile",
    ".xsessionrc",
];

/// Systemorte der Schnellprüfung.
#[cfg(unix)]
pub const SYSTEM_PATHS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/etc/xdg/autostart",
    "/etc/profile.d",
    "/etc/rc.local",
    "/etc/ld.so.preload",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Benutzerordner für Beschriftungen und Ziele.
pub struct Homes {
    /// (Benutzername, Ordner): erst `/home/*` nach Namen sortiert, dann `/root`.
    pub users: Vec<(String, PathBuf)>,
    /// Benutzer, der ohne Namen als `~` erscheint (nur wenn es genau einen gibt).
    single: Option<String>,
}

/// Ziele je Windows-Benutzerordner: Downloads, Desktop (auch in OneDrive), Autostart,
/// temporäre Dateien.
#[cfg(windows)]
const HOME_DIRS: &[&str] = &[
    "Downloads",
    "Desktop",
    r"OneDrive\Desktop",
    r"OneDrive\Schreibtisch",
    r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    r"AppData\Local\Temp",
];

/// Systemorte der Schnellprüfung unter Windows (relativ zu Windows-Ordner bzw. ProgramData).
#[cfg(windows)]
fn system_paths() -> Vec<PathBuf> {
    let sys = crate::win::system_dir();
    let windows = sys.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let pd = crate::win::program_data();
    vec![
        windows.join("Temp"),
        pd.join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        sys.join("Tasks"),
    ]
}

impl Homes {
    /// Ermittelt die Benutzerordner unter `C:\Users` (echte Ordner, keine Verknüpfungen, ohne
    /// die Vorlagen „Default“ und „Default User“). „Public“ zählt mit (gemeinsamer Desktop).
    #[cfg(windows)]
    pub fn detect() -> Homes {
        let base = crate::win::known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_UserProfiles)
            .unwrap_or_else(|| PathBuf::from(r"C:\Users"));
        let mut users: Vec<(String, PathBuf)> = fs::read_dir(&base)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.path())))
                    .filter(|(n, _)| !["Default", "Default User", "All Users"].contains(&n.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        users.sort();
        let real: Vec<&(String, PathBuf)> = users.iter().filter(|(n, _)| n != "Public").collect();
        let single = (real.len() == 1).then(|| real[0].0.clone());
        Homes { users, single }
    }

    /// Ermittelt die Benutzerordner: echte Ordner unter `/home` (keine Verknüpfungen) und `/root`.
    #[cfg(unix)]
    pub fn detect() -> Homes {
        let mut users: Vec<(String, PathBuf)> = fs::read_dir("/home")
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.path())))
                    .collect()
            })
            .unwrap_or_default();
        users.sort();
        // Nur ein Benutzer unter /home: er bekommt „~“; ohne Benutzer unter /home gilt das für root
        let single = match users.len() {
            0 => Some("root".to_string()),
            1 => Some(users[0].0.clone()),
            _ => None,
        };
        users.push(("root".into(), PathBuf::from("/root")));
        Homes { users, single }
    }

    /// Kurze Beschriftung: Home-Pfade mit `~` (mit Besitzer, wenn es mehrere gibt), sonst der Pfad.
    pub fn label(&self, p: &Path) -> String {
        let sep = std::path::MAIN_SEPARATOR;
        for (name, dir) in &self.users {
            if let Ok(rest) = p.strip_prefix(dir) {
                let prefix = if self.single.as_deref() == Some(name.as_str()) { "~".to_string() } else { format!("~{name}") };
                return if rest.as_os_str().is_empty() { prefix } else { format!("{prefix}{sep}{}", rest.display()) };
            }
        }
        paths::display(p)
    }
}

/// Ein Ziel der Schnellprüfung.
pub enum Target {
    /// Ordner oder Datei (ganzer Baum).
    Path(PathBuf),
    /// Programme laufender Prozesse.
    Programs(Vec<PathBuf>),
}

/// Beschriftung des Bereichs „Laufende Programme“.
pub fn programs_label() -> Text {
    tr!("Laufende Programme", "Running programs")
}

/// Existiert der Pfad als Ordner oder reguläre Datei (ohne Verknüpfungen zu folgen)?
fn exists_plain(p: &Path) -> bool {
    fs::symlink_metadata(p).map(|m| m.is_dir() || m.is_file()).unwrap_or(false)
}

/// Liest einen Eintrag aus `~/.config/user-dirs.dirs`, z. B. `XDG_DOWNLOAD_DIR="$HOME/Downloads"`.
/// `None`, wenn Datei oder Eintrag fehlen. Liefert nie den Benutzerordner selbst.
#[cfg(unix)]
fn xdg_dir(home: &Path, key: &str) -> Option<PathBuf> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(home.join(".config/user-dirs.dirs"))
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    f.take(64 * 1024).read_to_string(&mut text).ok()?;
    let line = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix(key)?.trim_start().strip_prefix('='))
        .next_back()?;
    let v = line.trim().trim_matches('"');
    let p = match v.strip_prefix("$HOME") {
        Some(rest) => home.join(rest.trim_start_matches('/')),
        None => PathBuf::from(v),
    };
    // Nur absolute Pfade ohne "..", nie der Benutzerordner selbst (sonst würde er ganz geprüft)
    let clean = p.is_absolute() && !p.components().any(|c| matches!(c, std::path::Component::ParentDir));
    (clean && p.components().ne(home.components())).then_some(p)
}

/// Download- und Desktop-Ordner eines Benutzers (laut user-dirs.dirs, sonst Standardnamen).
#[cfg(unix)]
fn user_dirs(home: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    match xdg_dir(home, "XDG_DOWNLOAD_DIR") {
        Some(p) => v.push(p),
        None => v.push(home.join("Downloads")),
    }
    match xdg_dir(home, "XDG_DESKTOP_DIR") {
        Some(p) => v.push(p),
        None => {
            v.push(home.join("Desktop"));
            v.push(home.join("Schreibtisch"));
        }
    }
    v
}

/// Programme aller laufenden Prozesse unter Windows (ohne Doppelte, nach Pfad sortiert).
/// Geschützte Systemprozesse, deren Programmpfad nicht abfragbar ist, fehlen.
#[cfg(windows)]
pub fn running_programs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = crate::win::processes()
        .into_iter()
        .filter_map(|(pid, _)| crate::win::process_image(pid))
        .filter(|p| fs::symlink_metadata(p).map(|m| m.is_file()).unwrap_or(false))
        .collect();
    v.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    v.dedup_by(|a, b| crate::win::eq_ci(a, b));
    v
}

/// Programme aller laufenden Prozesse: Ziel von `/proc/<pid>/exe`, nur reguläre Dateien,
/// ohne gelöschte, ohne Doppelte, nach Pfad sortiert.
#[cfg(unix)]
pub fn running_programs() -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir("/proc") else { return Vec::new() };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().map(|n| n.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false))
        .filter_map(|e| fs::read_link(e.path().join("exe")).ok())
        .filter(|p| p.is_absolute() && !p.to_string_lossy().ends_with(" (deleted)"))
        .filter(|p| fs::symlink_metadata(p).map(|m| m.is_file()).unwrap_or(false))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Alle vorhandenen Ziele der Schnellprüfung in Prüfreihenfolge. `excluded` filtert
/// ausgeschlossene Pfade. Verschachtelte Ziele werden nur einmal geprüft, Programme
/// innerhalb eines Zielordners entfallen.
pub fn targets(homes: &Homes, excluded: impl Fn(&Path) -> bool) -> Vec<Target> {
    let mut list: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    {
        for (_, home) in &homes.users {
            list.extend(user_dirs(home));
            list.extend(HOME_DIRS.iter().map(|d| home.join(d)));
            list.extend(HOME_FILES.iter().map(|f| home.join(f)));
        }
        list.extend(SYSTEM_PATHS.iter().map(PathBuf::from));
    }
    #[cfg(windows)]
    {
        for (_, home) in &homes.users {
            list.extend(HOME_DIRS.iter().map(|d| home.join(d)));
        }
        list.extend(system_paths());
    }
    list.retain(|p| exists_plain(p) && !excluded(p));

    // Doppelte und verschachtelte Ziele entfernen, Reihenfolge erhalten
    let all = list.clone();
    let mut seen: Vec<PathBuf> = Vec::new();
    list.retain(|p| {
        let nested = all.iter().any(|o| o != p && paths::starts_with(p, o));
        let dup = seen.contains(p);
        seen.push(p.clone());
        !nested && !dup
    });

    let programs: Vec<PathBuf> = running_programs()
        .into_iter()
        .filter(|p| !excluded(p) && !list.iter().any(|t| paths::starts_with(p, t)))
        .collect();
    let mut out: Vec<Target> = list.into_iter().map(Target::Path).collect();
    if !programs.is_empty() {
        out.push(Target::Programs(programs));
    }
    out
}
