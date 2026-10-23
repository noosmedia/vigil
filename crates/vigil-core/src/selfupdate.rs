//! Updates von Vigil selbst: signierte .deb in den Update-Ordner übernehmen, Signatur,
//! Paketname und Version prüfen, mit apt-get installieren. Das Herunterladen erledigt
//! der Helfer (`self-update --auto`) oder die App.
//!
//! Unter Windows ist das Update der signierte Installer `Vigil_X.Y.Z_x64-setup.exe`. Geprüft
//! werden Signatur, Produktname und Version aus den Dateieigenschaften; danach startet der
//! Helfer den Installer unbeaufsichtigt (`/S /R`) und endet. Der Installer hält den Dienst an,
//! ersetzt die Dateien und startet Vigil danach für den angemeldeten Benutzer neu.

#[cfg(unix)]
use crate::cmd;
use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::sign::{self, KeyKind};
use crate::tr;
use std::fs::{File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

/// GitHub-Repository des Quellcodes von Vigil (für den Link „Quellcode“).
pub const UPDATE_REPO: &str = "noosmedia/vigil";

/// Abfrage der neuesten Vigil-Version beim eigenen Update-Server (Lizenzserver, ohne Anmeldung).
/// Antwortet im Aufbau eines GitHub-Release: tag_name, body, published_at, assets mit .deb und .deb.sig.
pub const UPDATE_API: &str = "https://lizenz.noosmedia.de/vigil/api/core/releases/latest";

/// Größte erlaubte .deb.
pub const MAX_DEB_SIZE: u64 = 300 * 1024 * 1024;

/// Größte erlaubte Signaturdatei.
const MAX_SIG_SIZE: u64 = 4096;

/// Name des Pakets.
pub const PACKAGE: &str = "vigil";

/// Dateiname der .deb im Release, z. B. `Vigil_0.2.1_amd64.deb`.
#[cfg(unix)]
pub fn deb_asset_name(version: &str) -> String {
    format!("Vigil_{version}_amd64.deb")
}

/// Dateiname des Installers im Release, z. B. `Vigil_0.4.0_x64-setup.exe`.
#[cfg(windows)]
pub fn deb_asset_name(version: &str) -> String {
    format!("Vigil_{version}_x64-setup.exe")
}

/// Endung der Update-Datei im Update-Ordner.
#[cfg(unix)]
const STAGED_EXT: &str = "deb";
#[cfg(windows)]
const STAGED_EXT: &str = "exe";

/// Eine übernommene Update-Datei im Update-Ordner.
pub struct Staged {
    pub deb: PathBuf,
    pub sig: PathBuf,
}

impl Staged {
    /// Entfernt die übernommenen Dateien wieder.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.deb);
        let _ = std::fs::remove_file(&self.sig);
    }
}

/// Legt den Update-Ordner an (root, 0700).
pub fn ensure_updates_dir() -> Result<PathBuf, Text> {
    let dir = paths::updates_dir();
    fsutil::ensure_dir(&dir, 0o700)?;
    Ok(dir)
}

/// Neue Ablagenamen im Update-Ordner (`update-<zeit>-<pid>.deb` und `.deb.sig`, unter Windows
/// `.exe` und `.exe.sig`).
pub fn new_staged() -> Result<Staged, Text> {
    let dir = ensure_updates_dir()?;
    #[cfg(windows)]
    remove_old_installers(&dir);
    let base = format!("update-{}-{}", chrono::Local::now().format("%Y%m%d-%H%M%S"), std::process::id());
    Ok(Staged { deb: dir.join(format!("{base}.{STAGED_EXT}")), sig: dir.join(format!("{base}.{STAGED_EXT}.sig")) })
}

/// Entfernt Installer früherer Updates (unter Windows bleibt der laufende Installer liegen,
/// weil er sich während der Installation nicht löschen lässt).
#[cfg(windows)]
fn remove_old_installers(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let day = std::time::Duration::from_secs(24 * 3600);
    for e in rd.flatten() {
        let old = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).map(|a| a > day).unwrap_or(false);
        if old && e.file_name().to_string_lossy().starts_with("update-") {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Öffnet eine Quelldatei ohne Verfolgen einer Verknüpfung am Ende und prüft Art und Größe.
fn open_source(p: &Path, max: u64) -> Result<File, Text> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    // Windows: FILE_FLAG_OPEN_REPARSE_POINT (eine Verknüpfung ist keine reguläre Datei)
    #[cfg(windows)]
    o.custom_flags(0x0020_0000);
    let f = o
        .open(p)
        .map_err(|e| tr!("Die Datei {} konnte nicht geöffnet werden: {}", "Could not open the file {}: {}", p.display(), e))?;
    let meta = f
        .metadata()
        .map_err(|e| tr!("Die Datei {} ist nicht lesbar: {}", "The file {} is not readable: {}", p.display(), e))?;
    if !meta.is_file() {
        return Err(tr!("{} ist keine reguläre Datei.", "{} is not a regular file.", p.display()));
    }
    if meta.len() > max {
        return Err(tr!("Die Datei {} ist zu groß.", "The file {} is too large.", p.display()));
    }
    Ok(f)
}

/// Liest eine Quelldatei vollständig (höchstens `max` Byte).
pub fn read_source(p: &Path, max: u64) -> Result<Vec<u8>, Text> {
    let f = open_source(p, max)?;
    let mut data = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut data)
        .map_err(|e| tr!("Die Datei {} konnte nicht gelesen werden: {}", "Could not read the file {}: {}", p.display(), e))?;
    if data.len() as u64 > max {
        return Err(tr!("Die Datei {} ist zu groß.", "The file {} is too large.", p.display()));
    }
    Ok(data)
}

/// Übernimmt .deb und .sig (z. B. aus `~/.cache/vigil/update/`) in den Update-Ordner.
/// Geprüft wird danach nur die Kopie, damit niemand die Datei zwischen Prüfung und
/// Installation austauschen kann.
pub fn stage_files(deb: &Path, sig: &Path) -> Result<Staged, Text> {
    let sig_data = read_source(sig, MAX_SIG_SIZE)?;
    let deb_data = read_source(deb, MAX_DEB_SIZE)?;
    let staged = new_staged()?;
    let r = fsutil::write_atomic(&staged.deb, &deb_data, 0o600).and_then(|_| fsutil::write_atomic(&staged.sig, &sig_data, 0o600));
    if let Err(e) = r {
        staged.cleanup();
        return Err(e);
    }
    Ok(staged)
}

/// Prüft eine übernommene .deb (Signatur, Paketname, höhere Version) und installiert sie.
/// `expected_version` (aus dem Release) muss, wenn angegeben, zur .deb passen.
/// Die übernommenen Dateien werden in jedem Fall entfernt.
#[cfg(unix)]
pub fn install_staged(staged: &Staged, expected_version: Option<&str>) -> Result<Text, Text> {
    let r = install_inner(staged, expected_version);
    staged.cleanup();
    r
}

/// Prüft einen übernommenen Installer (Signatur, Produktname, höhere Version) und startet ihn
/// unbeaufsichtigt. Bei einem Fehler werden die übernommenen Dateien entfernt; der gestartete
/// Installer bleibt bis zum nächsten Update liegen (siehe [`remove_old_installers`]).
#[cfg(windows)]
pub fn install_staged(staged: &Staged, expected_version: Option<&str>) -> Result<Text, Text> {
    let r = win_install(staged, expected_version);
    if r.is_err() {
        staged.cleanup();
    } else {
        let _ = std::fs::remove_file(&staged.sig);
    }
    r
}

#[cfg(windows)]
fn win_install(staged: &Staged, expected_version: Option<&str>) -> Result<Text, Text> {
    use std::os::windows::process::CommandExt;
    let sig = read_source(&staged.sig, MAX_SIG_SIZE)?;
    let sig = String::from_utf8_lossy(&sig);
    let exe = read_source(&staged.deb, MAX_DEB_SIZE)?;
    sign::verify(KeyKind::Update, &exe, sig.trim())
        .map_err(|e| tr!("Das Update ist nicht von Vigil signiert: {}", "The update is not signed by Vigil: {}", e))?;
    drop(exe);

    let (product, version) = pe_version(&staged.deb).ok_or_else(|| {
        tr!("Die Update-Datei ist kein gültiger Installer von Vigil.", "The update file is not a valid Vigil installer.")
    })?;
    if product != "Vigil" {
        return Err(tr!(
            "Die Update-Datei enthält das Programm {} statt {}.",
            "The update file contains the program {} instead of {}.",
            product,
            "Vigil"
        ));
    }
    if let Some(exp) = expected_version {
        if exp != version {
            return Err(tr!("Die Update-Datei hat die Version {}, erwartet war {}.", "The update file has version {}, expected {}.", version, exp));
        }
    }
    let installed = installed_version()?;
    if !version_greater(&version, &installed)? {
        return Err(tr!(
            "Die Version {} ist nicht neuer als die installierte Version {}.",
            "Version {} is not newer than the installed version {}.",
            version,
            installed
        ));
    }
    // Installer unabhängig vom Helfer starten, dann enden. Aus dem Vigil-Dienst heraus muss er
    // dessen Job-Objekt verlassen (sonst endet er mit dem Dienst, den er anhält). Nach der
    // UAC-Abfrage steckt der Helfer dagegen oft in einem Job von Windows, der das Verlassen
    // verbietet (Zugriff verweigert); dann ohne diese Anweisung starten.
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let start = |flags: u32| std::process::Command::new(&staged.deb).args(["/S", "/R"]).creation_flags(flags).spawn();
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    let spawned = match start(base | CREATE_BREAKAWAY_FROM_JOB) {
        Err(e) if e.raw_os_error() == Some(5) => start(base),
        r => r,
    };
    spawned.map_err(|e| tr!("Der Installer von Vigil {} konnte nicht gestartet werden: {}", "Could not start the installer of Vigil {}: {}", version, e))?;
    Ok(tr!(
        "Vigil {} wird installiert. Vigil startet danach neu.",
        "Vigil {} is being installed. Vigil will restart afterwards.",
        version
    ))
}

/// Produktname und Version (`X.Y.Z`) aus den Dateieigenschaften eines Programms.
#[cfg(windows)]
fn pe_version(p: &Path) -> Option<(String, String)> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO};
    let name = crate::win::wide(p.as_os_str());
    let mut handle = 0u32;
    // SAFETY: gültige Zeichenkette
    let size = unsafe { GetFileVersionInfoSizeW(name.as_ptr(), &mut handle) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: Puffer der gemeldeten Größe
    if unsafe { GetFileVersionInfoW(name.as_ptr(), 0, size, buf.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let query = |sub: &str| -> Option<(*mut core::ffi::c_void, u32)> {
        let w = crate::win::wide(std::ffi::OsStr::new(sub));
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: Puffer aus GetFileVersionInfoW
        let ok = unsafe { VerQueryValueW(buf.as_ptr().cast(), w.as_ptr(), &mut ptr, &mut len) };
        (ok != 0 && !ptr.is_null() && len > 0).then_some((ptr, len))
    };
    let (fixed, _) = query("\\")?;
    // SAFETY: VerQueryValueW liefert für "\" eine VS_FIXEDFILEINFO
    let fixed = unsafe { &*(fixed as *const VS_FIXEDFILEINFO) };
    let ms = fixed.dwProductVersionMS;
    let ls = fixed.dwProductVersionLS;
    let version = format!("{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16);
    let (tr_ptr, tr_len) = query("\\VarFileInfo\\Translation")?;
    if tr_len < 4 {
        return None;
    }
    // SAFETY: mindestens ein Paar aus Sprache und Codepage
    let (lang, cp) = unsafe { (*(tr_ptr as *const u16), *(tr_ptr as *const u16).add(1)) };
    let (pn, pn_len) = query(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\ProductName"))?;
    // SAFETY: Zeichenkette der gemeldeten Länge (in Zeichen, mit Nullzeichen)
    let chars = unsafe { std::slice::from_raw_parts(pn as *const u16, pn_len as usize) };
    let product = String::from_utf16_lossy(chars).trim_end_matches('\0').trim().to_string();
    Some((product, version))
}

#[cfg(unix)]
fn install_inner(staged: &Staged, expected_version: Option<&str>) -> Result<Text, Text> {
    // Signatur über die Bytes der Kopie im Update-Ordner
    let sig = read_source(&staged.sig, MAX_SIG_SIZE)?;
    let sig = String::from_utf8_lossy(&sig);
    let deb = read_source(&staged.deb, MAX_DEB_SIZE)?;
    sign::verify(KeyKind::Update, &deb, sig.trim())
        .map_err(|e| tr!("Das Update ist nicht von Vigil signiert: {}", "The update is not signed by Vigil: {}", e))?;
    drop(deb);

    // Paketname und Version aus der .deb
    let t = Duration::from_secs(60);
    let deb_path = staged.deb.to_string_lossy().into_owned();
    let fields = cmd::run_named("dpkg-deb", &["-f", &deb_path, "Package", "Version"], t)?;
    if !fields.success() {
        return Err(tr!(
            "Die Update-Datei ist kein gültiges Debian-Paket: {}",
            "The update file is not a valid Debian package: {}",
            fields.error_text()
        ));
    }
    let field = |name: &str| {
        fields
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':')).map(|v| v.trim().to_string()))
            .unwrap_or_default()
    };
    let (package, version) = (field("Package"), field("Version"));
    if package != PACKAGE {
        return Err(tr!(
            "Die Update-Datei enthält das Paket {} statt {}.",
            "The update file contains the package {} instead of {}.",
            package,
            PACKAGE
        ));
    }
    let valid = version.starts_with(|c: char| c.is_ascii_digit())
        && version.chars().all(|c| c.is_ascii_alphanumeric() || ".+~-:".contains(c));
    if !valid {
        return Err(tr!("Die Version der Update-Datei ist ungültig: {}", "The version of the update file is invalid: {}", version));
    }
    if let Some(exp) = expected_version {
        if exp != version {
            return Err(tr!(
                "Die Update-Datei hat die Version {}, erwartet war {}.",
                "The update file has version {}, expected {}.",
                version,
                exp
            ));
        }
    }

    // Nur höhere Versionen als die installierte
    let installed = installed_version()?;
    if !version_greater(&version, &installed)? {
        return Err(tr!(
            "Die Version {} ist nicht neuer als die installierte Version {}.",
            "Version {} is not newer than the installed version {}.",
            version,
            installed
        ));
    }

    // Installation (ohne Rückfragen, ohne Empfehlungen)
    let out = cmd::run_env(
        Path::new("/usr/bin/apt-get"),
        &["install", "-y", "--no-install-recommends", &deb_path],
        &[("DEBIAN_FRONTEND", "noninteractive")],
        Duration::from_secs(30 * 60),
    )?;
    if !out.success() {
        return Err(tr!(
            "Die Installation von Vigil {} ist fehlgeschlagen: {}",
            "Installing Vigil {} failed: {}",
            version,
            out.error_text()
        ));
    }
    Ok(tr!("Vigil {} wurde installiert.", "Vigil {} has been installed.", version))
}

/// Installierte Version: unter Windows die Version dieses Programms (App, Helfer und Dienst
/// werden immer gemeinsam installiert).
#[cfg(windows)]
pub fn installed_version() -> Result<String, Text> {
    Ok(crate::VERSION.to_string())
}

/// Ist `a` höher als `b` (Vergleich der Zahlen X.Y.Z)?
#[cfg(windows)]
pub fn version_greater(a: &str, b: &str) -> Result<bool, Text> {
    match (sign::parse_version(a), sign::parse_version(b)) {
        (Some(x), Some(y)) => Ok(x > y),
        _ => Err(tr!("Der Versionsvergleich ist fehlgeschlagen: {} / {}", "The version comparison failed: {} / {}", a, b)),
    }
}

/// Installierte Version des Pakets (`dpkg-query -W -f '${Version}' vigil`).
#[cfg(unix)]
pub fn installed_version() -> Result<String, Text> {
    let out = cmd::run_named("dpkg-query", &["-W", "-f", "${Version}", PACKAGE], Duration::from_secs(60))?;
    let v = out.stdout.trim().to_string();
    if !out.success() || v.is_empty() {
        return Err(tr!(
            "Die installierte Version von Vigil ist nicht ermittelbar: {}",
            "Could not determine the installed version of Vigil: {}",
            out.error_text()
        ));
    }
    Ok(v)
}

/// Ist `a` höher als `b` (Debian-Versionsvergleich über `dpkg --compare-versions`)?
#[cfg(unix)]
pub fn version_greater(a: &str, b: &str) -> Result<bool, Text> {
    let out = cmd::run_named("dpkg", &["--compare-versions", a, "gt", b], Duration::from_secs(30))?;
    match out.code {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(tr!("Der Versionsvergleich ist fehlgeschlagen: {}", "The version comparison failed: {}", out.error_text())),
    }
}
