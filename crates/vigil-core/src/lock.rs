//! Sperren über flock: `job.lock` (nur ein Auftrag gleichzeitig) und `data.lock`
//! (kurze Sperre für Änderungen an quarantine.json, Berichten und config.json).
//! Unter Windows über die Dateisperren der Standardbibliothek (LockFileEx).

use crate::i18n::Text;
use crate::paths;
use crate::tr;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Gehaltene Sperre. Wird beim Verwerfen automatisch freigegeben.
pub struct FileLock {
    _file: File,
}

/// Ergebnis eines Sperrversuchs.
pub enum TryLock {
    Acquired(FileLock),
    Busy,
}

#[cfg(unix)]
fn open_lock_file(path: &Path, write: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if write {
        o.write(true).create(true).mode(0o644);
    }
    o.open(path)
}

/// Unter Windows ohne Verfolgen einer Verknüpfung am Ende (FILE_FLAG_OPEN_REPARSE_POINT).
#[cfg(windows)]
fn open_lock_file(path: &Path, write: bool) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut o = OpenOptions::new();
    o.read(true).custom_flags(0x0020_0000);
    if write {
        o.write(true).create(true);
    }
    let f = o.open(path)?;
    if f.metadata()?.file_type().is_symlink() {
        return Err(std::io::Error::other("symbolic link"));
    }
    Ok(f)
}

/// Exklusive Sperre; mit `wait` wird gewartet. `Ok(false)`, wenn ohne Warten belegt.
#[cfg(windows)]
fn lock_exclusive(file: &File, wait: bool) -> std::io::Result<bool> {
    if wait {
        return file.lock().map(|_| true);
    }
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(unix)]
fn flock(file: &File, op: libc::c_int) -> std::io::Result<()> {
    loop {
        // SAFETY: gültiger Dateideskriptor, flock ändert keinen Speicher
        let r = unsafe { libc::flock(file.as_raw_fd(), op) };
        if r == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(e);
    }
}

fn open_err(path: &Path, e: std::io::Error) -> Text {
    tr!("Die Sperrdatei {} konnte nicht geöffnet werden: {}", "Could not open the lock file {}: {}", path.display(), e)
}

fn lock_err(path: &Path, e: std::io::Error) -> Text {
    tr!("Die Sperre {} konnte nicht gesetzt werden: {}", "Could not acquire the lock {}: {}", path.display(), e)
}

/// Versucht, eine Sperrdatei zu übernehmen, ohne zu warten.
#[cfg(windows)]
fn try_lock(path: &Path) -> Result<TryLock, Text> {
    let file = open_lock_file(path, true).map_err(|e| open_err(path, e))?;
    match lock_exclusive(&file, false) {
        Ok(true) => Ok(TryLock::Acquired(FileLock { _file: file })),
        Ok(false) => Ok(TryLock::Busy),
        Err(e) => Err(lock_err(path, e)),
    }
}

/// Versucht, eine Sperrdatei zu übernehmen, ohne zu warten.
#[cfg(unix)]
fn try_lock(path: &Path) -> Result<TryLock, Text> {
    let file = open_lock_file(path, true).map_err(|e| open_err(path, e))?;
    match flock(&file, libc::LOCK_EX | libc::LOCK_NB) {
        Ok(()) => Ok(TryLock::Acquired(FileLock { _file: file })),
        Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => Ok(TryLock::Busy),
        Err(e) => Err(lock_err(path, e)),
    }
}

/// Versucht, `job.lock` zu übernehmen, ohne zu warten.
pub fn try_job_lock() -> Result<TryLock, Text> {
    try_lock(&paths::lock_path())
}

/// Versucht, `/var/lib/vigil/updates/update.lock` zu übernehmen (nur ein Update von Vigil gleichzeitig).
pub fn try_update_lock() -> Result<TryLock, Text> {
    crate::fsutil::ensure_dir(&paths::updates_dir(), 0o700)?;
    try_lock(&paths::updates_dir().join("update.lock"))
}

/// Sperre `/var/lib/vigil/extra-sigs/run.lock` (nur ein Abruf oder Entfernen der zusätzlichen
/// Signaturen gleichzeitig). Mit `wait` wird gewartet, sonst sofort `Busy` gemeldet.
pub fn extra_lock(wait: bool) -> Result<TryLock, Text> {
    crate::fsutil::ensure_dir(&paths::extra_sigs_dir(), 0o700)?;
    let path = paths::extra_sigs_dir().join("run.lock");
    if !wait {
        return try_lock(&path);
    }
    let file = open_lock_file(&path, true).map_err(|e| open_err(&path, e))?;
    #[cfg(unix)]
    flock(&file, libc::LOCK_EX).map_err(|e| lock_err(&path, e))?;
    #[cfg(windows)]
    lock_exclusive(&file, true).map_err(|e| lock_err(&path, e))?;
    Ok(TryLock::Acquired(FileLock { _file: file }))
}

/// Wartet auf `data.lock` (kurze Sperre für Lesen-Ändern-Schreiben).
pub fn data_lock() -> Result<FileLock, Text> {
    let path = paths::data_lock_path();
    let file = open_lock_file(&path, true).map_err(|e| open_err(&path, e))?;
    #[cfg(unix)]
    flock(&file, libc::LOCK_EX).map_err(|e| lock_err(&path, e))?;
    #[cfg(windows)]
    lock_exclusive(&file, true).map_err(|e| lock_err(&path, e))?;
    Ok(FileLock { _file: file })
}

/// Läuft gerade ein Auftrag? Funktioniert auch ohne Schreibrechte (für die App).
/// Damit lässt sich ein veralteter Zustand in state.json erkennen (z. B. nach einem Absturz).
#[cfg(unix)]
pub fn is_job_running() -> bool {
    let Ok(file) = open_lock_file(&paths::lock_path(), false) else {
        return false;
    };
    match flock(&file, libc::LOCK_SH | libc::LOCK_NB) {
        Ok(()) => false,
        Err(e) => e.raw_os_error() == Some(libc::EWOULDBLOCK),
    }
}

/// Läuft gerade ein Auftrag? Funktioniert auch ohne Schreibrechte (für die App).
#[cfg(windows)]
pub fn is_job_running() -> bool {
    let Ok(file) = open_lock_file(&paths::lock_path(), false) else {
        return false;
    };
    matches!(file.try_lock_shared(), Err(std::fs::TryLockError::WouldBlock))
}
