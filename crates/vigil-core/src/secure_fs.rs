//! Sichere Dateioperationen für root: Ordner werden Stück für Stück ohne Verfolgen
//! fremder symbolischer Verknüpfungen geöffnet, Dateien über Ordner-Deskriptoren
//! angesprochen. So kann niemand während einer Maßnahme Pfadteile austauschen
//! und root auf eine andere Datei umlenken.

use crate::i18n::Text;
use crate::tr;
use std::collections::VecDeque;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

/// Sicher geöffneter Ordner (Ordner-Deskriptor).
pub type Dir = OwnedFd;
/// Kennung einer geprüften Datei (Gerät, Inode, Größe, Besitzer, Rechte).
pub type Stat = libc::stat;

/// Größe einer geprüften Datei.
pub fn stat_size(st: &Stat) -> u64 {
    st.st_size as u64
}

/// fsync auf einen geöffneten Ordner.
pub fn sync_dir(dir: &Dir) {
    // SAFETY: gültiger Deskriptor
    unsafe { libc::fsync(dir.as_raw_fd()) };
}

fn cstr(s: &OsStr) -> Result<CString, Text> {
    CString::new(s.as_bytes()).map_err(|_| tr!("Ungültiges Zeichen im Pfad.", "Invalid character in the path."))
}

fn last_err() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn fstat_fd(fd: libc::c_int) -> std::io::Result<libc::stat> {
    // SAFETY: stat wird vollständig von fstat beschrieben
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(last_err());
    }
    Ok(st)
}

fn openat_raw(dir: libc::c_int, name: &CString, flags: libc::c_int, mode: libc::mode_t) -> std::io::Result<OwnedFd> {
    // SAFETY: gültige Zeichenkette und Deskriptor; Rückgabewert wird geprüft
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) };
    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: frisch geöffneter, eigener Deskriptor
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Öffnet einen Ordner sicher. Symbolische Verknüpfungen in Pfadteilen werden nur
/// verfolgt, wenn sie root gehören (oder im Testbetrieb dem eigenen Benutzer).
pub fn open_dir_secure(path: &Path) -> Result<OwnedFd, Text> {
    if !path.is_absolute() {
        return Err(tr!("Der Pfad muss absolut sein: {}", "The path must be absolute: {}", path.display()));
    }
    let err = |e: std::io::Error| {
        tr!("Der Ordner {} kann nicht sicher geöffnet werden: {}", "The folder {} cannot be opened safely: {}", path.display(), e)
    };
    let root = CString::new("/").unwrap();
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let mut cur = openat_raw(libc::AT_FDCWD, &root, dir_flags, 0).map_err(err)?;
    // SAFETY: geteuid hat keine Vorbedingungen
    let euid = unsafe { libc::geteuid() };

    let mut queue: VecDeque<OsString> = VecDeque::new();
    push_components(&mut queue, path, false);
    let mut links = 0;

    while let Some(comp) = queue.pop_front() {
        if comp == "/" {
            cur = openat_raw(libc::AT_FDCWD, &root, dir_flags, 0).map_err(err)?;
            continue;
        }
        let name = cstr(&comp)?;
        if comp == ".." {
            cur = openat_raw(cur.as_raw_fd(), &name, dir_flags, 0).map_err(err)?;
            continue;
        }
        // Erst nur den Eintrag selbst öffnen (O_PATH), dann Art prüfen
        let entry = openat_raw(cur.as_raw_fd(), &name, libc::O_PATH | libc::O_NOFOLLOW, 0).map_err(err)?;
        let st = fstat_fd(entry.as_raw_fd()).map_err(err)?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let dot = CString::new(".").unwrap();
                cur = openat_raw(entry.as_raw_fd(), &dot, dir_flags, 0).map_err(err)?;
            }
            libc::S_IFLNK => {
                links += 1;
                if links > 40 {
                    return Err(tr!("Zu viele symbolische Verknüpfungen in {}.", "Too many symbolic links in {}.", path.display()));
                }
                if st.st_uid != 0 && st.st_uid != euid {
                    return Err(tr!(
                        "Der Pfad {} enthält eine symbolische Verknüpfung eines anderen Benutzers ({}). Aus Sicherheitsgründen wird abgebrochen.",
                        "The path {} contains a symbolic link owned by another user ({}). Stopping for security reasons.",
                        path.display(),
                        comp.to_string_lossy()
                    ));
                }
                let target = readlink_fd(&entry).map_err(err)?;
                push_components(&mut queue, Path::new(&target), true);
            }
            _ => return Err(tr!("{} ist kein Ordner.", "{} is not a folder.", path.display())),
        }
    }
    Ok(cur)
}

/// Zerlegt einen Pfad in Bestandteile. Absolute Pfade beginnen mit "/".
fn push_components(queue: &mut VecDeque<OsString>, p: &Path, front: bool) {
    let mut parts: Vec<OsString> = Vec::new();
    for c in p.components() {
        match c {
            Component::RootDir => parts.push(OsString::from("/")),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => parts.push(OsString::from("..")),
            Component::Normal(n) => parts.push(n.to_os_string()),
        }
    }
    if front {
        for part in parts.into_iter().rev() {
            queue.push_front(part);
        }
    } else {
        queue.extend(parts);
    }
}

fn readlink_fd(fd: &OwnedFd) -> std::io::Result<OsString> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let empty = CString::new("").unwrap();
    // SAFETY: Puffer ausreichend groß, Länge wird geprüft
    let n = unsafe { libc::readlinkat(fd.as_raw_fd(), empty.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if n < 0 {
        return Err(last_err());
    }
    buf.truncate(n as usize);
    Ok(std::ffi::OsStr::from_bytes(&buf).to_os_string())
}

/// Zerlegt einen absoluten Dateipfad in Elternordner (sicher geöffnet) und Dateiname.
pub fn split_secure(path: &Path) -> Result<(OwnedFd, OsString), Text> {
    let invalid = || tr!("Ungültiger Dateipfad: {}", "Invalid file path: {}", path.display());
    let name = match path.components().next_back() {
        Some(Component::Normal(n)) => n.to_os_string(),
        _ => return Err(invalid()),
    };
    let parent = path.parent().ok_or_else(invalid)?;
    Ok((open_dir_secure(parent)?, name))
}

/// Öffnet eine reguläre Datei im Ordner zum Lesen (ohne Verfolgen von Verknüpfungen).
pub fn open_file_in(dir: &OwnedFd, name: &OsStr) -> Result<(File, libc::stat), Text> {
    let c = cstr(name)?;
    let base = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let fd = match openat_raw(dir.as_raw_fd(), &c, base | libc::O_NOATIME, 0) {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => openat_raw(dir.as_raw_fd(), &c, base, 0),
        r => r,
    };
    let n = name.to_string_lossy();
    let fd = fd.map_err(|e| match e.raw_os_error() {
        Some(libc::ELOOP) => tr!(
            "{} ist eine symbolische Verknüpfung und wird nicht angefasst.",
            "{} is a symbolic link and will not be touched.",
            n
        ),
        Some(libc::ENOENT) => tr!("Die Datei existiert nicht mehr.", "The file no longer exists."),
        _ => tr!("Die Datei {} konnte nicht geöffnet werden: {}", "Could not open the file {}: {}", n, e),
    })?;
    let st = fstat_fd(fd.as_raw_fd()).map_err(|e| tr!("Die Datei ist nicht lesbar: {}", "The file is not readable: {}", e))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(tr!("{} ist keine reguläre Datei.", "{} is not a regular file.", n));
    }
    Ok((File::from(fd), st))
}

/// Löscht `name` im Ordner, aber nur, wenn es noch genau die geprüfte Datei ist (Gerät und Inode).
pub fn unlink_verified(dir: &OwnedFd, name: &OsStr, expect: &libc::stat) -> Result<(), Text> {
    let c = cstr(name)?;
    let n = name.to_string_lossy();
    // SAFETY: stat wird vollständig von fstatat beschrieben
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let e = last_err();
        return Err(tr!("Die Datei {} ist nicht mehr vorhanden: {}", "The file {} no longer exists: {}", n, e));
    }
    if st.st_dev != expect.st_dev || st.st_ino != expect.st_ino {
        return Err(tr!(
            "Die Datei {} wurde während der Maßnahme ausgetauscht. Aus Sicherheitsgründen wird abgebrochen.",
            "The file {} was replaced during the action. Stopping for security reasons.",
            n
        ));
    }
    // SAFETY: gültiger Ordner-Deskriptor und Name
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        let e = last_err();
        return Err(tr!("Die Datei {} konnte nicht entfernt werden: {}", "Could not remove the file {}: {}", n, e));
    }
    // SAFETY: gültiger Deskriptor
    unsafe { libc::fsync(dir.as_raw_fd()) };
    Ok(())
}

/// Legt eine neue Datei exklusiv im Ordner an (scheitert, wenn der Name existiert).
pub fn create_excl_in(dir: &OwnedFd, name: &OsStr, mode: u32) -> std::io::Result<File> {
    let c = CString::new(name.as_bytes()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let fd = openat_raw(
        dir.as_raw_fd(),
        &c,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        mode as libc::mode_t,
    )?;
    Ok(File::from(fd))
}

/// Existiert `name` im Ordner (ohne Verknüpfungen zu verfolgen)?
pub fn exists_in(dir: &OwnedFd, name: &OsStr) -> bool {
    let Ok(c) = cstr(name) else { return false };
    // SAFETY: stat wird vollständig von fstatat beschrieben
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0 }
}

/// Entfernt `name` im Ordner ohne Prüfung (für eigene temporäre Dateien).
pub fn unlink_in(dir: &OwnedFd, name: &OsStr) {
    if let Ok(c) = cstr(name) {
        // SAFETY: gültiger Ordner-Deskriptor und Name
        unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
    }
}

/// Benennt `from` in `to` um, ohne ein vorhandenes Ziel zu überschreiben.
pub fn rename_noreplace(dir: &OwnedFd, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    let f = CString::new(from.as_bytes()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let t = CString::new(to.as_bytes()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let fd = dir.as_raw_fd();
    // SAFETY: gültige Deskriptoren und Zeichenketten
    let r = unsafe { libc::renameat2(fd, f.as_ptr(), fd, t.as_ptr(), libc::RENAME_NOREPLACE) };
    if r == 0 {
        return Ok(());
    }
    let e = last_err();
    match e.raw_os_error() {
        // Dateisystem kann RENAME_NOREPLACE nicht: harter Link (scheitert bei vorhandenem Ziel)
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
            // SAFETY: wie oben
            if unsafe { libc::linkat(fd, f.as_ptr(), fd, t.as_ptr(), 0) } == 0 {
                unsafe { libc::unlinkat(fd, f.as_ptr(), 0) };
                return Ok(());
            }
            let le = last_err();
            if le.raw_os_error() == Some(libc::EEXIST) {
                return Err(le);
            }
            // Letzter Weg (z. B. FAT): vorher prüfen, dann normal umbenennen
            if exists_in(dir, to) {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
            }
            if unsafe { libc::renameat(fd, f.as_ptr(), fd, t.as_ptr()) } == 0 {
                Ok(())
            } else {
                Err(last_err())
            }
        }
        _ => Err(e),
    }
}
