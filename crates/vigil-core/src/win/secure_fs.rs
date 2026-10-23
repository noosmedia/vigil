//! Sichere Dateioperationen unter Windows (Gegenstück zu `secure_fs.rs` unter Linux).
//!
//! Schutz gegen umgelenkte Pfade: Kein Pfadteil darf eine symbolische Verknüpfung oder
//! Abzweigung (Junction) sein. Der Zielordner bleibt während der Maßnahme geöffnet (ohne
//! Freigabe zum Löschen oder Umbenennen), und nach jedem Öffnen wird der tatsächliche Pfad des
//! Handles (`GetFinalPathNameByHandleW`) mit dem erwarteten verglichen. Gelöscht wird über das
//! Handle der geprüften Datei, nachdem Laufwerk und Dateinummer verglichen wurden. So kann
//! niemand zwischen Prüfung und Maßnahme eine andere Datei unterschieben.

use crate::i18n::Text;
use crate::tr;
use crate::win::{eq_ci, strip_verbatim, wide};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, FileDispositionInfo, FileDispositionInfoEx, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, MoveFileExW, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
};

/// Ordner nicht über Verknüpfungen öffnen, Ordner überhaupt öffnen können.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;
const DELETE: u32 = 0x0001_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const GENERIC_READ: u32 = 0x8000_0000;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// FileDispositionInfoEx: löschen, sofort aus dem Ordner entfernen, Schreibschutz ignorieren.
const FILE_DISPOSITION_FLAG_DELETE: u32 = 0x1;
const FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: u32 = 0x2;
const FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE: u32 = 0x10;

/// Ein sicher geöffneter Ordner. Das Handle hält den Ordner fest (er lässt sich währenddessen
/// weder löschen noch umbenennen).
pub struct Dir {
    path: PathBuf,
    _handle: File,
}

/// Kennung einer geprüften Datei: Größe, Laufwerk und Dateinummer.
#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub size: u64,
    volume: u32,
    index: u64,
}

fn attr_tag(f: &File) -> std::io::Result<(u32, u32)> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO { FileAttributes: 0, ReparseTag: 0 };
    // SAFETY: Puffer passend zur Abfrage, gültiges Handle
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((info.FileAttributes, info.ReparseTag))
}

/// Ist das geöffnete Objekt eine Verknüpfung oder Abzweigung?
fn is_link(attrs: u32, tag: u32) -> bool {
    attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && (tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT)
}

/// Tatsächlicher Pfad eines Handles (ohne `\\?\`).
fn final_path(f: &File) -> std::io::Result<PathBuf> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: Puffer mit Länge, gültiges Handle
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle(), buf.as_mut_ptr(), buf.len() as u32, 0) } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n < buf.len() {
            return Ok(strip_verbatim(Path::new(&OsString::from_wide(&buf[..n]))));
        }
        buf.resize(n + 1, 0);
    }
}

fn file_info(f: &File) -> std::io::Result<Stat> {
    // SAFETY: Struktur wird vollständig beschrieben
    let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut i) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Stat {
        size: ((i.nFileSizeHigh as u64) << 32) | i.nFileSizeLow as u64,
        volume: i.dwVolumeSerialNumber,
        index: ((i.nFileIndexHigh as u64) << 32) | i.nFileIndexLow as u64,
    })
}

/// Öffnet einen Eintrag ohne Verfolgen einer Verknüpfung (nur Attribute lesbar).
fn open_entry(p: &Path, access: u32, share: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)
}

/// Öffnet einen Ordner sicher: Kein Pfadteil darf eine Verknüpfung oder Abzweigung sein, und
/// der tatsächliche Pfad muss dem angegebenen entsprechen.
pub fn open_dir_secure(path: &Path) -> Result<Dir, Text> {
    let path = strip_verbatim(path);
    if !path.is_absolute() {
        return Err(tr!("Der Pfad muss absolut sein: {}", "The path must be absolute: {}", path.display()));
    }
    let err = |e: std::io::Error| {
        tr!("Der Ordner {} kann nicht sicher geöffnet werden: {}", "The folder {} cannot be opened safely: {}", path.display(), e)
    };
    if path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return Err(tr!("Ungültiger Dateipfad: {}", "Invalid file path: {}", path.display()));
    }
    // Jeden Pfadteil einzeln prüfen (ab dem ersten Ordner unter dem Laufwerk)
    let mut cur = PathBuf::new();
    for c in path.components() {
        cur.push(c.as_os_str());
        if !matches!(c, Component::Normal(_)) {
            continue;
        }
        let f = open_entry(&cur, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).map_err(err)?;
        let (attrs, tag) = attr_tag(&f).map_err(err)?;
        if is_link(attrs, tag) {
            return Err(tr!(
                "Der Pfad {} enthält eine Verknüpfung ({}). Aus Sicherheitsgründen wird abgebrochen.",
                "The path {} contains a link ({}). Stopping for security reasons.",
                path.display(),
                c.as_os_str().to_string_lossy()
            ));
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(tr!("{} ist kein Ordner.", "{} is not a folder.", path.display()));
        }
    }
    // Zielordner festhalten: ohne Freigabe zum Löschen lässt er sich nicht mehr umbenennen
    let handle = open_entry(&path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE).map_err(err)?;
    let (attrs, tag) = attr_tag(&handle).map_err(err)?;
    if is_link(attrs, tag) || attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(tr!("{} ist kein Ordner.", "{} is not a folder.", path.display()));
    }
    let real = final_path(&handle).map_err(err)?;
    if !eq_ci(&real, &path) {
        return Err(tr!(
            "Der Ordner {} führt tatsächlich nach {}. Aus Sicherheitsgründen wird abgebrochen.",
            "The folder {} actually leads to {}. Stopping for security reasons.",
            path.display(),
            real.display()
        ));
    }
    Ok(Dir { path, _handle: handle })
}

/// Zerlegt einen absoluten Dateipfad in Elternordner (sicher geöffnet) und Dateiname.
pub fn split_secure(path: &Path) -> Result<(Dir, OsString), Text> {
    let invalid = || tr!("Ungültiger Dateipfad: {}", "Invalid file path: {}", path.display());
    let path = strip_verbatim(path);
    let name = match path.components().next_back() {
        Some(Component::Normal(n)) => n.to_os_string(),
        _ => return Err(invalid()),
    };
    let parent = path.parent().ok_or_else(invalid)?;
    Ok((open_dir_secure(parent)?, name))
}

/// Prüft, dass ein geöffnetes Objekt tatsächlich `dir\name` ist.
fn check_location(f: &File, dir: &Dir, name: &OsStr) -> Result<(), Text> {
    let expected = dir.path.join(name);
    let real = final_path(f).map_err(|e| tr!("Die Datei ist nicht lesbar: {}", "The file is not readable: {}", e))?;
    if !eq_ci(&real, &expected) {
        return Err(tr!(
            "Die Datei {} führt tatsächlich nach {}. Aus Sicherheitsgründen wird abgebrochen.",
            "The file {} actually leads to {}. Stopping for security reasons.",
            expected.display(),
            real.display()
        ));
    }
    Ok(())
}

/// Öffnet eine reguläre Datei im Ordner zum Lesen (ohne Verfolgen von Verknüpfungen).
pub fn open_file_in(dir: &Dir, name: &OsStr) -> Result<(File, Stat), Text> {
    let n = name.to_string_lossy();
    let p = dir.path.join(name);
    let f = OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&p)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => tr!("Die Datei existiert nicht mehr.", "The file no longer exists."),
            _ => tr!("Die Datei {} konnte nicht geöffnet werden: {}", "Could not open the file {}: {}", n, e),
        })?;
    let (attrs, tag) = attr_tag(&f).map_err(|e| tr!("Die Datei ist nicht lesbar: {}", "The file is not readable: {}", e))?;
    if is_link(attrs, tag) {
        return Err(tr!(
            "{} ist eine symbolische Verknüpfung und wird nicht angefasst.",
            "{} is a symbolic link and will not be touched.",
            n
        ));
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(tr!("{} ist keine reguläre Datei.", "{} is not a regular file.", n));
    }
    check_location(&f, dir, name)?;
    let st = file_info(&f).map_err(|e| tr!("Die Datei ist nicht lesbar: {}", "The file is not readable: {}", e))?;
    Ok((f, st))
}

/// Größe einer geprüften Datei.
pub fn stat_size(st: &Stat) -> u64 {
    st.size
}

/// Löscht `name` im Ordner, aber nur, wenn es noch genau die geprüfte Datei ist (Laufwerk und
/// Dateinummer). Gelöscht wird über das Handle, das verglichen wurde.
pub fn unlink_verified(dir: &Dir, name: &OsStr, expect: &Stat) -> Result<(), Text> {
    let n = name.to_string_lossy();
    let f = open_entry(&dir.path.join(name), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .map_err(|e| tr!("Die Datei {} ist nicht mehr vorhanden: {}", "The file {} no longer exists: {}", n, e))?;
    let st = file_info(&f).map_err(|e| tr!("Die Datei {} ist nicht mehr vorhanden: {}", "The file {} no longer exists: {}", n, e))?;
    if st.volume != expect.volume || st.index != expect.index {
        return Err(tr!(
            "Die Datei {} wurde während der Maßnahme ausgetauscht. Aus Sicherheitsgründen wird abgebrochen.",
            "The file {} was replaced during the action. Stopping for security reasons.",
            n
        ));
    }
    check_location(&f, dir, name)?;
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: gültiges Handle mit DELETE-Recht, Struktur passend zur Klasse
    let mut ok = unsafe {
        SetFileInformationByHandle(
            f.as_raw_handle(),
            FileDispositionInfoEx,
            (&ex as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } != 0;
    if !ok {
        // Ältere Dateisysteme (z. B. FAT) kennen nur die einfache Form
        let simple = FILE_DISPOSITION_INFO { DeleteFile: true };
        ok = unsafe {
            SetFileInformationByHandle(
                f.as_raw_handle(),
                FileDispositionInfo,
                (&simple as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } != 0;
    }
    if !ok {
        let e = std::io::Error::last_os_error();
        return Err(tr!("Die Datei {} konnte nicht entfernt werden: {}", "Could not remove the file {}: {}", n, e));
    }
    Ok(())
}

/// Legt eine neue Datei exklusiv im Ordner an (scheitert, wenn der Name existiert). Unter
/// Windows erbt sie die Rechte des Ordners; `mode` gilt nicht.
pub fn create_excl_in(dir: &Dir, name: &OsStr, _mode: u32) -> std::io::Result<File> {
    let p = dir.path.join(name);
    let f = OpenOptions::new().write(true).read(true).create_new(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&p)?;
    if check_location(&f, dir, name).is_err() {
        drop(f);
        let _ = std::fs::remove_file(&p);
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "redirected path"));
    }
    Ok(f)
}

/// Existiert `name` im Ordner (ohne Verknüpfungen zu verfolgen)?
pub fn exists_in(dir: &Dir, name: &OsStr) -> bool {
    std::fs::symlink_metadata(dir.path.join(name)).is_ok()
}

/// Entfernt `name` im Ordner ohne Prüfung (für eigene temporäre Dateien).
pub fn unlink_in(dir: &Dir, name: &OsStr) {
    let _ = std::fs::remove_file(dir.path.join(name));
}

/// Benennt `from` in `to` um, ohne ein vorhandenes Ziel zu überschreiben
/// (Fehlerart `AlreadyExists`, wenn das Ziel existiert).
pub fn rename_noreplace(dir: &Dir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    let f = wide(dir.path.join(from).as_os_str());
    let t = wide(dir.path.join(to).as_os_str());
    // SAFETY: gültige Zeichenketten; ohne MOVEFILE_REPLACE_EXISTING scheitert es bei vorhandenem Ziel
    if unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Bringt Änderungen im Ordner auf die Platte. Unter Windows nicht nötig (NTFS schreibt die
/// Metadaten selbst), daher leer.
pub fn sync_dir(_dir: &Dir) {}
