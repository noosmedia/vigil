//! Dateihilfen: atomares Schreiben, JSON lesen/schreiben, Ordner anlegen, sha256.

use crate::i18n::Text;
use crate::tr;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Schreibt eine Datei atomar: temporäre Datei im selben Ordner, fsync, rename, fsync des Ordners.
/// `mode` sind die Rechte der Zieldatei (z. B. 0o644). Unter Windows erbt die Datei die Rechte
/// ihres Ordners, `mode` gilt dort nicht.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), Text> {
    let dir = path
        .parent()
        .ok_or_else(|| tr!("Ungültiger Dateipfad: {}", "Invalid file path: {}", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| tr!("Ungültiger Dateipfad: {}", "Invalid file path: {}", path.display()))?
        .to_string_lossy();
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{}",
        name,
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    // Temporäre Datei exklusiv anlegen, schreiben und auf die Platte bringen
    #[cfg(unix)]
    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(data)?;
        // Rechte unabhängig von der umask setzen
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    #[cfg(windows)]
    let result = {
        let _ = mode;
        (|| -> std::io::Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            rename_retry(&tmp, path)
        })()
    };
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(tr!("Die Datei {} konnte nicht geschrieben werden: {}", "Could not write the file {}: {}", path.display(), e));
    }
    sync_dir(dir);
    Ok(())
}

/// Ersetzt `to` durch `from`. Unter Windows kann das Ziel kurz von einem Leser (App, Indexdienst,
/// Virenschutz) belegt sein; dann wird bis zu 2 s lang erneut versucht.
#[cfg(windows)]
fn rename_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for _ in 0..40 {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::PermissionDenied || e.raw_os_error() == Some(32) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::from(ErrorKind::PermissionDenied)))
}

/// Schreibt einen Wert als JSON atomar.
pub fn write_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), Text> {
    let mut data = serde_json::to_vec_pretty(value).map_err(|e| {
        tr!("Daten für {} konnten nicht umgewandelt werden: {}", "Could not serialize data for {}: {}", path.display(), e)
    })?;
    data.push(b'\n');
    write_atomic(path, &data, mode)
}

/// Liest JSON. `Ok(None)`, wenn die Datei fehlt.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, Text> {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(tr!("Die Datei {} konnte nicht gelesen werden: {}", "Could not read the file {}: {}", path.display(), e))
        }
    };
    serde_json::from_slice(&data)
        .map(Some)
        .map_err(|e| tr!("Die Datei {} ist beschädigt: {}", "The file {} is damaged: {}", path.display(), e))
}

/// Legt einen Ordner an (samt Elternordnern) und setzt seine Rechte. Unter Windows bekommt ein
/// neu angelegter Ordner feste Zugriffsrechte (siehe [`crate::win::set_dir_acl`]): bei `mode`
/// mit Leserecht für andere (z. B. 0o755) dürfen alle Benutzer lesen, sonst nur SYSTEM und
/// Administratoren (z. B. 0o700). Im Testbetrieb bleiben die Rechte unter Windows unverändert.
#[cfg(windows)]
pub fn ensure_dir(path: &Path, mode: u32) -> Result<(), Text> {
    let existed = fs::symlink_metadata(path).is_ok();
    fs::create_dir_all(path).map_err(|e| {
        tr!("Der Ordner {} konnte nicht angelegt werden: {}", "Could not create the folder {}: {}", path.display(), e)
    })?;
    let meta = fs::symlink_metadata(path)
        .map_err(|e| tr!("Der Ordner {} ist nicht lesbar: {}", "The folder {} is not readable: {}", path.display(), e))?;
    // Verknüpfungen und Abzweigungen (Junctions) gelten nicht als Ordner
    if !meta.is_dir() {
        return Err(tr!("{} ist kein Ordner.", "{} is not a folder.", path.display()));
    }
    if !existed && !crate::paths::is_dev() {
        crate::win::set_dir_acl(path, mode & 0o005 != 0)?;
    }
    Ok(())
}

/// Legt einen Ordner an (samt Elternordnern) und setzt seine Rechte.
#[cfg(unix)]
pub fn ensure_dir(path: &Path, mode: u32) -> Result<(), Text> {
    fs::create_dir_all(path).map_err(|e| {
        tr!("Der Ordner {} konnte nicht angelegt werden: {}", "Could not create the folder {}: {}", path.display(), e)
    })?;
    let meta = fs::symlink_metadata(path)
        .map_err(|e| tr!("Der Ordner {} ist nicht lesbar: {}", "The folder {} is not readable: {}", path.display(), e))?;
    if !meta.is_dir() {
        return Err(tr!("{} ist kein Ordner.", "{} is not a folder.", path.display()));
    }
    if meta.permissions().mode() & 0o7777 != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
            tr!("Die Rechte von {} konnten nicht gesetzt werden: {}", "Could not set the permissions of {}: {}", path.display(), e)
        })?;
    }
    Ok(())
}

/// fsync auf einen Ordner (Fehler werden ignoriert, nicht alle Dateisysteme können das).
pub fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// sha256 eines Lesers als Hex-Text.
pub fn sha256_reader<R: Read>(r: &mut R) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Bytes als Hex-Text (Kleinbuchstaben).
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Prüft, ob ein Text ein sha256 in Hex-Schreibweise ist.
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Übersetzt Betriebssystem-Fehlertexte wie `No such file or directory (os error 2)`
/// in einer Meldung ins Deutsche. Unbekannte Fehler bleiben unverändert.
pub fn localize_os_errors(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(pos) = rest.find("(os error ") {
        let after = &rest[pos + 10..];
        let Some(end) = after.find(')') else { break };
        let german = after[..end].parse::<i32>().ok().and_then(errno_de);
        let before = &rest[..pos];
        // Englischer Text beginnt nach dem letzten ": " vor der Klammer
        let start = before.rfind(": ").map(|i| i + 2).unwrap_or(0);
        match german {
            Some(g) => {
                out.push_str(&before[..start]);
                out.push_str(g);
            }
            None => {
                out.push_str(before);
                out.push_str(&rest[pos..pos + 10 + end + 1]);
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(windows)]
fn errno_de(n: i32) -> Option<&'static str> {
    // Fehlernummern von Windows (GetLastError)
    Some(match n {
        2 => "Datei nicht gefunden",
        3 => "Pfad nicht gefunden",
        5 => "Zugriff verweigert",
        19 => "Datenträger ist schreibgeschützt",
        32 => "Die Datei wird von einem anderen Programm verwendet",
        33 => "Ein Teil der Datei ist von einem anderen Programm gesperrt",
        39 | 112 => "Kein Speicherplatz mehr frei",
        80 | 183 => "Datei existiert bereits",
        87 => "Ungültiges Argument",
        123 => "Ungültiger Datei- oder Ordnername",
        206 => "Dateiname zu lang",
        225 => "Die Datei enthält einen Virus oder unerwünschte Software und wurde von Windows gesperrt",
        1920 => "Auf die Datei kann vom System nicht zugegriffen werden",
        10054 => "Verbindung zurückgesetzt",
        10060 => "Zeitüberschreitung",
        10061 => "Verbindung abgelehnt",
        _ => return None,
    })
}

#[cfg(unix)]
fn errno_de(n: i32) -> Option<&'static str> {
    Some(match n {
        libc::EPERM => "Vorgang nicht erlaubt",
        libc::ENOENT => "Datei oder Ordner nicht gefunden",
        libc::EIO => "Ein-/Ausgabefehler",
        libc::EAGAIN => "Zeitüberschreitung oder Ressource vorübergehend nicht verfügbar",
        libc::EACCES => "Zugriff verweigert",
        libc::EBUSY => "Gerät oder Ressource belegt",
        libc::EEXIST => "Datei existiert bereits",
        libc::ENOTDIR => "Ist kein Ordner",
        libc::EISDIR => "Ist ein Ordner",
        libc::EINVAL => "Ungültiges Argument",
        libc::ENOSPC => "Kein Speicherplatz mehr frei",
        libc::EROFS => "Dateisystem ist schreibgeschützt",
        libc::EPIPE => "Verbindung unterbrochen",
        libc::ENAMETOOLONG => "Dateiname zu lang",
        libc::ELOOP => "Symbolische Verknüpfung oder zu viele Verknüpfungen",
        libc::EOPNOTSUPP => "Vorgang wird nicht unterstützt",
        libc::ECONNRESET => "Verbindung zurückgesetzt",
        libc::ETIMEDOUT => "Zeitüberschreitung",
        libc::ECONNREFUSED => "Verbindung abgelehnt",
        libc::EDQUOT => "Speicherkontingent überschritten",
        _ => return None,
    })
}
