//! Quarantäne: Dateien nach erneuter Prüfung sicher verschieben (kopieren, fsync, löschen),
//! wiederherstellen (mit uid, gid, mode) und endgültig löschen.
//!
//! Unter Windows wird die Kopie in der Quarantäne mit einem festen Schlüssel umkodiert (XOR),
//! damit Microsoft Defender oder ein anderer Virenschutz sie dort nicht erkennt und löscht;
//! Wiederherstellen kodiert zurück. Besitzer und Rechte erbt die Datei beim Wiederherstellen
//! vom Zielordner.

use crate::clamd::Verdict;
use crate::engine::Engine;
use crate::fsutil::{self, sha256_reader};
use crate::i18n::Text;
use crate::lock;
use crate::paths;
use crate::secure_fs;
use crate::tr;
use crate::types::{QuarantineIndex, QuarantineItem};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Liest quarantine.json (leer, wenn nicht vorhanden).
pub fn load_index() -> Result<QuarantineIndex, Text> {
    Ok(fsutil::read_json(&paths::quarantine_index_path())?.unwrap_or_default())
}

fn save_index(idx: &QuarantineIndex) -> Result<(), Text> {
    fsutil::write_json(&paths::quarantine_index_path(), idx, 0o644)
}

/// Neue Quarantäne-Kennung, z. B. `q-20261023-123005-1a2b3c4d`.
fn new_qid(path: &Path) -> String {
    let now = chrono::Local::now();
    let seed = format!("{}|{}|{}", path.display(), now.timestamp_nanos_opt().unwrap_or(0), std::process::id());
    let h = fsutil::sha256_reader(&mut seed.as_bytes()).unwrap_or_default();
    format!("q-{}-{}", now.format("%Y%m%d-%H%M%S"), &h[..8])
}

/// Ergebnis der erneuten Prüfung vor einer Maßnahme.
pub struct Rechecked {
    pub dir: secure_fs::Dir,
    pub name: OsString,
    pub file: File,
    pub stat: secure_fs::Stat,
    pub signature: String,
    pub sha256: String,
}

/// Öffnet eine Datei sicher und prüft sie erneut. Fehler, wenn sie nicht (mehr) infiziert ist.
pub fn recheck(engine: &Engine, path: &Path) -> Result<Rechecked, Text> {
    if !path.is_absolute() {
        return Err(tr!("Der Pfad muss absolut sein: {}", "The path must be absolute: {}", path.display()));
    }
    let (dir, name) = secure_fs::split_secure(path)?;
    let (mut file, stat) = secure_fs::open_file_in(&dir, &name)?;
    let verdict = engine.scan_file(&mut file).map_err(|e| {
        tr!("Die erneute Prüfung von {} ist fehlgeschlagen: {}", "Rescanning {} failed: {}", path.display(), e)
    })?;
    let signature = match verdict {
        Verdict::Infected(sig) => sig,
        Verdict::Clean => {
            return Err(tr!(
                "Die Datei {} wird bei der erneuten Prüfung nicht mehr als Bedrohung erkannt. Es wurde nichts verändert.",
                "The file {} is no longer detected as a threat when scanned again. Nothing was changed.",
                path.display()
            ))
        }
        Verdict::Skipped(why) => {
            let why = Text::new(why.clone(), crate::clamd::skip_reason_en(&why));
            return Err(tr!(
                "Die Datei {} konnte nicht erneut geprüft werden: {}",
                "The file {} could not be scanned again: {}",
                path.display(),
                why
            ));
        }
    };
    let unreadable = |e: io::Error| tr!("Die Datei ist nicht lesbar: {}", "The file is not readable: {}", e);
    file.seek(SeekFrom::Start(0)).map_err(unreadable)?;
    let sha256 = sha256_reader(&mut file).map_err(unreadable)?;
    Ok(Rechecked { dir, name, file, stat, signature, sha256 })
}

/// Prüft eine Datei erneut und verschiebt sie in die Quarantäne.
pub fn quarantine_path(
    engine: &Engine,
    path: &Path,
    report_id: Option<&str>,
    threat_id: Option<&str>,
) -> Result<QuarantineItem, Text> {
    let mut rc = recheck(engine, path)?;
    fsutil::ensure_dir(&paths::quarantine_dir(), 0o700)?;
    let qdir = secure_fs::open_dir_secure(&paths::quarantine_dir())?;
    let qid = new_qid(path);
    let tmp = OsString::from(format!(".tmp-{qid}"));

    // Kopie mit Rechten 0000 anlegen und auf die Platte bringen
    let copy = (|| -> io::Result<()> {
        let mut out = secure_fs::create_excl_in(&qdir, &tmp, 0o000)?;
        rc.file.seek(SeekFrom::Start(0))?;
        #[cfg(unix)]
        {
            io::copy(&mut rc.file, &mut out)?;
            out.set_permissions(fs::Permissions::from_mode(0o000))?;
        }
        #[cfg(windows)]
        io::copy(&mut Xor::new(&mut rc.file), &mut out)?;
        out.sync_all()?;
        drop(out);
        secure_fs::rename_noreplace(&qdir, &tmp, OsString::from(&qid).as_os_str())?;
        secure_fs::sync_dir(&qdir);
        Ok(())
    })();
    if let Err(e) = copy {
        secure_fs::unlink_in(&qdir, &tmp);
        return Err(tr!(
            "Die Datei {} konnte nicht in die Quarantäne kopiert werden: {}",
            "Could not copy the file {} into quarantine: {}",
            path.display(),
            e
        ));
    }

    let item = QuarantineItem {
        id: qid.clone(),
        original_path: paths::display(path),
        signature: rc.signature.clone(),
        size: secure_fs::stat_size(&rc.stat),
        sha256: rc.sha256.clone(),
        quarantined_at: crate::now_rfc3339(),
        report_id: report_id.map(str::to_string),
        threat_id: threat_id.map(str::to_string),
        #[cfg(unix)]
        uid: rc.stat.st_uid,
        #[cfg(unix)]
        gid: rc.stat.st_gid,
        #[cfg(unix)]
        mode: rc.stat.st_mode & 0o7777,
        // Unter Windows erbt die Datei beim Wiederherstellen die Rechte des Zielordners
        #[cfg(windows)]
        uid: 0,
        #[cfg(windows)]
        gid: 0,
        #[cfg(windows)]
        mode: 0,
    };

    // Erst Verzeichnis ergänzen, dann Original löschen; bei Fehler alles zurücknehmen
    {
        let _l = lock::data_lock()?;
        let mut idx = load_index()?;
        idx.items.push(item.clone());
        if let Err(e) = save_index(&idx) {
            secure_fs::unlink_in(&qdir, OsString::from(&qid).as_os_str());
            return Err(e);
        }
    }
    if let Err(e) = secure_fs::unlink_verified(&rc.dir, &rc.name, &rc.stat) {
        let _l = lock::data_lock()?;
        let mut idx = load_index()?;
        idx.items.retain(|i| i.id != qid);
        let _ = save_index(&idx);
        secure_fs::unlink_in(&qdir, OsString::from(&qid).as_os_str());
        return Err(tr!("{} Die Datei bleibt unverändert am ursprünglichen Ort.", "{} The file remains unchanged in its original location.", e));
    }
    Ok(item)
}

/// Prüft eine Datei erneut und löscht sie endgültig. Liefert die Signatur.
pub fn delete_infected_path(engine: &Engine, path: &Path) -> Result<String, Text> {
    let rc = recheck(engine, path)?;
    secure_fs::unlink_verified(&rc.dir, &rc.name, &rc.stat)?;
    Ok(rc.signature)
}

/// Schlüssel für die Umkodierung der Quarantäne-Kopien unter Windows.
#[cfg(windows)]
const XOR_KEY: &[u8; 16] = b"Vigil-Quarantine";

/// Leser, der die Bytes mit [`XOR_KEY`] umkodiert (hin und zurück gleich).
#[cfg(windows)]
struct Xor<R> {
    inner: R,
    pos: usize,
}

#[cfg(windows)]
impl<R: io::Read> Xor<R> {
    fn new(inner: R) -> Self {
        Xor { inner, pos: 0 }
    }
}

#[cfg(windows)]
impl<R: io::Read> io::Read for Xor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for b in &mut buf[..n] {
            *b ^= XOR_KEY[self.pos % XOR_KEY.len()];
            self.pos += 1;
        }
        Ok(n)
    }
}

/// Öffnet eine Quarantäne-Datei zum Lesen. Unter Windows reicht das Recht als Administrator.
#[cfg(windows)]
fn open_quarantined(p: &Path) -> Result<File, Text> {
    File::open(p).map_err(|e| {
        tr!("Die Quarantäne-Datei {} ist nicht lesbar: {}", "The quarantine file {} is not readable: {}", p.display(), e)
    })
}

/// Öffnet eine Quarantäne-Datei zum Lesen. Ohne root (Testbetrieb) werden die Rechte 0000
/// vorher auf 0400 gesetzt, sonst ist sie nicht lesbar.
#[cfg(unix)]
fn open_quarantined(p: &Path) -> Result<File, Text> {
    let err = |e: io::Error| {
        tr!("Die Quarantäne-Datei {} ist nicht lesbar: {}", "The quarantine file {} is not readable: {}", p.display(), e)
    };
    match File::open(p) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            fs::set_permissions(p, fs::Permissions::from_mode(0o400)).and_then(|_| File::open(p)).map_err(err)
        }
        Err(e) => Err(err(e)),
    }
}

fn find_item(idx: &QuarantineIndex, qid: &str) -> Result<(usize, PathBuf), Text> {
    let qpath = paths::quarantine_file_path(qid)
        .ok_or_else(|| tr!("Ungültige Quarantäne-Kennung: {}", "Invalid quarantine ID: {}", qid))?;
    let pos = idx.items.iter().position(|i| i.id == qid).ok_or_else(|| {
        tr!("Der Quarantäne-Eintrag {} existiert nicht.", "The quarantine entry {} does not exist.", qid)
    })?;
    Ok((pos, qpath))
}

/// Stellt eine Datei wieder her (lehnt ab, wenn am Ursprungsort schon etwas liegt).
/// Liefert den Eintrag und ggf. einen Hinweis (z. B. wenn Besitzer nicht gesetzt werden konnte).
pub fn restore(qid: &str) -> Result<(QuarantineItem, Option<Text>), Text> {
    let _l = lock::data_lock()?;
    let mut idx = load_index()?;
    let (pos, qpath) = find_item(&idx, qid)?;
    let item = idx.items[pos].clone();
    let original = PathBuf::from(&item.original_path);

    let parent = original.parent().map(Path::to_path_buf).unwrap_or_default();
    let (dir, name) = secure_fs::split_secure(&original).map_err(|e| {
        if !parent.exists() {
            tr!(
                "Der ursprüngliche Ordner {} existiert nicht mehr. Die Datei bleibt in der Quarantäne.",
                "The original folder {} no longer exists. The file remains in quarantine.",
                parent.display()
            )
        } else {
            e
        }
    })?;
    let occupied = || {
        tr!(
            "Am ursprünglichen Ort liegt bereits eine Datei: {}. Die Datei bleibt in der Quarantäne.",
            "There is already a file at the original location: {}. The file remains in quarantine.",
            original.display()
        )
    };
    if secure_fs::exists_in(&dir, &name) {
        return Err(occupied());
    }

    let mut src = open_quarantined(&qpath)?;
    let tmp = OsString::from(format!(".vigil-restore-{qid}"));
    #[cfg_attr(windows, allow(unused_mut))]
    let mut note = None;
    let result = (|| -> io::Result<()> {
        let mut out = secure_fs::create_excl_in(&dir, &tmp, 0o600)?;
        #[cfg(windows)]
        io::copy(&mut Xor::new(&mut src), &mut out)?;
        #[cfg(unix)]
        io::copy(&mut src, &mut out)?;
        // Erst Besitzer, dann Rechte (chown löscht setuid-Bits)
        #[cfg(unix)]
        if let Err(e) = std::os::unix::fs::fchown(&out, Some(item.uid), Some(item.gid)) {
            note = Some(tr!(
                "Besitzer {}:{} konnte nicht gesetzt werden ({}).",
                "Could not set owner {}:{} ({}).",
                item.uid,
                item.gid,
                e
            ));
        }
        #[cfg(unix)]
        if let Err(e) = out.set_permissions(fs::Permissions::from_mode(item.mode & 0o7777)) {
            let mode = format!("{:o}", item.mode);
            let n = tr!("Rechte {} konnten nicht gesetzt werden ({}).", "Could not set permissions {} ({}).", mode, e);
            note = Some(match note.take() {
                Some(a) => Text::join(&[a, n]),
                None => n,
            });
        }
        out.sync_all()?;
        drop(out);
        secure_fs::rename_noreplace(&dir, &tmp, &name)?;
        secure_fs::sync_dir(&dir);
        Ok(())
    })();
    if let Err(e) = result {
        secure_fs::unlink_in(&dir, &tmp);
        if e.kind() == io::ErrorKind::AlreadyExists {
            return Err(occupied());
        }
        return Err(tr!(
            "Die Datei {} konnte nicht wiederhergestellt werden: {}",
            "Could not restore the file {}: {}",
            original.display(),
            e
        ));
    }

    // Quarantäne-Kopie und Eintrag entfernen
    let _ = fs::remove_file(&qpath);
    fsutil::sync_dir(&paths::quarantine_dir());
    idx.items.remove(pos);
    save_index(&idx)?;
    Ok((item, note))
}

/// Löscht eine Datei aus der Quarantäne endgültig.
pub fn delete(qid: &str) -> Result<QuarantineItem, Text> {
    let _l = lock::data_lock()?;
    let mut idx = load_index()?;
    let (pos, qpath) = find_item(&idx, qid)?;
    match fs::remove_file(&qpath) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(tr!(
                "Die Quarantäne-Datei {} konnte nicht gelöscht werden: {}",
                "Could not delete the quarantine file {}: {}",
                qpath.display(),
                e
            ))
        }
    }
    fsutil::sync_dir(&paths::quarantine_dir());
    let item = idx.items.remove(pos);
    save_index(&idx)?;
    Ok(item)
}
