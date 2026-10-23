//! Zusätzliche, kostenlose Virensignaturen von Sanesecurity (<https://sanesecurity.com>) und der
//! Abstand, in dem freshclam nach neuen ClamAV-Daten sucht.
//!
//! Sanesecurity erlaubt die kostenlose Nutzung auch in verkauften Produkten, verbietet aber das
//! Weiterverteilen der Signaturen. Jede Installation lädt deshalb selbst von den offiziellen
//! Spiegeln (`rsync://rsync.sanesecurity.net/sanesecurity/`, wie das Werkzeug
//! clamav-unofficial-sigs), höchstens einmal je Stunde (Vorgabe von Sanesecurity:
//! nicht mehrmals je Stunde). rsync überträgt nur Dateien, deren Größe oder Zeitstempel sich
//! geändert hat.
//!
//! Ablauf eines Abrufs:
//! 1. rsync in den Arbeitsordner `/var/lib/vigil/extra-sigs/sanesecurity` (Datei plus `.sig`).
//! 2. Jede Datei mit `gpgv` und dem eingebauten Schlüssel von Sanesecurity prüfen
//!    (Fingerabdruck fest eingetragen). Unechte Dateien werden verworfen.
//! 3. Geprüfte Dateien in einen Prüfordner kopieren und mit clamscan einzeln und gemeinsam
//!    testweise laden. Was ClamAV nicht laden kann, wird verworfen.
//! 4. Erst dann atomar in den Datenbankordner von clamd übernehmen (Dateinamen
//!    `vigil-sanesecurity-*`) und clamd neu laden lassen.
//!
//! Bei jedem Fehler bleibt für die betroffene Datei der bisherige Stand erhalten; clamd sieht nie
//! eine ungeprüfte Datei. Der Stand für die App steht in `/var/lib/vigil/extra-signatures.json`.

use crate::clamd;
use crate::cmd;
use crate::config;
use crate::engine;
use crate::fsutil;
use crate::i18n::Text;
use crate::lock::{self, TryLock};
use crate::paths;
use crate::sign;
use crate::sysinfo;
use crate::tr;
use crate::types::{Config, ExtraFile, ExtraSignatures, ExtraSource, ExtraStatus};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Kennung der Quelle (Ordnername im Arbeitsordner und `id` in der Zustandsdatei).
pub const SOURCE_ID: &str = "sanesecurity";
/// Anzeigename der Quelle.
pub const SOURCE_NAME: &str = "Sanesecurity";
/// Webseite der Quelle.
pub const SOURCE_URL: &str = "https://sanesecurity.com";
/// Offizielle Spiegel von Sanesecurity (DNS verteilt auf die einzelnen Spiegel).
pub const RSYNC_URL: &str = "rsync://rsync.sanesecurity.net/sanesecurity/";
/// Namensanfang aller Dateien, die Vigil in den Datenbankordner von clamd legt.
pub const INSTALL_PREFIX: &str = "vigil-sanesecurity-";
/// Kürzester Abstand zwischen zwei Abrufen. Sanesecurity bittet, nicht mehrmals je Stunde zu
/// laden; 5 Minuten Spielraum für die zufällige Verzögerung des Timers.
pub const MIN_INTERVAL_SECS: i64 = 55 * 60;
/// Fingerabdruck des Signaturschlüssels von Sanesecurity (DSA, seit 2009).
pub const KEY_FINGERPRINT: &str = "4E025A1CBA90A0653F38D2D8D691DED931EA4D9E";

/// Verwendete Datenbanken: nur von Sanesecurity selbst erstellte mit geringer Fehlalarmgefahr
/// laut <https://sanesecurity.com/usage/signatures/>, ohne Spam-Signaturen. Dazu die beiden
/// Pflichtdateien `sanesecurity.ftm` (Dateitypen für Mails) und `sigwhitelist.ign2`
/// (schnelle Rücknahme fehlerhafter Signaturen).
pub const DATABASES: &[&str] = &[
    "sanesecurity.ftm",
    "sigwhitelist.ign2",
    "phish.ndb",
    "rogue.hdb",
    "malwarehash.hsb",
    "hackingteam.hsb",
    "foxhole_generic.cdb",
    "foxhole_filename.cdb",
    "blurl.ndb",
];

/// Größte erlaubte Datenbankdatei.
const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Öffentlicher Schlüssel von Sanesecurity (<https://www.sanesecurity.com/publickey.gpg>,
/// Fingerabdruck siehe [`KEY_FINGERPRINT`]).
const PUBLIC_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

mQGiBElnAKcRBACX5ELfVPeAubJaQDQZHF8fGZFVkmT54J2uj0UwLfxbN5dQ4jEr
Pxdr0UiqOA0cttKpe0m6IZHnkbeeY4s0/HpaVZKGXsiizazB4F2NdzskuT4TRGXg
fAMQ16mlpslY//quEfIQzTSKPhEKpVHqZTn8wjSDZQo+NI3qmBODz9p5HwCggFoi
p2/LpvjmLkjPFKNpyjOwt6sD/ifFA07EmF9vxOG7aXqB7Z5zB24rpXb3/KBPbF93
6bvbT70jlwMczdOt9eNK7brpIj/ZpkdUol84MYb7sv9ZC3+qmVFKERo1rM+kvkXV
jjCFBRMyBTYYB67RgkMd79gaJ3Zo9SavQW65EtFxMr5aDfbXwkshoI3EzwVSsVPv
MoQwA/40qOV6eXQChLet795btwhbmVWvrAZ7MaN8Gdx0hMP+a9DOGo0O4J1GeNXX
Prt9PLdmUb2cahqrIVDVis6KDjD3GSdgRPf8zZ6kDUteeMND4EsYytpOQl8AeL6h
9zncFtPng1Kj/aAJyxO38YvPMFLkQV/iyZu/0Oq8RIFp/E1ZG7RJU2FuZXNlY3Vy
aXR5IChTYW5lc2VjdXJpdHkgU2lnbmF0dXJlcykgPHN0ZXZlYl9jbGFtYXZAc2Fu
ZXNlY3VyaXR5LmNvLnVrPohgBBMRAgAgBQJJZwCnAhsDBgsJCAcDAgQVAggDBBYC
AwECHgECF4AACgkQ1pHe2THqTZ7mowCaA9QGSxkN6XP7dbOlrjB9aDp5D90AniNm
W0NT6DUEVRMLnvWvnnlfufsJuQINBElnAKcQCAC1/hC7vENr66EkX0t8FAtKKZ31
kMYYjUd24uXYBEL/Fwip+JDpS9xUClK70PVcJ/Ad0z4lYQRUgRcCvq5twF5clmMG
E7M+K5vgJtjk2Wvl+w77X6za9bu8euwkzzWeyskmUpJ78EAcwsOk28Q8VPtrI76z
JjLqdY3tFXkCwCLvKzfhdg+3967B4ge+XBdTCQhE6dQ+A5ePMQKZj365A8BQdHOY
+e/MuGH6LbB/VuqGD7kjC+gE44syY/O6X9STRufvCYwPlqkJVpuR2arFIIGcXzP0
GA4m8ESFY5N68QXYvzO60CqGABhFEmAtGul7ZOJgI8QLcVIPn+lghL8V9IYDAAMG
B/4zh/khzx4TwkiAU40nsCvgjVeNKF0frka/AXdODzf9MDyJEdrdxFSKNANS/IPJ
W/n0gk5khwOcNnCIAM/GMm5szJftywhmuM3vXM6l+pHLF1/FABpNCFzjQAsBDg+g
dIYFhE9qDbFf1ZBGuJp0fdUyKG9fkdkYX4tN0F2bM6hqAIZab1FfDQC/rRcFmA0t
MeQwAQCOsyva3ipRa0xoAWS8C5bpXeVZbo9ZAGw/W+MDi7atrqURB0HRKB9PZB1J
BLlaQgZAHILykpQEE2gelUwihZS9MadB2bEvrJcbhgxaRqarAam/rcTLrMEOWgdP
uPNmK1GeJrr7D6H1g5TSYYKoiEkEGBECAAkFAklnAKcCGwwACgkQ1pHe2THqTZ6C
vACdF31uNpoParageOrmdtOdJUKUs0cAn2DLySqry2A5FlQ/6W+7IptN02IE
=fh8i
-----END PGP PUBLIC KEY BLOCK-----
";

/// Ergebnis eines Abrufs.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub status: ExtraStatus,
    pub message: Text,
    /// Anzahl der übernommenen (neuen oder geänderten) Dateien.
    pub changed: usize,
    /// Aktive Signaturen der Quelle nach dem Lauf.
    pub signatures: u64,
}

// ---------------------------------------------------------------------------
// Zustandsdatei
// ---------------------------------------------------------------------------

/// Liest extra-signatures.json. Fehlt oder ist sie unlesbar, gilt ein leerer Stand.
pub fn read_state() -> ExtraSignatures {
    fsutil::read_json(&paths::extra_sigs_state_path()).ok().flatten().unwrap_or_default()
}

fn save_state(state: &mut ExtraSignatures) -> Result<(), Text> {
    state.updated_at = crate::now_rfc3339();
    fsutil::write_json(&paths::extra_sigs_state_path(), state, 0o644)
}

/// Eintrag der Quelle im Stand (wird angelegt, falls er fehlt).
fn source_mut(state: &mut ExtraSignatures) -> &mut ExtraSource {
    let pos = match state.sources.iter().position(|s| s.id == SOURCE_ID) {
        Some(p) => p,
        None => {
            state.sources.push(ExtraSource { id: SOURCE_ID.into(), ..Default::default() });
            state.sources.len() - 1
        }
    };
    let src = &mut state.sources[pos];
    src.name = SOURCE_NAME.into();
    src.url = SOURCE_URL.into();
    src
}

/// Übernimmt Einstellungen und den Zeitpunkt der letzten Suche von freshclam in den Stand
/// (nach `set-config` und nach jedem Lauf).
pub fn refresh_state(cfg: &Config) -> Result<(), Text> {
    let mut state = read_state();
    state.enabled = cfg.extra_signatures;
    state.interval_hours = cfg.signature_interval_hours;
    state.freshclam_last_check = freshclam_last_check();
    let src = source_mut(&mut state);
    if cfg.extra_signatures && src.status == ExtraStatus::Off {
        src.status = ExtraStatus::Pending;
    }
    save_state(&mut state)
}

// ---------------------------------------------------------------------------
// Abruf
// ---------------------------------------------------------------------------

/// Ruft die zusätzlichen Signaturen ab (Timer, `extra-signatures` und `update-signatures`).
/// Sind sie in config.json ausgeschaltet, werden eigene Dateien stattdessen entfernt.
pub fn run() -> Outcome {
    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => return failed_outcome(e),
    };
    if !cfg.extra_signatures {
        let message = match disable() {
            Ok(t) => t,
            Err(e) => e,
        };
        return Outcome { status: ExtraStatus::Off, message, changed: 0, signatures: 0 };
    }
    let _lock = match lock::extra_lock(false) {
        Ok(TryLock::Acquired(l)) => l,
        Ok(TryLock::Busy) => {
            return Outcome {
                status: ExtraStatus::Waiting,
                message: tr!(
                    "Sanesecurity: Die zusätzlichen Signaturen werden gerade schon abgerufen.",
                    "Sanesecurity: The additional signatures are already being fetched."
                ),
                changed: 0,
                signatures: source_signatures(&read_state()),
            }
        }
        Err(e) => return failed_outcome(e),
    };

    let mut state = read_state();
    state.enabled = true;
    state.interval_hours = cfg.signature_interval_hours;
    let mut outcome = run_source(&mut state);
    state.freshclam_last_check = freshclam_last_check();
    if let Err(e) = save_state(&mut state) {
        outcome.message = Text::join(&[outcome.message, e]);
    }
    outcome
}

fn source_signatures(state: &ExtraSignatures) -> u64 {
    state.sources.iter().find(|s| s.id == SOURCE_ID).map(|s| s.signatures).unwrap_or(0)
}

fn failed_outcome(e: Text) -> Outcome {
    Outcome {
        status: ExtraStatus::Failed,
        message: tr!("Sanesecurity: {}", "Sanesecurity: {}", e),
        changed: 0,
        signatures: source_signatures(&read_state()),
    }
}

/// Im Testbetrieb mit `VIGIL_EXTRA_NO_WAIT=1` gilt der Mindestabstand nicht.
fn no_wait() -> bool {
    paths::dev_value("VIGIL_EXTRA_NO_WAIT").as_deref() == Some("1")
}

/// Adresse der Spiegel. Im Testbetrieb überschreibt `VIGIL_EXTRA_RSYNC_URL`.
fn rsync_url() -> String {
    paths::dev_value("VIGIL_EXTRA_RSYNC_URL").unwrap_or_else(|| RSYNC_URL.to_string())
}

fn parse_time(s: &str) -> Option<DateTime<Local>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Local))
}

fn rfc3339(t: &DateTime<Local>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

/// Name im Datenbankordner von clamd.
fn installed_name(name: &str) -> String {
    format!("{INSTALL_PREFIX}{name}")
}

/// Ein Abruf der Quelle mit Prüfung und Übernahme. Schreibt den Stand der Quelle in `state`.
fn run_source(state: &mut ExtraSignatures) -> Outcome {
    let now = Local::now();
    let work = paths::extra_sigs_dir();
    let mirror = work.join(SOURCE_ID);
    if let Err(e) = fsutil::ensure_dir(&work, 0o700).and_then(|_| fsutil::ensure_dir(&mirror, 0o700)) {
        return finish_failed(source_mut(state), e, now);
    }

    // Mindestabstand einhalten (auch bei manuellem Abruf); eine zurückgestellte Uhr hebt ihn auf
    let last = source_mut(state).last_attempt.as_deref().and_then(parse_time);
    let next_allowed = last.map(|t| t + chrono::Duration::seconds(MIN_INTERVAL_SECS));
    let due = no_wait() || last.is_none() || last.is_some_and(|t| t > now) || next_allowed.is_some_and(|n| now >= n);

    let mut errors: Vec<Text> = Vec::new();
    let mut fetched = false;
    if due {
        {
            let src = source_mut(state);
            src.last_attempt = Some(rfc3339(&now));
            src.next_allowed = Some(rfc3339(&(now + chrono::Duration::seconds(MIN_INTERVAL_SECS))));
        }
        // Abrufzeit sofort festhalten, damit auch ein abgebrochener Lauf den Abstand einhält
        let _ = save_state(state);
        match fetch(&work, &mirror) {
            Ok(()) => fetched = true,
            Err(e) => errors.push(e),
        }
    }

    // Echtheit prüfen
    let keyring = match write_keyring(&work) {
        Ok(k) => k,
        Err(e) => return finish_failed(source_mut(state), e, now),
    };
    let mut verified: Vec<&str> = Vec::new();
    for name in DATABASES {
        let file = mirror.join(name);
        let sig = mirror.join(format!("{name}.sig"));
        if !file.is_file() || !sig.is_file() {
            // Ohne (erfolgreichen) Abruf gibt es nichts zu prüfen; der Abruffehler steht schon in der Meldung
            if fetched {
                errors.push(tr!("{}: Die Datei fehlt auf dem Spiegel.", "{}: The file is missing on the mirror.", name));
            }
            continue;
        }
        match verify_gpg(&work, &keyring, &file, &sig) {
            Ok(()) => verified.push(name),
            Err(e) => {
                // Verwerfen, damit der nächste Abruf die Datei vollständig neu lädt
                let _ = fs::remove_file(&file);
                let _ = fs::remove_file(&sig);
                errors.push(tr!("{}: {}", "{}: {}", name, e));
            }
        }
    }

    // Testweise mit ClamAV laden: jede Datei einzeln, dann alle zusammen
    let stage = work.join("stage");
    let _ = fs::remove_dir_all(&stage);
    if let Err(e) = fsutil::ensure_dir(&stage, 0o700) {
        return finish_failed(source_mut(state), e, now);
    }
    let test_file = work.join("scan-test.txt");
    if let Err(e) = fsutil::write_atomic(&test_file, b"Vigil Testdatei\n", 0o600) {
        return finish_failed(source_mut(state), e, now);
    }
    let mut accepted: Vec<(&str, Vec<u8>, u64)> = Vec::new();
    for name in verified {
        let result = read_limited(&mirror.join(name)).and_then(|data| {
            let staged = stage.join(installed_name(name));
            fsutil::write_atomic(&staged, &data, 0o644)?;
            match clamscan_count(&staged, &test_file) {
                Ok(n) => Ok((data, n)),
                Err(e) => {
                    let _ = fs::remove_file(&staged);
                    Err(e)
                }
            }
        });
        match result {
            Ok((data, n)) => accepted.push((name, data, n)),
            Err(e) => {
                let _ = fs::remove_file(mirror.join(name));
                let _ = fs::remove_file(mirror.join(format!("{name}.sig")));
                errors.push(tr!("{}: {}", "{}: {}", name, e));
            }
        }
    }
    if !accepted.is_empty() {
        if let Err(e) = clamscan_count(&stage, &test_file) {
            errors.push(tr!(
                "Die neuen Dateien lassen sich zusammen nicht laden, es wird nichts übernommen: {}",
                "The new files cannot be loaded together, nothing is taken over: {}",
                e
            ));
            accepted.clear();
        }
    }
    let _ = fs::remove_dir_all(&stage);

    // Übernehmen
    let dbdir = clamd_database_dir();
    if !dbdir.is_dir() {
        let e = tr!(
            "Der Datenbankordner von clamd {} fehlt.",
            "The clamd database folder {} is missing.",
            dbdir.display()
        );
        return finish_failed(source_mut(state), e, now);
    }
    let now_s = rfc3339(&now);
    let previous = source_mut(state).files.clone();
    let mut files: Vec<ExtraFile> = Vec::new();
    let mut changed = 0usize;
    for (name, data, sigs) in &accepted {
        let target = dbdir.join(installed_name(name));
        let sha = sha256_bytes(data);
        let old_sha = sha256_file(&target).ok();
        let prev = previous.iter().find(|f| f.name == *name);
        let changed_at = if old_sha.as_deref() == Some(sha.as_str()) {
            prev.and_then(|p| p.changed_at.clone()).or_else(|| Some(now_s.clone()))
        } else {
            if let Err(e) = fsutil::write_atomic(&target, data, 0o644) {
                errors.push(tr!("{}: {}", "{}: {}", name, e));
                if let Some(p) = prev.filter(|p| dbdir.join(&p.installed).is_file()) {
                    files.push(p.clone());
                }
                continue;
            }
            changed += 1;
            Some(now_s.clone())
        };
        files.push(ExtraFile {
            name: name.to_string(),
            installed: installed_name(name),
            signatures: *sigs,
            size: data.len() as u64,
            sha256: sha,
            changed_at,
        });
    }
    // Nicht übernommene Dateien: der bisherige Stand bleibt, solange er installiert ist
    for name in DATABASES {
        if files.iter().any(|f| f.name == *name) {
            continue;
        }
        if let Some(p) = previous.iter().find(|f| f.name == *name && dbdir.join(&f.installed).is_file()) {
            files.push(p.clone());
        }
    }
    files.sort_by_key(|f| DATABASES.iter().position(|n| *n == f.name).unwrap_or(usize::MAX));
    // Eigene Dateien, die nicht mehr verwendet werden, entfernen
    let keep: Vec<String> = files.iter().map(|f| f.installed.clone()).collect();
    let removed = match remove_installed_files(&dbdir, &keep) {
        Ok(n) => n,
        Err(e) => {
            errors.push(e);
            0
        }
    };
    let reload_note = (changed > 0 || removed > 0).then(reload_clamd);

    // Stand und Meldung
    let src = source_mut(state);
    let signatures: u64 = files.iter().map(|f| f.signatures).sum();
    let total = DATABASES.len();
    let missing = total.saturating_sub(files.len());
    src.signatures = signatures;
    src.files = files;
    if changed > 0 {
        src.last_change = Some(now_s.clone());
    }
    if fetched {
        src.last_success = Some(now_s.clone());
    }
    let updated_text = tr!(
        "Sanesecurity: {} von {} Dateien wurden erneuert, aktiv sind {} Signaturen.",
        "Sanesecurity: {} of {} files were renewed, {} signatures are active.",
        changed,
        total,
        signatures
    );
    let (status, mut message) = if errors.is_empty() {
        if changed > 0 {
            (ExtraStatus::Updated, updated_text)
        } else if due {
            (
                ExtraStatus::Current,
                tr!(
                    "Sanesecurity: bereits aktuell, aktiv sind {} Signaturen.",
                    "Sanesecurity: already up to date, {} signatures are active.",
                    signatures
                ),
            )
        } else {
            let at = last.map(|t| t.format("%H:%M").to_string()).unwrap_or_default();
            let next = next_allowed.map(|t| t.format("%H:%M").to_string()).unwrap_or_default();
            (
                ExtraStatus::Waiting,
                tr!(
                    "Sanesecurity: zuletzt um {} abgerufen. Sanesecurity erlaubt einen neuen Abruf frühestens um {}. Aktiv sind {} Signaturen.",
                    "Sanesecurity: last fetched at {}. Sanesecurity allows the next fetch at {} at the earliest. {} signatures are active.",
                    at,
                    next,
                    signatures
                ),
            )
        }
    } else {
        let err = Text::join(&errors);
        src.error = Some(err.de_text());
        src.error_en = Some(err.en_text());
        src.error_at = Some(now_s.clone());
        if (due && !fetched) || src.files.is_empty() {
            let msg = if signatures > 0 {
                tr!(
                    "Sanesecurity: Der Abruf ist fehlgeschlagen, der bisherige Stand bleibt aktiv ({} Signaturen). {}",
                    "Sanesecurity: Fetching failed, the previous data stays active ({} signatures). {}",
                    signatures,
                    err
                )
            } else {
                tr!("Sanesecurity: Der Abruf ist fehlgeschlagen. {}", "Sanesecurity: Fetching failed. {}", err)
            };
            (ExtraStatus::Failed, msg)
        } else {
            let part = tr!(
                "Sanesecurity: {} von {} Dateien wurden nicht übernommen, für sie bleibt der bisherige Stand. {}",
                "Sanesecurity: {} of {} files were not taken over, the previous data stays for them. {}",
                total - accepted.len().min(total),
                total,
                err
            );
            let msg = if changed > 0 { Text::join(&[updated_text, part]) } else { part };
            (ExtraStatus::Partial, msg)
        }
    };
    if errors.is_empty() {
        src.error = None;
        src.error_en = None;
        src.error_at = None;
    }
    if missing > 0 && errors.is_empty() {
        // Ohne Abruf fehlen Dateien (z. B. von Hand gelöscht): beim nächsten Abruf neu laden
        message = Text::join(&[
            message,
            tr!(
                "{} Dateien fehlen und werden beim nächsten Abruf geladen.",
                "{} files are missing and will be fetched next time.",
                missing
            ),
        ]);
    }
    if let Some(n) = reload_note {
        message = Text::join(&[message, n]);
    }
    src.status = status;
    src.message = Some(message.de_text());
    src.message_en = Some(message.en_text());
    Outcome { status, message, changed, signatures }
}

/// Fehler vor der Übernahme: bisheriger Stand bleibt, Meldung in den Stand schreiben.
fn finish_failed(src: &mut ExtraSource, e: Text, now: DateTime<Local>) -> Outcome {
    let message = if src.signatures > 0 {
        tr!(
            "Sanesecurity: Der Abruf ist fehlgeschlagen, der bisherige Stand bleibt aktiv ({} Signaturen). {}",
            "Sanesecurity: Fetching failed, the previous data stays active ({} signatures). {}",
            src.signatures,
            e
        )
    } else {
        tr!("Sanesecurity: Der Abruf ist fehlgeschlagen. {}", "Sanesecurity: Fetching failed. {}", e)
    };
    src.status = ExtraStatus::Failed;
    src.error = Some(e.de_text());
    src.error_en = Some(e.en_text());
    src.error_at = Some(rfc3339(&now));
    src.message = Some(message.de_text());
    src.message_en = Some(message.en_text());
    Outcome { status: ExtraStatus::Failed, message, changed: 0, signatures: src.signatures }
}

/// Lädt die Datenbanken und ihre `.sig` per rsync in den Arbeitsordner. Versucht es bis zu
/// dreimal (jeder Versuch kann über DNS einen anderen Spiegel treffen).
fn fetch(work: &Path, mirror: &Path) -> Result<(), Text> {
    let rsync = cmd::find_program("rsync").ok_or_else(|| {
        tr!(
            "Das Programm rsync ist nicht installiert. Es wird für den Abruf von Sanesecurity gebraucht.",
            "The program rsync is not installed. It is needed to fetch from Sanesecurity."
        )
    })?;
    let list = work.join("files.txt");
    let mut text = String::new();
    for name in DATABASES {
        text.push_str(name);
        text.push('\n');
        text.push_str(name);
        text.push_str(".sig\n");
    }
    fsutil::write_atomic(&list, text.as_bytes(), 0o600)?;
    let files_from = format!("--files-from={}", list.display());
    let dest = format!("{}/", mirror.display());
    let url = rsync_url();
    let args = [
        "-tz",
        "--no-motd",
        "--contimeout=30",
        "--timeout=120",
        "--max-size=64m",
        files_from.as_str(),
        url.as_str(),
        dest.as_str(),
    ];
    let mut last_err = Text::default();
    for attempt in 0..3 {
        if crate::TERMINATE.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(5));
        }
        let out = cmd::run(&rsync, &args, Duration::from_secs(10 * 60))?;
        // 23/24: einzelne Dateien fehlen; das erkennt die anschließende Prüfung je Datei
        if !out.timed_out && matches!(out.code, Some(0) | Some(23) | Some(24)) {
            return Ok(());
        }
        last_err = short(&out.error_text());
    }
    Err(tr!(
        "Die Spiegel von Sanesecurity sind nicht erreichbar: {}",
        "The Sanesecurity mirrors are not reachable: {}",
        last_err
    ))
}

/// Kürzt eine mehrzeilige Ausgabe auf eine Zeile mit höchstens 400 Zeichen.
fn short(t: &Text) -> Text {
    let f = |s: &str| {
        let line = s
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        line.chars().take(400).collect::<String>()
    };
    Text::new(f(&t.de), f(&t.en))
}

/// Schreibt den eingebauten Schlüssel als Schlüsselbund für gpgv in den Arbeitsordner.
fn write_keyring(work: &Path) -> Result<PathBuf, Text> {
    let mut body = String::new();
    let mut in_body = false;
    for line in PUBLIC_KEY.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") {
            continue;
        }
        if l.starts_with("-----END") || (in_body && l.starts_with('=')) {
            break;
        }
        if !in_body {
            // Kopfzeilen bis zur Leerzeile überspringen
            in_body = l.is_empty();
            continue;
        }
        body.push_str(l);
    }
    let raw = sign::b64_decode(&body)
        .ok_or_else(|| tr!("Der eingebaute Schlüssel von Sanesecurity ist beschädigt.", "The built-in Sanesecurity key is damaged."))?;
    let path = work.join("sanesecurity-keyring.gpg");
    fsutil::write_atomic(&path, &raw, 0o600)?;
    Ok(path)
}

/// Prüft die GPG-Signatur einer Datei mit gpgv. Gültig nur mit genau einer gültigen Signatur
/// des Schlüssels [`KEY_FINGERPRINT`].
fn verify_gpg(work: &Path, keyring: &Path, file: &Path, sig: &Path) -> Result<(), Text> {
    let gpgv = cmd::find_program("gpgv").ok_or_else(|| {
        tr!(
            "Das Programm gpgv ist nicht installiert. Ohne gpgv lässt sich die Echtheit nicht prüfen.",
            "The program gpgv is not installed. Without gpgv the authenticity cannot be checked."
        )
    })?;
    let home = work.join("gnupg");
    fsutil::ensure_dir(&home, 0o700)?;
    let (home_s, kr_s) = (home.to_string_lossy().into_owned(), keyring.to_string_lossy().into_owned());
    let (sig_s, file_s) = (sig.to_string_lossy().into_owned(), file.to_string_lossy().into_owned());
    let out = cmd::run(
        &gpgv,
        &["--homedir", &home_s, "--status-fd", "1", "--keyring", &kr_s, &sig_s, &file_s],
        Duration::from_secs(120),
    )?;
    let status: Vec<&str> = out.stdout.lines().filter_map(|l| l.strip_prefix("[GNUPG:] ")).collect();
    let valid: Vec<&str> = status.iter().filter_map(|l| l.strip_prefix("VALIDSIG ")).collect();
    let bad = status.iter().any(|l| {
        ["BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"].iter().any(|k| l.starts_with(k))
    });
    // VALIDSIG <fpr> … <fpr des Hauptschlüssels>
    let key_ok = valid.len() == 1
        && valid[0].split_whitespace().last() == Some(KEY_FINGERPRINT)
        && valid[0].split_whitespace().next() == Some(KEY_FINGERPRINT);
    if out.success() && !bad && key_ok {
        return Ok(());
    }
    Err(tr!(
        "Die GPG-Signatur ist ungültig oder stammt nicht von Sanesecurity, die Datei wird verworfen. {}",
        "The GPG signature is invalid or not from Sanesecurity, the file is discarded. {}",
        short(&out.error_text())
    ))
}

/// Lädt eine Datenbankdatei oder einen Ordner mit clamscan und liefert die Zahl der geladenen
/// Signaturen. Fehler, wenn ClamAV etwas nicht laden kann oder die harmlose Testdatei erkennt.
fn clamscan_count(db: &Path, test_file: &Path) -> Result<u64, Text> {
    let bin = engine::clamscan_path();
    let db_arg = format!("--database={}", db.display());
    let test = test_file.to_string_lossy().into_owned();
    let out = cmd::run(&bin, &[&db_arg, "--stdout", &test], Duration::from_secs(10 * 60))?;
    let errors: Vec<&str> = out
        .stderr
        .lines()
        .chain(out.stdout.lines())
        .filter(|l| l.contains("LibClamAV Error") || l.starts_with("ERROR"))
        .collect();
    if out.code == Some(1) {
        return Err(tr!(
            "ClamAV meldet mit dieser Datei eine harmlose Testdatei als Fund, sie wird verworfen.",
            "With this file ClamAV reports a harmless test file as a finding, it is discarded."
        ));
    }
    if !out.success() || !errors.is_empty() {
        let detail = if errors.is_empty() { short(&out.error_text()) } else { Text::same(errors.join(" | ")) };
        return Err(tr!("ClamAV kann die Datei nicht laden: {}", "ClamAV cannot load the file: {}", short(&detail)));
    }
    out.stdout
        .lines()
        .find_map(|l| l.strip_prefix("Known viruses:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| tr!("clamscan hat keine Signaturzahl gemeldet.", "clamscan did not report a signature count."))
}

/// Liest eine Datei vollständig, höchstens [`MAX_FILE_SIZE`] Byte, ohne Verknüpfungen zu folgen.
fn read_limited(p: &Path) -> Result<Vec<u8>, Text> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)
        .map_err(|e| tr!("Die Datei {} konnte nicht geöffnet werden: {}", "Could not open the file {}: {}", p.display(), e))?;
    let mut data = Vec::new();
    f.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|e| tr!("Die Datei {} konnte nicht gelesen werden: {}", "Could not read the file {}: {}", p.display(), e))?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(tr!("Die Datei {} ist zu groß.", "The file {} is too large.", p.display()));
    }
    Ok(data)
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut r: &[u8] = data;
    fsutil::sha256_reader(&mut r).unwrap_or_default()
}

fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(p)?;
    fsutil::sha256_reader(&mut f)
}

// ---------------------------------------------------------------------------
// Datenbankordner von clamd
// ---------------------------------------------------------------------------

/// Wert eines Schlüssels aus einer ClamAV-Konfiguration (letzte gültige Zeile zählt).
fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.splitn(2, char::is_whitespace);
            let k = it.next()?;
            let v = it.next()?.trim();
            (k == key && !v.is_empty()).then(|| v.to_string())
        })
        .next_back()
}

/// Datenbankordner von clamd: `DatabaseDirectory` aus /etc/clamav/clamd.conf, sonst aus
/// freshclam.conf, sonst /var/lib/clamav. Im Testbetrieb überschreibt `VIGIL_CLAMAV_DB`.
pub fn clamd_database_dir() -> PathBuf {
    if let Some(p) = paths::dev_override("VIGIL_CLAMAV_DB") {
        return p;
    }
    fs::read_to_string(clamd::CLAMD_CONF)
        .ok()
        .and_then(|t| conf_value(&t, "DatabaseDirectory"))
        .map(PathBuf::from)
        .unwrap_or_else(sysinfo::database_dir)
}

/// Entfernt eigene Dateien (`vigil-sanesecurity-*` und liegengebliebene temporäre Dateien
/// `.vigil-sanesecurity-*`) aus dem Datenbankordner, außer denen in `keep`.
fn remove_installed_files(dbdir: &Path, keep: &[String]) -> Result<usize, Text> {
    let rd = match fs::read_dir(dbdir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(tr!("Der Ordner {} ist nicht lesbar: {}", "The folder {} is not readable: {}", dbdir.display(), e))
        }
    };
    let tmp_prefix = format!(".{INSTALL_PREFIX}");
    let mut removed = 0;
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let ours = name.starts_with(INSTALL_PREFIX) || (name.starts_with(&tmp_prefix) && name.contains(".tmp-"));
        if !ours || keep.contains(&name) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
        if meta.is_dir() {
            continue;
        }
        fs::remove_file(entry.path()).map_err(|e| {
            tr!("Die Datei {} konnte nicht entfernt werden: {}", "Could not remove the file {}: {}", entry.path().display(), e)
        })?;
        // Temporäre Reste lädt clamd nicht, sie zählen nicht als Änderung
        if name.starts_with(INSTALL_PREFIX) {
            removed += 1;
        }
    }
    if removed > 0 {
        fsutil::sync_dir(dbdir);
    }
    Ok(removed)
}

/// Bittet clamd, die Datenbanken neu zu laden: zuerst `zRELOAD` über den Socket. Ist das in
/// clamd.conf ausgeschaltet (`EnableReloadCommand false`, Standard bei Debian und Ubuntu), über
/// `systemctl reload clamav-daemon` (SIGUSR2). Liefert einen Hinweis für die Meldung.
pub fn reload_clamd() -> Text {
    let sock = clamd::clamd_socket();
    match clamd::reload(&sock) {
        Ok(r) if r.starts_with("RELOADING") => tr!("clamd lädt die neuen Daten.", "clamd is loading the new data."),
        Ok(r) if r.contains("UNAVAILABLE") => reload_via_systemd(),
        Ok(r) => tr!(
            "clamd hat das Neuladen nicht bestätigt ({}). clamd übernimmt die Daten bei seiner nächsten Selbstprüfung oder beim nächsten Start.",
            "clamd did not confirm the reload ({}). clamd takes over the data at its next self check or next start.",
            r
        ),
        Err(_) => tr!(
            "clamd läuft gerade nicht. Die neuen Daten werden beim nächsten Start geladen.",
            "clamd is not running right now. The new data will be loaded at the next start."
        ),
    }
}

fn reload_via_systemd() -> Text {
    if paths::is_dev() {
        return tr!(
            "Testbetrieb: clamd erlaubt kein Neuladen über den Socket, systemctl wurde nicht aufgerufen.",
            "Test mode: clamd does not allow reloading via the socket, systemctl was not called."
        );
    }
    let fail = |e: Text| {
        tr!(
            "clamd konnte nicht neu geladen werden: {}. clamd übernimmt die Daten bei seiner nächsten Selbstprüfung oder beim nächsten Start.",
            "clamd could not be reloaded: {}. clamd takes over the data at its next self check or next start.",
            e
        )
    };
    match cmd::run_named("systemctl", &["--no-ask-password", "reload", "clamav-daemon"], Duration::from_secs(60)) {
        Ok(o) if o.success() => tr!("clamd lädt die neuen Daten.", "clamd is loading the new data."),
        Ok(o) => fail(o.error_text()),
        Err(e) => fail(e),
    }
}

// ---------------------------------------------------------------------------
// Ausschalten und Entfernen
// ---------------------------------------------------------------------------

/// Schaltet die zusätzlichen Signaturen aus: eigene Dateien aus dem Datenbankordner und die
/// Arbeitskopien entfernen, clamd neu laden, Stand auf „aus“ setzen.
pub fn disable() -> Result<Text, Text> {
    let _lock = match lock::extra_lock(true)? {
        TryLock::Acquired(l) => l,
        TryLock::Busy => unreachable!("extra_lock(true) wartet"),
    };
    let dbdir = clamd_database_dir();
    let removed = remove_installed_files(&dbdir, &[])?;
    let work = paths::extra_sigs_dir();
    let _ = fs::remove_dir_all(work.join(SOURCE_ID));
    let _ = fs::remove_dir_all(work.join("stage"));

    let message = if removed > 0 {
        Text::join(&[
            tr!(
                "Die zusätzlichen Signaturen von Sanesecurity wurden entfernt ({} Dateien).",
                "The additional Sanesecurity signatures have been removed ({} files).",
                removed
            ),
            reload_clamd(),
        ])
    } else {
        tr!("Zusätzliche Signaturen sind ausgeschaltet.", "Additional signatures are turned off.")
    };

    let mut state = read_state();
    state.enabled = false;
    if let Ok(cfg) = config::load_config() {
        state.interval_hours = cfg.signature_interval_hours;
    }
    state.freshclam_last_check = freshclam_last_check();
    let src = source_mut(&mut state);
    src.status = ExtraStatus::Off;
    src.files.clear();
    src.signatures = 0;
    src.error = None;
    src.error_en = None;
    src.error_at = None;
    src.message = Some(message.de_text());
    src.message_en = Some(message.en_text());
    save_state(&mut state)?;
    Ok(message)
}

/// Beim Deinstallieren (prerm): eigene Dateien entfernen und `Checks` in freshclam.conf auf
/// den Wert vor der ersten Änderung durch Vigil zurücksetzen.
pub fn remove_all() -> Result<Text, Text> {
    let mut notes = vec![disable()?];
    if let Some(n) = restore_freshclam_interval()? {
        notes.push(n);
    }
    Ok(Text::join(&notes))
}

// ---------------------------------------------------------------------------
// freshclam: Abstand der Suche und letzte Suche
// ---------------------------------------------------------------------------

/// Wert für `Checks` (Suchen je Tag) zu einem Abstand in Stunden.
pub fn freshclam_checks(hours: u32) -> u32 {
    24 / hours.clamp(1, 24)
}

/// Ersetzt die Zeile `Checks` (alle gültigen Zeilen mit diesem Schlüssel) oder hängt sie an;
/// `None` entfernt sie. Liefert den neuen Text nur, wenn sich etwas ändert.
fn set_checks(text: &str, value: Option<u32>) -> Option<String> {
    let mut out = String::with_capacity(text.len() + 16);
    let mut found = false;
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        let trimmed = body.trim_start();
        let is_checks = !trimmed.starts_with('#') && trimmed.split_whitespace().next() == Some("Checks");
        if !is_checks {
            out.push_str(line);
            continue;
        }
        found = true;
        match value {
            Some(v) => {
                let indent = &body[..body.len() - trimmed.len()];
                let new_line = format!("{indent}Checks {v}");
                if new_line.trim_end() != body.trim_end() {
                    changed = true;
                }
                out.push_str(&new_line);
                out.push_str(nl);
            }
            None => changed = true,
        }
    }
    if !found {
        if let Some(v) = value {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("Checks {v}\n"));
            changed = true;
        }
    }
    changed.then_some(out)
}

/// Sicherungen von freshclam.conf im Datenordner: `.orig` (Stand vor der ersten Änderung durch
/// Vigil, wird nie überschrieben) und `.bak` (Stand vor der letzten Änderung).
fn freshclam_backup_paths() -> (PathBuf, PathBuf) {
    let d = paths::data_dir();
    (d.join("freshclam.conf.orig"), d.join("freshclam.conf.bak"))
}

/// Setzt `Checks` in freshclam.conf passend zum Abstand (24 / Stunden), nur diese Zeile, mit
/// Sicherung vorher, und startet clamav-freshclam danach neu. `Ok(None)`, wenn nichts zu tun war.
pub fn apply_freshclam_interval(hours: u32) -> Result<Option<Text>, Text> {
    let Some(path) = paths::freshclam_conf_path() else {
        return Ok(Some(tr!(
            "Testbetrieb: freshclam.conf wurde nicht geändert (VIGIL_FRESHCLAM_CONF ist nicht gesetzt).",
            "Test mode: freshclam.conf was not changed (VIGIL_FRESHCLAM_CONF is not set)."
        )));
    };
    let checks = freshclam_checks(hours);
    let original = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(Some(tr!(
                "{} fehlt, der Abstand für freshclam wurde nicht gesetzt.",
                "{} is missing, the interval for freshclam was not set.",
                path.display()
            )))
        }
        Err(e) => {
            return Err(tr!("Die Datei {} konnte nicht gelesen werden: {}", "Could not read the file {}: {}", path.display(), e))
        }
    };
    let Some(new) = set_checks(&original, Some(checks)) else { return Ok(None) };
    let (orig, bak) = freshclam_backup_paths();
    if !orig.exists() {
        fsutil::write_atomic(&orig, original.as_bytes(), 0o600)?;
    }
    fsutil::write_atomic(&bak, original.as_bytes(), 0o600)?;
    write_preserving(&path, new.as_bytes())?;
    Ok(Some(restart_freshclam(tr!(
        "freshclam sucht jetzt {} Mal am Tag nach neuen Daten.",
        "freshclam now checks for new data {} times a day.",
        checks
    ))))
}

/// Setzt `Checks` auf den Wert aus der Sicherung `.orig` zurück (beim Deinstallieren).
fn restore_freshclam_interval() -> Result<Option<Text>, Text> {
    let (orig, _) = freshclam_backup_paths();
    let Some(path) = paths::freshclam_conf_path() else { return Ok(None) };
    let Ok(orig_text) = fs::read_to_string(&orig) else { return Ok(None) };
    let Ok(current) = fs::read_to_string(&path) else { return Ok(None) };
    let value = conf_value(&orig_text, "Checks").and_then(|v| v.parse::<u32>().ok());
    let Some(new) = set_checks(&current, value) else { return Ok(None) };
    write_preserving(&path, new.as_bytes())?;
    Ok(Some(restart_freshclam(tr!(
        "Der Abstand von freshclam wurde auf den Stand vor Vigil zurückgesetzt.",
        "The freshclam interval has been reset to its state before Vigil."
    ))))
}

/// Startet clamav-freshclam neu, damit `Checks` gilt (nur wenn der Dienst läuft).
fn restart_freshclam(note: Text) -> Text {
    if paths::is_dev() {
        return Text::join(&[
            note,
            tr!("Testbetrieb: clamav-freshclam wurde nicht neu gestartet.", "Test mode: clamav-freshclam was not restarted."),
        ]);
    }
    match cmd::run_named("systemctl", &["--no-ask-password", "try-restart", "clamav-freshclam"], Duration::from_secs(60)) {
        Ok(o) if o.success() => note,
        Ok(o) => Text::join(&[
            note,
            tr!(
                "clamav-freshclam konnte nicht neu gestartet werden, der neue Abstand gilt nach dem nächsten Neustart: {}",
                "clamav-freshclam could not be restarted, the new interval applies after the next restart: {}",
                o.error_text()
            ),
        ]),
        Err(e) => Text::join(&[note, e]),
    }
}

/// Schreibt eine Datei atomar und übernimmt Besitzer und Rechte der bisherigen Datei.
fn write_preserving(path: &Path, data: &[u8]) -> Result<(), Text> {
    let err = |e: std::io::Error| {
        tr!("Die Datei {} konnte nicht geschrieben werden: {}", "Could not write the file {}: {}", path.display(), e)
    };
    let meta = fs::symlink_metadata(path).map_err(err)?;
    if !meta.file_type().is_file() {
        return Err(tr!("{} ist keine reguläre Datei.", "{} is not a regular file.", path.display()));
    }
    let dir = path.parent().ok_or_else(|| tr!("Ungültiger Dateipfad: {}", "Invalid file path: {}", path.display()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.vigil-{}", std::process::id()));
    let r = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(data)?;
        std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid()))?;
        f.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777))?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = r {
        let _ = fs::remove_file(&tmp);
        return Err(err(e));
    }
    fsutil::sync_dir(dir);
    Ok(())
}

/// Zeitpunkt der letzten Suche von freshclam nach neuen Daten: Meldung „ClamAV update process
/// started“ aus dem Journal von clamav-freshclam, sonst aus dem freshclam-Protokoll
/// (`UpdateLogFile`). `None`, wenn keine Quelle lesbar ist.
pub fn freshclam_last_check() -> Option<String> {
    journal_last_check().or_else(log_last_check)
}

fn journal_last_check() -> Option<String> {
    let out = cmd::run_named(
        "journalctl",
        &["-u", "clamav-freshclam", "-o", "short-iso", "-n", "500", "--no-pager", "-q"],
        Duration::from_secs(20),
    )
    .ok()?;
    let line = out.stdout.lines().rev().find(|l| l.contains("update process started at"))?;
    let ts = line.split_whitespace().next()?;
    let dt = DateTime::parse_from_rfc3339(ts).or_else(|_| DateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%z")).ok()?;
    Some(rfc3339(&dt.with_timezone(&Local)))
}

fn log_last_check() -> Option<String> {
    let conf = paths::freshclam_conf_path().unwrap_or_else(|| PathBuf::from("/etc/clamav/freshclam.conf"));
    let log = fs::read_to_string(conf)
        .ok()
        .and_then(|t| conf_value(&t, "UpdateLogFile"))
        .unwrap_or_else(|| "/var/log/clamav/freshclam.log".into());
    // Nur das Ende des Protokolls lesen
    let mut f = File::open(log).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(256 * 1024))).ok()?;
    let mut buf = Vec::new();
    f.take(256 * 1024).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let marker = "update process started at ";
    let line = text.lines().rev().find(|l| l.contains(marker))?;
    let when = line.split(marker).nth(1)?.split_whitespace().collect::<Vec<_>>().join(" ");
    let naive = NaiveDateTime::parse_from_str(&when, "%a %b %d %H:%M:%S %Y").ok()?;
    let local = Local.from_local_datetime(&naive).single()?;
    Some(rfc3339(&local))
}

