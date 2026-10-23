//! Rahmen für Vigil Pro im offenen Kern: signierte Pro-Pakete installieren und entfernen,
//! die Freigabe (Token) prüfen und speichern, `vigil-pro` nach Prüfung starten.
//! Alle Signaturen stammen vom Lizenzserver (Schlüssel [`crate::sign::LICENSE_PUBLIC_KEY`]).

use crate::fsutil::{self, sha256_reader};
use crate::i18n::{Lang, Text};
use crate::paths;
use crate::selfupdate::read_source;
use crate::sign::{self, KeyKind, TokenClaims};
use crate::tr;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Lizenzserver (wird von der App genutzt, steht hier an einer Stelle für Rust).
pub const LICENSE_BASE: &str = "https://lizenz.noosmedia.de/vigil";

/// Programm, das als root über den Helfer läuft.
#[cfg(unix)]
pub const PRO_BIN: &str = "vigil-pro";
/// Programm, das die App als Benutzer startet.
#[cfg(unix)]
pub const PRO_AGENT: &str = "vigil-pro-agent";
/// Programm, das als SYSTEM bzw. Administrator über den Helfer läuft.
#[cfg(windows)]
pub const PRO_BIN: &str = "vigil-pro.exe";
/// Programm, das die App als Benutzer startet.
#[cfg(windows)]
pub const PRO_AGENT: &str = "vigil-pro-agent.exe";
/// ES-Modul der Pro-Oberfläche.
pub const PRO_UI: &str = "pro-ui.js";
/// Paketbeschreibung.
pub const MANIFEST: &str = "manifest.json";

/// Die drei Dateien laut Manifest.
pub const PRO_FILES: [&str; 3] = [PRO_BIN, PRO_AGENT, PRO_UI];

/// Größte erlaubte Datei eines Pro-Pakets.
const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024;
/// Größte erlaubte Signaturdatei.
const MAX_SIG_SIZE: u64 = 4096;

/// Inhalt von manifest.json.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub features: Vec<String>,
    pub files: BTreeMap<String, String>,
    pub min_core: String,
}

/// Fehler rund um Pro: nicht aktiv (Exit 5) oder sonstiger Fehler (Exit 4).
#[derive(Debug)]
pub enum ProError {
    Inactive(Text),
    Failed(Text),
}

impl From<Text> for ProError {
    fn from(t: Text) -> Self {
        ProError::Failed(t)
    }
}

/// Meldung „nicht aktiv“ mit Grund.
fn inactive(reason: Text) -> ProError {
    ProError::Inactive(Text::join(&[tr!("Vigil Pro ist nicht aktiv.", "Vigil Pro is not active."), reason]))
}

/// Betriebsart von `vigil-pro`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Nur lesen (über vigil-scan, ohne Passwort).
    Ro,
    /// Ändern (über vigil-helper, mit Passwort).
    Rw,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Ro => "ro",
            Mode::Rw => "rw",
        }
    }
}

/// Liest eine Datei mit ihrer Signatur (`<datei>.sig`) aus einem Ordner und prüft die Signatur.
/// Liefert Inhalt und Signaturdatei.
fn read_signed(dir: &Path, name: &str, max: u64) -> Result<(Vec<u8>, Vec<u8>), Text> {
    let data = read_source(&dir.join(name), max)?;
    let sig = read_source(&dir.join(format!("{name}.sig")), MAX_SIG_SIZE)?;
    sign::verify(KeyKind::License, &data, String::from_utf8_lossy(&sig).trim())
        .map_err(|e| tr!("Die Datei {} ist nicht gültig signiert: {}", "The file {} is not validly signed: {}", name, e))?;
    Ok((data, sig))
}

/// Liest und prüft das Manifest (Signatur, Dateiliste, Version, minCore).
fn parse_manifest(data: &[u8]) -> Result<Manifest, Text> {
    let m: Manifest = serde_json::from_slice(data)
        .map_err(|e| tr!("Das Manifest von Vigil Pro ist nicht lesbar: {}", "The Vigil Pro manifest is not readable: {}", e))?;
    let names: Vec<&str> = m.files.keys().map(String::as_str).collect();
    let mut expected = PRO_FILES.to_vec();
    expected.sort();
    if names != expected {
        return Err(tr!(
            "Das Manifest nennt nicht genau die Dateien {}.",
            "The manifest does not list exactly the files {}.",
            PRO_FILES.join(", ")
        ));
    }
    if m.files.values().any(|h| !fsutil::is_sha256(h)) {
        return Err(tr!("Das Manifest enthält ungültige Prüfsummen.", "The manifest contains invalid checksums."));
    }
    if m.version.is_empty() || m.version.len() > 64 || !m.version.chars().all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c)) {
        return Err(tr!("Die Version im Manifest ist ungültig: {}", "The version in the manifest is invalid: {}", m.version));
    }
    let min = sign::parse_version(&m.min_core)
        .ok_or_else(|| tr!("minCore im Manifest ist ungültig: {}", "minCore in the manifest is invalid: {}", m.min_core))?;
    let own = sign::parse_version(crate::VERSION).unwrap_or((0, 0, 0));
    if min > own {
        return Err(tr!(
            "Vigil Pro {} benötigt Vigil {} oder neuer, installiert ist {}.",
            "Vigil Pro {} requires Vigil {} or newer, installed is {}.",
            m.version,
            m.min_core,
            crate::VERSION
        ));
    }
    Ok(m)
}

/// Prüft die sha256 einer Datei gegen das Manifest.
fn check_hash(m: &Manifest, name: &str, data: &[u8]) -> Result<(), Text> {
    let have = sha256_reader(&mut &data[..]).unwrap_or_default();
    if m.files.get(name).map(String::as_str) != Some(have.as_str()) {
        return Err(tr!(
            "Die Prüfsumme (sha256) von {} passt nicht zum Manifest.",
            "The checksum (sha256) of {} does not match the manifest.",
            name
        ));
    }
    Ok(())
}

/// `pro-install --dir <ordner> --token <t>`: prüft Freigabe, Signaturen aller vier Dateien,
/// sha256 laut Manifest und minCore, installiert nach `/usr/lib/vigil/pro/` und speichert die
/// Freigabe. `install-hooks` startet danach der Helfer.
pub fn install(dir: &Path, token: &str) -> Result<Manifest, ProError> {
    sign::verify_token(token, true).map_err(inactive)?;

    // Alles in den Speicher lesen und dort prüfen; installiert wird genau das Geprüfte
    let (manifest_data, manifest_sig) = read_signed(dir, MANIFEST, 1024 * 1024)?;
    let manifest = parse_manifest(&manifest_data)?;
    let mut files: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut sigs: Vec<(String, Vec<u8>)> = vec![(format!("{MANIFEST}.sig"), manifest_sig)];
    for name in PRO_FILES {
        let (data, sig) = read_signed(dir, name, MAX_FILE_SIZE)?;
        check_hash(&manifest, name, &data)?;
        files.push((name, data));
        sigs.push((format!("{name}.sig"), sig));
    }

    // Neuen Ordner neben dem Ziel aufbauen, dann austauschen
    let lib = paths::lib_dir();
    let target = paths::pro_dir();
    let staging = lib.join(format!(".pro-new-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    let build = || -> Result<(), Text> {
        fsutil::ensure_dir(&staging, 0o755)?;
        fsutil::write_atomic(&staging.join(MANIFEST), &manifest_data, 0o644)?;
        for (name, data) in &files {
            let mode = if *name == PRO_UI { 0o644 } else { 0o755 };
            fsutil::write_atomic(&staging.join(name), data, mode)?;
        }
        for (name, data) in &sigs {
            fsutil::write_atomic(&staging.join(name), data, 0o644)?;
        }
        Ok(())
    };
    if let Err(e) = build() {
        let _ = fs::remove_dir_all(&staging);
        return Err(ProError::Failed(e));
    }
    let old = lib.join(format!(".pro-old-{}", std::process::id()));
    let had_old = target.exists();
    let swap = || -> std::io::Result<()> {
        if had_old {
            fs::rename(&target, &old)?;
        }
        if let Err(e) = fs::rename(&staging, &target) {
            if had_old {
                let _ = fs::rename(&old, &target);
            }
            return Err(e);
        }
        Ok(())
    };
    if let Err(e) = swap() {
        let _ = fs::remove_dir_all(&staging);
        return Err(ProError::Failed(tr!(
            "Vigil Pro konnte nicht nach {} installiert werden: {}",
            "Could not install Vigil Pro into {}: {}",
            target.display(),
            e
        )));
    }
    let _ = fs::remove_dir_all(&old);
    fsutil::sync_dir(&lib);

    save_token(token)?;
    Ok(manifest)
}

/// Speichert die Freigabe (Ordner 0700, Datei 0600).
fn save_token(token: &str) -> Result<(), Text> {
    fsutil::ensure_dir(&paths::pro_data_dir(), 0o700)?;
    fsutil::write_atomic(&paths::pro_token_path(), token.trim().as_bytes(), 0o600)
}

/// Gespeicherte Freigabe (ohne Prüfung).
fn stored_token() -> Result<String, ProError> {
    match fs::read_to_string(paths::pro_token_path()) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(inactive(tr!("Es ist keine Freigabe gespeichert.", "No activation token is stored.")))
        }
        Err(e) => Err(ProError::Failed(tr!(
            "Die Freigabe konnte nicht gelesen werden: {}",
            "Could not read the activation token: {}",
            e
        ))),
    }
}

/// Prüft die gespeicherte Freigabe (Signatur, nicht abgelaufen).
pub fn check_active() -> Result<TokenClaims, ProError> {
    sign::verify_token(&stored_token()?, true).map_err(inactive)
}

/// `pro-token --token <t>`: ersetzt die gespeicherte Freigabe durch eine gültig signierte,
/// nicht abgelaufene Freigabe derselben Lizenz.
pub fn update_token(token: &str) -> Result<TokenClaims, ProError> {
    let new = sign::verify_token(token, true).map_err(inactive)?;
    // Die alte Freigabe darf abgelaufen sein, muss aber echt sein
    let old = sign::verify_token(&stored_token()?, false).map_err(inactive)?;
    if old.lic != new.lic {
        return Err(inactive(tr!(
            "Die neue Freigabe gehört zu einer anderen Lizenz.",
            "The new activation token belongs to a different license."
        )));
    }
    save_token(token)?;
    Ok(new)
}

/// Unter Windows liegen die Pro-Dateien im Installationsordner (Programme), den nur
/// Administratoren ändern dürfen. Geprüft wird, dass keine Verknüpfung untergeschoben ist.
#[cfg(windows)]
fn check_owner(p: &Path) -> Result<(), Text> {
    let m = fs::symlink_metadata(p).map_err(|e| tr!("{} ist nicht lesbar: {}", "{} is not readable: {}", p.display(), e))?;
    if m.file_type().is_symlink() {
        return Err(tr!(
            "{} hat unsichere Rechte oder einen fremden Besitzer.",
            "{} has unsafe permissions or a foreign owner.",
            p.display()
        ));
    }
    Ok(())
}

/// Rechte einer installierten Datei: gehört dem Helfer (root) und ist für andere nicht beschreibbar.
#[cfg(unix)]
fn check_owner(p: &Path) -> Result<(), Text> {
    let m = fs::symlink_metadata(p)
        .map_err(|e| tr!("{} ist nicht lesbar: {}", "{} is not readable: {}", p.display(), e))?;
    // SAFETY: geteuid hat keine Vorbedingungen
    let euid = unsafe { libc::geteuid() };
    if m.file_type().is_symlink() || m.uid() != euid || m.permissions().mode() & 0o022 != 0 {
        return Err(tr!(
            "{} hat unsichere Rechte oder einen fremden Besitzer.",
            "{} has unsafe permissions or a foreign owner.",
            p.display()
        ));
    }
    Ok(())
}

/// Ist Vigil Pro installiert (Ordner vorhanden)?
pub fn is_installed() -> bool {
    paths::pro_dir().join(PRO_BIN).exists()
}

/// Liest eine installierte Pro-Datei und prüft Rechte, Signatur des Manifests, Signatur der
/// Datei und sha256 laut Manifest. Auch für die App (z. B. `pro-ui.js`).
pub fn read_verified(name: &str) -> Result<(Manifest, Vec<u8>), Text> {
    if !PRO_FILES.contains(&name) {
        return Err(tr!("Unbekannte Pro-Datei: {}", "Unknown Pro file: {}", name));
    }
    let dir = paths::pro_dir();
    if !dir.join(name).exists() {
        return Err(tr!("Vigil Pro ist nicht installiert.", "Vigil Pro is not installed."));
    }
    check_owner(&dir)?;
    for n in [MANIFEST.to_string(), format!("{MANIFEST}.sig"), name.to_string(), format!("{name}.sig")] {
        check_owner(&dir.join(n))?;
    }
    let manifest = parse_manifest(&read_signed(&dir, MANIFEST, 1024 * 1024)?.0)?;
    let (data, _) = read_signed(&dir, name, MAX_FILE_SIZE)?;
    check_hash(&manifest, name, &data)?;
    Ok((manifest, data))
}

/// Befehl für `/usr/lib/vigil/pro/vigil-pro --mode ro|rw --lang de|en <args…>` mit leerer
/// Umgebung (nur PATH, LANG=C.UTF-8, VIGIL_DATA_DIR). Vorher [`read_verified`] aufrufen.
/// Endet der Helfer, erhält vigil-pro SIGTERM.
#[cfg(windows)]
pub fn command(mode: Mode, lang: Lang, args: &[String]) -> Command {
    use std::os::windows::process::CommandExt;
    let sys = crate::win::system_dir();
    let windir = sys.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut c = Command::new(pro_bin_path());
    c.arg("--mode")
        .arg(mode.as_str())
        .arg("--lang")
        .arg(lang.as_str())
        .args(args)
        .env_clear()
        .env("SystemRoot", &windir)
        .env("windir", &windir)
        .env("PATH", &sys)
        .env("ProgramData", crate::win::program_data())
        .env("VIGIL_DATA_DIR", paths::data_dir())
        .stdin(Stdio::null())
        .creation_flags(crate::win::CREATE_NO_WINDOW);
    c
}

/// Befehl für vigil-pro (Linux), siehe oben.
#[cfg(unix)]
pub fn command(mode: Mode, lang: Lang, args: &[String]) -> Command {
    let mut c = Command::new(pro_bin_path());
    c.arg("--mode")
        .arg(mode.as_str())
        .arg("--lang")
        .arg(lang.as_str())
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .env("VIGIL_DATA_DIR", paths::data_dir())
        .stdin(Stdio::null());
    // SAFETY: prctl ist im Kindprozess vor exec erlaubt (async-signal-sicher)
    unsafe {
        c.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    c
}

/// Pfad von `vigil-pro`.
pub fn pro_bin_path() -> PathBuf {
    paths::pro_dir().join(PRO_BIN)
}

/// Entfernt Ordner und Freigabe (nach `remove-hooks`, das der Helfer vorher startet).
pub fn remove_files() -> Result<(), Text> {
    let dir = paths::pro_dir();
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(tr!(
                "Der Ordner {} konnte nicht entfernt werden: {}",
                "Could not remove the folder {}: {}",
                dir.display(),
                e
            ))
        }
    }
    match fs::remove_file(paths::pro_token_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(tr!("Die Freigabe konnte nicht gelöscht werden: {}", "Could not delete the activation token: {}", e)),
    }
}
