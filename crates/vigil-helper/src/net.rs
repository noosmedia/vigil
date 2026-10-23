//! Abfrage der neuesten Version beim Update-Server und Herunterladen für `self-update --auto`
//! (HTTPS über rustls, kein OpenSSL).

use std::time::Duration;
use vigil_core::i18n::Text;
use vigil_core::selfupdate::{self, MAX_DEB_SIZE, UPDATE_API};
use vigil_core::{paths, sign, tr};

/// Neueste Veröffentlichung mit den Adressen der beiden Dateien.
pub struct Release {
    pub version: String,
    tag: String,
    deb_url: Option<String>,
    sig_url: Option<String>,
}

/// HTTP-Zugang mit Zeitgrenze und User-Agent `Vigil/<version>`. Nur HTTPS, außer im Testbetrieb.
fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .timeout_connect(Some(Duration::from_secs(20)))
        .https_only(!paths::is_dev())
        .user_agent(format!("Vigil/{}", vigil_core::VERSION))
        .build()
        .into()
}

fn net_err(url: &str, e: ureq::Error) -> Text {
    tr!("Die Anfrage an {} ist fehlgeschlagen: {}", "The request to {} failed: {}", url, e)
}

/// Adresse der Release-Abfrage. Im Testbetrieb überschreibt `VIGIL_UPDATE_API`.
fn latest_url() -> String {
    paths::dev_value("VIGIL_UPDATE_API")
        .unwrap_or_else(|| UPDATE_API.to_string())
}

/// Fragt die neueste Veröffentlichung ab (`tag_name` `vX.Y.Z`, Assets `.deb` und `.deb.sig`).
pub fn latest_release() -> Result<Release, Text> {
    let url = latest_url();
    let mut resp = agent(Duration::from_secs(60))
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| net_err(&url, e))?;
    let body = resp.body_mut().with_config().limit(4 * 1024 * 1024).read_to_string().map_err(|e| net_err(&url, e))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| tr!("Die Antwort des Update-Servers ist nicht lesbar: {}", "The answer from the update server is not readable: {}", e))?;
    let tag = v.get("tag_name").and_then(|t| t.as_str()).unwrap_or_default();
    let version = tag.strip_prefix('v').unwrap_or_default().to_string();
    if sign::parse_version(&version).is_none() {
        return Err(tr!("Die neueste Version hat ein ungültiges Kennzeichen: {}", "The latest release has an invalid tag: {}", tag));
    }
    let deb_name = selfupdate::deb_asset_name(&version);
    let sig_name = format!("{deb_name}.sig");
    let assets = v.get("assets").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    let find = |name: &str| {
        assets
            .iter()
            .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
            .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
            .map(str::to_string)
    };
    Ok(Release { deb_url: find(&deb_name), sig_url: find(&sig_name), tag: tag.to_string(), version })
}

/// Lädt eine Datei herunter (höchstens `max` Byte).
fn download(url: &str, max: u64) -> Result<Vec<u8>, Text> {
    let mut resp = agent(Duration::from_secs(15 * 60)).get(url).call().map_err(|e| net_err(url, e))?;
    resp.body_mut().with_config().limit(max).read_to_vec().map_err(|e| net_err(url, e))
}

/// Lädt .deb und .sig einer Veröffentlichung direkt in den Update-Ordner.
pub fn download_release(r: &Release) -> Result<selfupdate::Staged, Text> {
    let missing = |name: String| {
        tr!("Die Veröffentlichung {} enthält keine Datei {}.", "The release {} does not contain the file {}.", r.tag, name)
    };
    let deb_name = selfupdate::deb_asset_name(&r.version);
    let sig_url = r.sig_url.as_deref().ok_or_else(|| missing(format!("{deb_name}.sig")))?;
    let deb_url = r.deb_url.as_deref().ok_or_else(|| missing(deb_name.clone()))?;
    let sig = download(sig_url, 4096)?;
    let deb = download(deb_url, MAX_DEB_SIZE)?;
    let staged = selfupdate::new_staged()?;
    let w = vigil_core::fsutil::write_atomic(&staged.deb, &deb, 0o600)
        .and_then(|_| vigil_core::fsutil::write_atomic(&staged.sig, &sig, 0o600));
    if let Err(e) = w {
        staged.cleanup();
        return Err(e);
    }
    Ok(staged)
}
