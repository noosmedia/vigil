//! Signaturen und Prüfsummen: Updates und Pro-Pakete werden nur mit gültiger Ed25519-Signatur angenommen

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use vigil_core::paths;

/// Öffentlicher Schlüssel für Vigil-Updates (rohe 32 Byte, base64)
const RELEASE_PUBKEY: &str = "AObJDGT4x2SgDeBm4mPJdWQK4TJUzu/Abz5oHt/FkQg=";
/// Öffentlicher Schlüssel des Lizenzservers (Freigaben und Pro-Pakete)
const LICENSE_PUBKEY: &str = "KNcTRY44tDiDOr4WyuKpNmYPD51O3yVGBbNCC5yQjDE=";

// Im Testbetrieb dürfen Testschlüssel die eingebauten ersetzen
fn key_from(env_name: &str, builtin: &str) -> Option<VerifyingKey> {
    let b64 = if paths::is_dev() { std::env::var(env_name).unwrap_or_else(|_| builtin.to_string()) } else { builtin.to_string() };
    let raw = STANDARD.decode(b64.trim()).ok()?;
    let bytes: [u8; 32] = raw.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

fn verify_with(key: Option<VerifyingKey>, data: &[u8], sig_b64url: &str) -> bool {
    let Some(key) = key else { return false };
    let Ok(raw) = URL_SAFE_NO_PAD.decode(sig_b64url.trim().trim_end_matches('=')) else { return false };
    let Ok(sig) = Signature::from_slice(&raw) else { return false };
    key.verify(data, &sig).is_ok()
}

/// Signatur eines Vigil-Updates prüfen
pub fn verify_release(data: &[u8], sig: &str) -> bool {
    verify_with(key_from("VIGIL_UPDATE_PUBKEY", RELEASE_PUBKEY), data, sig)
}

/// Signatur des Lizenzservers prüfen
pub fn verify_license(data: &[u8], sig: &str) -> bool {
    verify_with(key_from("VIGIL_LICENSE_PUBKEY", LICENSE_PUBKEY), data, sig)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=')).ok()
}

/// Inhalt einer Freigabe (Token) des Lizenzservers
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TokenPayload {
    pub lic: String,
    pub inst: String,
    pub features: Vec<String>,
    pub version: String,
    pub iat: i64,
    pub exp: i64,
}

/// Freigabe prüfen: Signatur gültig und noch nicht abgelaufen
pub fn read_token(token: &str) -> Option<TokenPayload> {
    let (body, sig) = token.split_once('.')?;
    if !verify_license(body.as_bytes(), sig) {
        return None;
    }
    let payload: TokenPayload = serde_json::from_slice(&b64url_decode(body)?).ok()?;
    (payload.exp > chrono::Utc::now().timestamp_millis()).then_some(payload)
}

/// Zufällige Kennung aus dem Zufallsgenerator des Systems
pub fn random_id(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; len];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect()
}
