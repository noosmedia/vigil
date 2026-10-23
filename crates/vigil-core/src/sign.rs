//! Signaturen (Ed25519) für Updates von Vigil und für Vigil Pro, Pro-Freigaben (Token),
//! Base64 und Versionsvergleich. Auch für die App gedacht (sie prüft Downloads selbst).

use crate::i18n::Text;
use crate::paths;
use crate::tr;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Öffentlicher Schlüssel für Updates von Vigil (rohe 32 Byte, Base64).
pub const UPDATE_PUBLIC_KEY: &str = "AObJDGT4x2SgDeBm4mPJdWQK4TJUzu/Abz5oHt/FkQg=";

/// Öffentlicher Schlüssel des Lizenzservers für Freigaben und Pro-Dateien (rohe 32 Byte, Base64).
pub const LICENSE_PUBLIC_KEY: &str = "KNcTRY44tDiDOr4WyuKpNmYPD51O3yVGBbNCC5yQjDE=";

/// Welcher Schlüssel prüft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Updates von Vigil selbst.
    Update,
    /// Lizenzserver (Freigaben, Pro-Dateien).
    License,
}

impl KeyKind {
    /// Schlüssel als Base64. Nur im Testbetrieb (`VIGIL_DEV=1`) ersetzen
    /// `VIGIL_UPDATE_PUBKEY` bzw. `VIGIL_LICENSE_PUBKEY` den eingebauten Schlüssel.
    fn base64(&self) -> String {
        let (var, builtin) = match self {
            KeyKind::Update => ("VIGIL_UPDATE_PUBKEY", UPDATE_PUBLIC_KEY),
            KeyKind::License => ("VIGIL_LICENSE_PUBKEY", LICENSE_PUBLIC_KEY),
        };
        paths::dev_value(var).unwrap_or_else(|| builtin.to_string())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Text> {
        let raw = b64_decode(self.base64().trim())
            .ok_or_else(|| tr!("Der öffentliche Schlüssel ist ungültig.", "The public key is invalid."))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| tr!("Der öffentliche Schlüssel hat nicht 32 Byte.", "The public key is not 32 bytes long."))?;
        VerifyingKey::from_bytes(&arr).map_err(|_| tr!("Der öffentliche Schlüssel ist ungültig.", "The public key is invalid."))
    }
}

/// Dekodiert Base64 (Standard- und URL-Alphabet, mit oder ohne Auffüllung `=`).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Ein einzelnes übriges Zeichen (6 Bit) ist kein gültiges Base64; Restbits müssen null sein
    if bits >= 6 || acc != 0 {
        return None;
    }
    Some(out)
}

/// Prüft eine Ed25519-Signatur (Base64url, eine Zeile) über die Bytes `data`.
pub fn verify(kind: KeyKind, data: &[u8], signature_b64: &str) -> Result<(), Text> {
    let key = kind.verifying_key()?;
    let raw = b64_decode(signature_b64.trim())
        .ok_or_else(|| tr!("Die Signatur ist nicht lesbar (kein Base64).", "The signature is not readable (not Base64)."))?;
    let arr: [u8; 64] = raw
        .try_into()
        .map_err(|_| tr!("Die Signatur hat nicht 64 Byte.", "The signature is not 64 bytes long."))?;
    key.verify_strict(data, &Signature::from_bytes(&arr))
        .map_err(|_| tr!("Die Signatur ist ungültig.", "The signature is invalid."))
}

/// Inhalt einer Pro-Freigabe `{lic, inst, features[], version, iat, exp}` (Zeiten in ms seit Epoche).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub lic: String,
    #[serde(default)]
    pub inst: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub iat: i64,
    pub exp: i64,
}

/// Prüft eine Freigabe `<base64url(JSON)>.<base64url(Signatur über den ersten Teil)>` und liefert
/// ihren Inhalt. Mit `check_expiry` muss `exp` in der Zukunft liegen.
pub fn verify_token(token: &str, check_expiry: bool) -> Result<TokenClaims, Text> {
    let token = token.trim();
    if token.len() > 16 * 1024 {
        return Err(tr!("Die Freigabe ist zu lang.", "The activation token is too long."));
    }
    let (body, sig) = token
        .split_once('.')
        .ok_or_else(|| tr!("Die Freigabe hat ein ungültiges Format.", "The activation token has an invalid format."))?;
    verify(KeyKind::License, body.as_bytes(), sig)
        .map_err(|e| tr!("Die Freigabe ist nicht gültig signiert: {}", "The activation token is not validly signed: {}", e))?;
    let json = b64_decode(body)
        .ok_or_else(|| tr!("Die Freigabe ist nicht lesbar.", "The activation token is not readable."))?;
    let claims: TokenClaims = serde_json::from_slice(&json)
        .map_err(|e| tr!("Die Freigabe ist nicht lesbar: {}", "The activation token is not readable: {}", e))?;
    if claims.lic.is_empty() {
        return Err(tr!("Die Freigabe nennt keine Lizenz.", "The activation token names no license."));
    }
    if check_expiry && claims.exp <= chrono::Utc::now().timestamp_millis() {
        return Err(tr!("Die Freigabe ist abgelaufen.", "The activation token has expired."));
    }
    Ok(claims)
}

/// Zerlegt eine Version `X.Y.Z` (ohne Zusätze) in Zahlen.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    it.next().is_none().then_some((a, b, c))
}
