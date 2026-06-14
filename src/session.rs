//! Session-token format and (de)serialisation.
//!
//! A session token is `base64(payload_json) + "." + hex(stamp)`, where the
//! stamp is the [`SecurityModule`](wyrtloom_core::security::SecurityModule) HMAC
//! over the exact `payload_json` bytes. The payload carries the user id, the
//! roles AT MINT TIME (informational only — never trusted on verify), the
//! absolute expiry, and a per-session nonce used for revocation.
//!
//! SECURITY: the token's `roles` are advisory. On every request the user is
//! re-fetched from the directory and the *current* roles + `active` flag are
//! authoritative (see `auth.rs`). This prevents a stolen/long-lived token from
//! retaining elevated privileges after a role change or account disable.

use base64::Engine;
use serde::{Deserialize, Serialize};

use wyrtloom_core::security::{SecurityModule, Stamp};
use wyrtloom_core::users::Role;

/// Decoded session payload. Serialised deterministically (serde preserves field
/// order) so the bytes that are signed match the bytes that are verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPayload {
    pub user_id: String,
    pub roles: Vec<Role>,
    pub exp_unix: i64,
    pub nonce: String,
}

/// Errors that can occur while parsing/validating a token's structure (before
/// any cryptographic or freshness checks).
#[derive(Debug)]
pub enum TokenError {
    Malformed,
}

/// Mint a token for `payload` using `security` to stamp the payload bytes.
pub fn mint(security: &SecurityModule, payload: &SessionPayload) -> String {
    let payload_json = serde_json::to_vec(payload).expect("SessionPayload is always serialisable");
    let stamp = security.stamp(&payload_json);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&payload_json);
    format!("{b64}.{}", hex(&stamp.0))
}

/// Parse a token into `(payload, payload_bytes, stamp)` WITHOUT validating the
/// stamp, expiry, or revocation — callers in `auth.rs` perform those checks in
/// the security-mandated order (exp before is_valid before role re-fetch).
pub fn parse(token: &str) -> Result<(SessionPayload, Vec<u8>, Stamp), TokenError> {
    let (b64, stamp_hex) = token.split_once('.').ok_or(TokenError::Malformed)?;
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| TokenError::Malformed)?;
    let payload: SessionPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::Malformed)?;
    let stamp_bytes = hex_decode(stamp_hex).ok_or(TokenError::Malformed)?;
    let arr: [u8; 32] = stamp_bytes.try_into().map_err(|_| TokenError::Malformed)?;
    Ok((payload, payload_bytes, Stamp(arr)))
}

/// Lowercase hex-encode. Shared crate-internally (auth.rs reuses the decoder).
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Decode a lowercase/uppercase hex string. `None` on odd length or non-hex.
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::security::SecurityPolicy;

    #[test]
    fn mint_then_parse_roundtrips_and_verifies() {
        let sec = SecurityModule::with_key([3u8; 32], SecurityPolicy::deny_all());
        let payload = SessionPayload {
            user_id: "alice".into(),
            roles: vec![Role::Viewer],
            exp_unix: 1_000_000,
            nonce: "n1".into(),
        };
        let token = mint(&sec, &payload);
        let (back, bytes, stamp) = parse(&token).expect("parse");
        assert_eq!(back.user_id, "alice");
        assert!(sec.is_valid(&stamp, &bytes));
    }

    #[test]
    fn tampered_payload_fails_stamp() {
        let sec = SecurityModule::with_key([4u8; 32], SecurityPolicy::deny_all());
        let payload = SessionPayload {
            user_id: "bob".into(),
            roles: vec![Role::Admin],
            exp_unix: 1_000_000,
            nonce: "n2".into(),
        };
        let token = mint(&sec, &payload);
        // Forge a new payload with the same stamp segment.
        let stamp_hex = token.split_once('.').unwrap().1;
        let forged_payload = SessionPayload {
            user_id: "bob".into(),
            roles: vec![Role::Admin],
            exp_unix: 9_999_999,
            nonce: "n2".into(),
        };
        let forged_b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&forged_payload).unwrap());
        let forged_token = format!("{forged_b64}.{stamp_hex}");
        let (_, bytes, stamp) = parse(&forged_token).expect("parse");
        assert!(!sec.is_valid(&stamp, &bytes), "tampered payload must fail stamp");
    }

    #[test]
    fn garbage_tokens_are_malformed() {
        assert!(parse("no-dot").is_err());
        assert!(parse("####.zz").is_err());
    }
}
