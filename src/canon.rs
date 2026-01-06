//! JSON canonicalization for Coz.
//!
//! This module provides functions for extracting field order, generating
//! canonical JSON forms, and computing canonical digests.

use digest::Digest;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::alg::Algorithm;
use crate::error::Result;

// ============================================================================
// Constants
// ============================================================================

/// Canon for key thumbprint: `["alg", "pub"]`
pub const KEY_CANON: &[&str] = &["alg", "pub"];

/// Canon for czd: `["cad", "sig"]`
pub const CZD_CANON: &[&str] = &["cad", "sig"];

// ============================================================================
// Cad - Canonical Digest
// ============================================================================

/// Canonical digest of the payload.
///
/// This is the hash of the canonical JSON form of `pay`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cad(#[serde(with = "crate::b64")] Vec<u8>);

impl Cad {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode as b64ut string.
    pub fn to_b64(&self) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

impl std::fmt::Display for Cad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_b64())
    }
}

// ============================================================================
// Czd - Coz Digest
// ============================================================================

/// Coz digest - hash of canonical `{"cad":"...","sig":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Czd(#[serde(with = "crate::b64")] Vec<u8>);

impl Czd {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode as b64ut string.
    pub fn to_b64(&self) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        Base64UrlUnpadded::encode_string(&self.0)
    }

    /// Compute czd from cad and signature bytes.
    pub fn compute<A: Algorithm>(cad: &Cad, sig: &[u8]) -> Self {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let cad_b64 = cad.to_b64();
        let sig_b64 = Base64UrlUnpadded::encode_string(sig);
        let canonical = format!(r#"{{"cad":"{}","sig":"{}"}}"#, cad_b64, sig_b64);

        let hash = <A::Hasher>::digest(canonical.as_bytes());
        Self::from_bytes(hash.to_vec())
    }
}

impl std::fmt::Display for Czd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_b64())
    }
}

// ============================================================================
// Canon functions
// ============================================================================

/// Extract the field names (canon) from JSON in order of appearance.
///
/// Only extracts top-level fields, no recursion.
pub fn canon(json: &[u8]) -> Result<Vec<String>> {
    let map: IndexMap<String, serde_json::Value> = serde_json::from_slice(json)?;
    Ok(map.keys().cloned().collect())
}

/// Generate the canonical form of JSON.
///
/// If `fields` is `None`, the input is only compactified.
/// If `fields` is `Some`, only those fields are included in the specified order.
pub fn canonical(input: &[u8], fields: Option<&[&str]>) -> Result<Vec<u8>> {
    match fields {
        None => {
            // Compact the JSON while preserving field order
            let map: IndexMap<String, serde_json::Value> = serde_json::from_slice(input)?;
            Ok(serde_json::to_vec(&map)?)
        },
        Some(field_list) => {
            // Parse into map, extract only specified fields in order
            let map: IndexMap<String, serde_json::Value> = serde_json::from_slice(input)?;

            let mut result = IndexMap::new();
            for &field in field_list {
                if let Some(value) = map.get(field) {
                    result.insert(field.to_string(), value.clone());
                }
            }

            Ok(serde_json::to_vec(&result)?)
        },
    }
}

/// Compute the canonical hash of JSON.
///
/// Uses the algorithm's associated hasher.
pub fn canonical_hash<A: Algorithm>(input: &[u8], fields: Option<&[&str]>) -> Result<Cad> {
    let canonical_bytes = canonical(input, fields)?;
    let hash = <A::Hasher>::digest(&canonical_bytes);
    Ok(Cad::from_bytes(hash.to_vec()))
}

/// Compute a hash using SHA-256 (for thumbprints).
pub fn hash_sha256(input: &[u8]) -> Vec<u8> {
    Sha256::digest(input).to_vec()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::ES256;

    #[test]
    fn canon_extracts_field_order() {
        let json = br#"{"msg":"hello","alg":"ES256","tmb":"abc"}"#;
        let fields = canon(json).unwrap();
        assert_eq!(fields, vec!["msg", "alg", "tmb"]);
    }

    #[test]
    fn canonical_compact_only() {
        let json = br#"{ "a" : 1 , "b" : 2 }"#;
        let result = canonical(json, None).unwrap();
        assert_eq!(result, br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_with_fields() {
        let json = br#"{"c":3,"a":1,"b":2}"#;
        let result = canonical(json, Some(&["a", "b"])).unwrap();
        // Only a and b in that order
        assert_eq!(result, br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_reorders_fields() {
        let json = br#"{"z":26,"a":1,"m":13}"#;
        let result = canonical(json, Some(&["a", "m", "z"])).unwrap();
        assert_eq!(result, br#"{"a":1,"m":13,"z":26}"#);
    }

    #[test]
    fn canonical_missing_field_omitted() {
        let json = br#"{"a":1,"b":2}"#;
        let result = canonical(json, Some(&["a", "c", "b"])).unwrap();
        // c is missing, so only a and b
        assert_eq!(result, br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_hash_es256() {
        let json = br#"{"msg":"test","alg":"ES256"}"#;
        let cad = canonical_hash::<ES256>(json, None).unwrap();
        assert_eq!(cad.as_bytes().len(), 32); // SHA-256
    }

    #[test]
    fn cad_to_b64() {
        let cad = Cad::from_bytes(vec![0; 32]);
        let b64 = cad.to_b64();
        assert_eq!(b64.len(), 43); // 32 bytes in b64ut
        assert!(!b64.contains('='));
    }

    #[test]
    fn czd_compute() {
        let cad = Cad::from_bytes(vec![0; 32]);
        let sig = vec![0; 64];
        let czd = Czd::compute::<ES256>(&cad, &sig);
        assert_eq!(czd.as_bytes().len(), 32);
    }

    #[test]
    fn golden_key_canon() {
        assert_eq!(KEY_CANON, &["alg", "pub"]);
    }

    #[test]
    fn golden_czd_canon() {
        assert_eq!(CZD_CANON, &["cad", "sig"]);
    }
}
