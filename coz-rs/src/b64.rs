//! Base64 URL-safe encoding with truncated padding (b64ut).
//!
//! This module provides serde serialization helpers for encoding bytes as
//! [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) base64 URL-safe
//! with padding truncated.
//!
//! # Usage
//!
//! Apply to struct fields using `#[serde(with = "crate::b64")]`:
//!
//! ```ignore
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct Digest(#[serde(with = "crate::b64")] Vec<u8>);
//! ```

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serializer, de};

/// Serialize bytes as b64ut string.
pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&Base64UrlUnpadded::encode_string(bytes))
}

/// Deserialize b64ut string to bytes.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    Base64UrlUnpadded::decode_vec(&s).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    /// Simple wrapper for testing serde with b64
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestBytes(#[serde(with = "crate::b64")] Vec<u8>);

    /// Struct wrapper to test JSON object serialization (like Go's B64Struct)
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct B64Struct {
        #[serde(rename = "B", with = "crate::b64")]
        b: Vec<u8>,
    }

    // ===== Basic round-trip tests =====

    #[test]
    fn round_trip_empty() {
        // B64 of empty/nil is ""
        let original = TestBytes(vec![]);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#""""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_single_zero() {
        // B64 of [0] is "AA" (not empty!)
        let original = TestBytes(vec![0]);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#""AA""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_0x00_0xff() {
        // From Go: [0, 255] encodes to "AP8"
        let original = TestBytes(vec![0, 255]);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#""AP8""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_bytes() {
        let original = TestBytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let json = serde_json::to_string(&original).unwrap();
        // URL-safe: uses - instead of +
        assert_eq!(json, r#""3q2-7w""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn url_safe_alphabet() {
        // Verify URL-safe characters are used (- and _ instead of + and /)
        // Bytes that would produce + and / in standard base64
        let bytes = vec![0xfb, 0xff, 0xbf]; // Would be +/+/ in standard
        let encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert!(!encoded.contains('+'), "should use - not +");
        assert!(!encoded.contains('/'), "should use _ not /");
    }

    // ===== JSON struct tests (like Go's B64Struct) =====

    #[test]
    fn json_struct_round_trip() {
        // From Go: {"B":"AP8"}
        let original = B64Struct { b: vec![0, 255] };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"B":"AP8"}"#);
        let decoded: B64Struct = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn json_struct_unmarshal() {
        let json = r#"{"B":"AP8"}"#;
        let decoded: B64Struct = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.b, vec![0, 255]);
    }

    // ===== Error cases =====

    #[test]
    fn decode_invalid_base64() {
        let result: Result<TestBytes, _> = serde_json::from_str(r#""not valid!!!""#);
        assert!(result.is_err());
    }

    #[test]
    fn decode_non_canonical_rejected() {
        // From Go test: "hOk" and "hOl" both decode to same bytes (0x84, 0xE9)
        // in non-strict mode, but "hOl" is non-canonical and should error.
        // base64ct uses strict decoding so "hOl" should fail.
        let canonical: Result<TestBytes, _> = serde_json::from_str(r#""hOk""#);
        assert!(canonical.is_ok());

        let non_canonical: Result<TestBytes, _> = serde_json::from_str(r#""hOl""#);
        assert!(
            non_canonical.is_err(),
            "non-canonical base64 should be rejected"
        );
    }

    #[test]
    fn decode_with_padding_rejected() {
        // Padding characters should be rejected in b64ut
        let result: Result<TestBytes, _> = serde_json::from_str(r#""AP8=""#);
        assert!(result.is_err(), "padding should be rejected");
    }

    #[test]
    fn decode_standard_base64_rejected() {
        // Standard base64 characters + and / should fail
        let result: Result<TestBytes, _> = serde_json::from_str(r#""+/+/""#);
        assert!(
            result.is_err(),
            "standard base64 alphabet should be rejected"
        );
    }

    // ===== Golden values from Coz spec =====

    #[test]
    fn golden_thumbprint() {
        // From Coz spec: thumbprint "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
        let tmb_b64 = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();
        assert_eq!(bytes.len(), 32); // SHA-256 output

        let re_encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert_eq!(re_encoded, tmb_b64);
    }

    #[test]
    fn golden_signature() {
        // From Coz spec: signature for example message
        let sig_b64 = "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg";
        let bytes = Base64UrlUnpadded::decode_vec(sig_b64).unwrap();
        assert_eq!(bytes.len(), 64); // ES256 signature size

        let re_encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert_eq!(re_encoded, sig_b64);
    }

    #[test]
    fn golden_public_key() {
        // From Coz spec: public key
        let pub_b64 = "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g";
        let bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
        assert_eq!(bytes.len(), 64); // ES256 public key (X || Y)

        let re_encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert_eq!(re_encoded, pub_b64);
    }

    #[test]
    fn golden_cad() {
        // From Coz spec: canonical digest
        let cad_b64 = "XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU";
        let bytes = Base64UrlUnpadded::decode_vec(cad_b64).unwrap();
        assert_eq!(bytes.len(), 32); // SHA-256

        let re_encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert_eq!(re_encoded, cad_b64);
    }

    #[test]
    fn golden_czd() {
        // From Coz spec: coz digest
        let czd_b64 = "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo";
        let bytes = Base64UrlUnpadded::decode_vec(czd_b64).unwrap();
        assert_eq!(bytes.len(), 32); // SHA-256

        let re_encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert_eq!(re_encoded, czd_b64);
    }
}
