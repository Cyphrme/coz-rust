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

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestBytes(#[serde(with = "crate::b64")] Vec<u8>);

    #[test]
    fn round_trip_empty() {
        let original = TestBytes(vec![]);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#""""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_single_zero() {
        let original = TestBytes(vec![0]);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#""AA""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_bytes() {
        let original = TestBytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#""3q2-7w""#);
        let decoded: TestBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_invalid_base64() {
        let result: Result<TestBytes, _> = serde_json::from_str(r#""not valid!!!""#);
        assert!(result.is_err());
    }

    #[test]
    fn golden_thumbprint() {
        // From Coz spec: thumbprint "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
        let tmb_b64 = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();
        assert_eq!(bytes.len(), 32); // SHA-256 output

        let re_encoded = Base64UrlUnpadded::encode_string(&bytes);
        assert_eq!(re_encoded, tmb_b64);
    }
}
