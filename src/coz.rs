//! Coz message types.
//!
//! This module provides [`Pay`] (payload), [`PayBuilder`] for ergonomic
//! construction, and [`Coz`] for signed messages.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::alg::Algorithm;
use crate::canon::{Cad, Czd, canonical_hash};
use crate::error::Result;
use crate::key::{SigningKey, Thumbprint, VerifyingKey};

// ============================================================================
// Pay - Payload
// ============================================================================

/// Standard Coz payload fields.
///
/// Contains the standard fields (`alg`, `now`, `tmb`, `typ`) plus optional
/// message (`msg`) and digest (`dig`) fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pay {
    /// Algorithm name (e.g., "ES256").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Unix timestamp of signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<i64>,

    /// Key thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmb: Option<Thumbprint>,

    /// Application-defined type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Message content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,

    /// Digest of external content.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_b64")]
    pub dig: Option<Vec<u8>>,

    /// Revocation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rvk: Option<i64>,

    /// Additional custom fields.
    #[serde(flatten)]
    pub extra: IndexMap<String, Value>,
}

/// Helper for optional b64 fields.
mod option_b64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        opt: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match opt {
            Some(bytes) => serializer.serialize_str(&Base64UrlUnpadded::encode_string(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => Base64UrlUnpadded::decode_vec(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

impl Pay {
    /// Create a new empty payload.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this is a revocation payload.
    pub fn is_revoke(&self) -> bool {
        self.rvk.map(|r| r > 0).unwrap_or(false)
    }
}

// ============================================================================
// PayBuilder
// ============================================================================

/// Builder for constructing [`Pay`] payloads.
///
/// # Example
///
/// ```ignore
/// let pay = PayBuilder::new()
///     .msg("Hello, Coz!")
///     .typ("example/hello")
///     .build();
/// ```
#[derive(Debug, Default)]
#[must_use = "builders do nothing unless you call .build() or .sign()"]
pub struct PayBuilder {
    pay: Pay,
}

impl PayBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the message content.
    pub fn msg(mut self, msg: impl Into<String>) -> Self {
        self.pay.msg = Some(msg.into());
        self
    }

    /// Set the type.
    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.pay.typ = Some(typ.into());
        self
    }

    /// Set the algorithm.
    pub fn alg(mut self, alg: impl Into<String>) -> Self {
        self.pay.alg = Some(alg.into());
        self
    }

    /// Set the timestamp.
    pub fn now(mut self, now: i64) -> Self {
        self.pay.now = Some(now);
        self
    }

    /// Set the thumbprint.
    pub fn tmb(mut self, tmb: Thumbprint) -> Self {
        self.pay.tmb = Some(tmb);
        self
    }

    /// Set the external content digest.
    pub fn dig(mut self, dig: Vec<u8>) -> Self {
        self.pay.dig = Some(dig);
        self
    }

    /// Set the revocation timestamp.
    pub fn rvk(mut self, rvk: i64) -> Self {
        self.pay.rvk = Some(rvk);
        self
    }

    /// Set a custom field.
    pub fn field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.pay.extra.insert(key.into(), value);
        self
    }

    /// Build the payload.
    pub fn build(self) -> Pay {
        self.pay
    }

    /// Build and sign the payload, returning a [`Coz`] message.
    pub fn sign<A>(mut self, key: &SigningKey<A>) -> Result<Coz<A>>
    where
        A: Algorithm + crate::key::ops::KeyOps,
    {
        // Set standard fields from key
        self.pay.alg = Some(A::NAME.to_string());
        self.pay.tmb = Some(key.thumbprint().clone());

        Coz::sign(self.pay, key)
    }
}

// ============================================================================
// Coz - Signed Message
// ============================================================================

/// A signed Coz message.
///
/// Contains the payload, signature, and computed digests.
pub struct Coz<A: Algorithm> {
    /// The payload.
    pub pay: Pay,

    /// Signature over the canonical digest.
    sig: Vec<u8>,

    /// Canonical digest of pay.
    cad: Cad,

    /// Coz digest of {cad, sig}.
    czd: Czd,

    /// Phantom for algorithm.
    _marker: std::marker::PhantomData<A>,
}

impl<A> Coz<A>
where
    A: Algorithm + crate::key::ops::KeyOps,
{
    /// Sign a payload and create a Coz message.
    pub fn sign(pay: Pay, key: &SigningKey<A>) -> Result<Self> {
        // Serialize pay to JSON
        let pay_json = serde_json::to_vec(&pay)?;

        // Compute canonical digest
        let cad = canonical_hash::<A>(&pay_json, None)?;

        // Sign the cad
        let sig = key.sign(cad.as_bytes());

        // Compute czd
        let czd = Czd::compute::<A>(&cad, &sig);

        Ok(Self {
            pay,
            sig,
            cad,
            czd,
            _marker: std::marker::PhantomData,
        })
    }

    /// Verify the signature.
    pub fn verify(&self, key: &VerifyingKey<A>) -> bool {
        key.verify(self.cad.as_bytes(), &self.sig)
    }

    /// Get the signature bytes.
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }

    /// Get the canonical digest.
    pub fn cad(&self) -> &Cad {
        &self.cad
    }

    /// Get the coz digest.
    pub fn czd(&self) -> &Czd {
        &self.czd
    }

    /// Get the algorithm name.
    pub fn algorithm(&self) -> &'static str {
        A::NAME
    }
}

// ============================================================================
// Serialization for Coz
// ============================================================================

/// JSON representation of a Coz message.
#[derive(Serialize, Deserialize)]
struct CozJson {
    pay: Value,
    #[serde(with = "crate::b64")]
    sig: Vec<u8>,
}

impl<A: Algorithm + crate::key::ops::KeyOps> Serialize for Coz<A> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pay_value = serde_json::to_value(&self.pay).map_err(serde::ser::Error::custom)?;
        let json = CozJson {
            pay: pay_value,
            sig: self.sig.clone(),
        };
        json.serialize(serializer)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::ES256;

    #[test]
    fn pay_builder_basic() {
        let pay = PayBuilder::new()
            .msg("Hello, Coz!")
            .typ("example/hello")
            .build();

        assert_eq!(pay.msg, Some("Hello, Coz!".to_string()));
        assert_eq!(pay.typ, Some("example/hello".to_string()));
    }

    #[test]
    fn pay_serialize() {
        let pay = PayBuilder::new().msg("test").alg("ES256").build();

        let json = serde_json::to_string(&pay).unwrap();
        assert!(json.contains("\"msg\":\"test\""));
        assert!(json.contains("\"alg\":\"ES256\""));
    }

    #[test]
    fn pay_custom_fields() {
        let pay = PayBuilder::new()
            .msg("test")
            .field("custom", Value::String("value".to_string()))
            .build();

        let json = serde_json::to_string(&pay).unwrap();
        assert!(json.contains("\"custom\":\"value\""));
    }

    #[test]
    fn coz_sign_and_verify() {
        let key = SigningKey::<ES256>::generate();
        let coz = PayBuilder::new()
            .msg("Hello, Coz!")
            .typ("example/hello")
            .sign(&key)
            .unwrap();

        assert!(coz.verify(key.verifying_key()));
        assert_eq!(coz.algorithm(), "ES256");
        assert_eq!(coz.sig().len(), 64);
        assert_eq!(coz.cad().as_bytes().len(), 32);
        assert_eq!(coz.czd().as_bytes().len(), 32);
    }

    #[test]
    fn coz_verify_wrong_key_fails() {
        let key1 = SigningKey::<ES256>::generate();
        let key2 = SigningKey::<ES256>::generate();

        let coz = PayBuilder::new().msg("test").sign(&key1).unwrap();

        assert!(!coz.verify(key2.verifying_key()));
    }

    #[test]
    fn coz_serialize() {
        let key = SigningKey::<ES256>::generate();
        let coz = PayBuilder::new().msg("test").sign(&key).unwrap();

        let json = serde_json::to_string(&coz).unwrap();
        assert!(json.contains("\"pay\":"));
        assert!(json.contains("\"sig\":"));
    }

    #[test]
    fn pay_is_revoke() {
        let mut pay = Pay::new();
        assert!(!pay.is_revoke());

        pay.rvk = Some(1623132000);
        assert!(pay.is_revoke());

        pay.rvk = Some(0);
        assert!(!pay.is_revoke());
    }
}
