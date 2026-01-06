//! Key types for Coz cryptographic operations.
//!
//! This module provides [`SigningKey`] and [`VerifyingKey`] types that wrap
//! RustCrypto implementations and add Coz-specific functionality like
//! thumbprint calculation.

use std::marker::PhantomData;

use digest::Digest;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::alg::{Algorithm, ES256, ES384, ES512, Ed25519};

// ============================================================================
// Thumbprint
// ============================================================================

/// A key thumbprint - the hash of the canonical `{"alg":"...","pub":"..."}`.
///
/// Thumbprints uniquely identify keys and are always SHA-256 (32 bytes),
/// regardless of the algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbprint(#[serde(with = "crate::b64")] Vec<u8>);

impl Thumbprint {
    /// Create a thumbprint from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the thumbprint.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode as b64ut string.
    pub fn to_b64(&self) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

impl std::fmt::Display for Thumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_b64())
    }
}

// ============================================================================
// Key traits for algorithm-specific operations
// ============================================================================

/// Internal trait for algorithm-specific key operations.
///
/// This trait is implemented for each algorithm to provide the concrete
/// RustCrypto types and operations.
pub(crate) trait KeyOps: Algorithm {
    type SigningKeyInner;
    type VerifyingKeyInner;

    fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner;
    fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner;
    fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8>;
    fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8>;
    fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool;
}

// ============================================================================
// ES256 KeyOps
// ============================================================================

impl KeyOps for ES256 {
    type SigningKeyInner = p256::ecdsa::SigningKey;
    type VerifyingKeyInner = p256::ecdsa::VerifyingKey;

    fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
        p256::ecdsa::SigningKey::random(rng)
    }

    fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
        *sk.verifying_key()
    }

    fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let point = vk.to_encoded_point(false);
        // Skip the 0x04 prefix for uncompressed point
        point.as_bytes()[1..].to_vec()
    }

    fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = sk.sign(digest);
        sig.to_bytes().to_vec()
    }

    fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(digest, &sig).is_ok()
    }
}

// ============================================================================
// ES384 KeyOps
// ============================================================================

impl KeyOps for ES384 {
    type SigningKeyInner = p384::ecdsa::SigningKey;
    type VerifyingKeyInner = p384::ecdsa::VerifyingKey;

    fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
        p384::ecdsa::SigningKey::random(rng)
    }

    fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
        *sk.verifying_key()
    }

    fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let point = vk.to_encoded_point(false);
        point.as_bytes()[1..].to_vec()
    }

    fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8> {
        use p384::ecdsa::signature::Signer;
        let sig: p384::ecdsa::Signature = sk.sign(digest);
        sig.to_bytes().to_vec()
    }

    fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool {
        use p384::ecdsa::signature::Verifier;
        let Ok(sig) = p384::ecdsa::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(digest, &sig).is_ok()
    }
}

// ============================================================================
// ES512 KeyOps
// ============================================================================

impl KeyOps for ES512 {
    type SigningKeyInner = p521::ecdsa::SigningKey;
    type VerifyingKeyInner = p521::ecdsa::VerifyingKey;

    fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
        p521::ecdsa::SigningKey::random(rng)
    }

    fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
        p521::ecdsa::VerifyingKey::from(sk)
    }

    fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
        use p521::elliptic_curve::sec1::ToEncodedPoint;
        let point = vk.to_encoded_point(false);
        point.as_bytes()[1..].to_vec()
    }

    fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8> {
        use p521::ecdsa::signature::Signer;
        let sig: p521::ecdsa::Signature = sk.sign(digest);
        sig.to_bytes().to_vec()
    }

    fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool {
        use p521::ecdsa::signature::Verifier;
        let Ok(sig) = p521::ecdsa::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(digest, &sig).is_ok()
    }
}

// ============================================================================
// Ed25519 KeyOps
// ============================================================================

impl KeyOps for Ed25519 {
    type SigningKeyInner = ed25519_dalek::SigningKey;
    type VerifyingKeyInner = ed25519_dalek::VerifyingKey;

    fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
        ed25519_dalek::SigningKey::generate(rng)
    }

    fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
        sk.verifying_key()
    }

    fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
        vk.as_bytes().to_vec()
    }

    fn sign(sk: &Self::SigningKeyInner, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = sk.sign(msg);
        sig.to_bytes().to_vec()
    }

    fn verify(vk: &Self::VerifyingKeyInner, msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

// ============================================================================
// SigningKey
// ============================================================================

/// A signing key that can sign messages.
///
/// This wraps the algorithm-specific signing key and caches the thumbprint.
pub struct SigningKey<A: KeyOps> {
    inner: A::SigningKeyInner,
    verifying_key: VerifyingKey<A>,
}

impl<A: KeyOps> SigningKey<A> {
    /// Generate a new random signing key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let inner = A::generate_signing_key(rng);
        let vk_inner = A::verifying_key_from_signing(&inner);
        let pub_bytes = A::public_key_bytes(&vk_inner);
        let thumbprint = compute_thumbprint::<A>(&pub_bytes);

        Self {
            inner,
            verifying_key: VerifyingKey {
                inner: vk_inner,
                pub_bytes,
                thumbprint,
                _marker: PhantomData,
            },
        }
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey<A> {
        &self.verifying_key
    }

    /// Get the key thumbprint.
    pub fn thumbprint(&self) -> &Thumbprint {
        &self.verifying_key.thumbprint
    }

    /// Sign a digest and return the signature bytes.
    pub fn sign(&self, digest: &[u8]) -> Vec<u8> {
        A::sign(&self.inner, digest)
    }

    /// Get the algorithm name.
    pub fn algorithm(&self) -> &'static str {
        A::NAME
    }
}

// ============================================================================
// VerifyingKey
// ============================================================================

/// A verifying key that can verify signatures.
///
/// This is the public-only version of a key, extracted from a [`SigningKey`].
pub struct VerifyingKey<A: KeyOps> {
    inner: A::VerifyingKeyInner,
    pub_bytes: Vec<u8>,
    thumbprint: Thumbprint,
    _marker: PhantomData<A>,
}

impl<A: KeyOps> VerifyingKey<A> {
    /// Get the thumbprint.
    pub fn thumbprint(&self) -> &Thumbprint {
        &self.thumbprint
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.pub_bytes
    }

    /// Verify a signature against a digest.
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> bool {
        A::verify(&self.inner, digest, signature)
    }

    /// Get the algorithm name.
    pub fn algorithm(&self) -> &'static str {
        A::NAME
    }
}

impl<A: KeyOps> Clone for VerifyingKey<A>
where
    A::VerifyingKeyInner: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            pub_bytes: self.pub_bytes.clone(),
            thumbprint: self.thumbprint.clone(),
            _marker: PhantomData,
        }
    }
}

// ============================================================================
// Thumbprint computation
// ============================================================================

/// Compute the thumbprint for a key.
///
/// Thumbprint is SHA-256 of the canonical JSON: `{"alg":"...","pub":"..."}`
fn compute_thumbprint<A: Algorithm>(pub_bytes: &[u8]) -> Thumbprint {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::Sha256;

    let pub_b64 = Base64UrlUnpadded::encode_string(pub_bytes);
    let canonical = format!(r#"{{"alg":"{}","pub":"{}"}}"#, A::NAME, pub_b64);
    let hash = Sha256::digest(canonical.as_bytes());

    Thumbprint::from_bytes(hash.to_vec())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn es256_generate_and_sign() {
        let key = SigningKey::<ES256>::generate(&mut OsRng);
        assert_eq!(key.algorithm(), "ES256");
        assert_eq!(key.thumbprint().as_bytes().len(), 32);

        let digest = sha2::Sha256::digest(b"test message");
        let sig = key.sign(&digest);
        assert_eq!(sig.len(), 64);

        assert!(key.verifying_key().verify(&digest, &sig));
    }

    #[test]
    fn es384_generate_and_sign() {
        let key = SigningKey::<ES384>::generate(&mut OsRng);
        assert_eq!(key.algorithm(), "ES384");

        let digest = sha2::Sha384::digest(b"test message");
        let sig = key.sign(&digest);
        assert_eq!(sig.len(), 96);

        assert!(key.verifying_key().verify(&digest, &sig));
    }

    #[test]
    fn es512_generate_and_sign() {
        let key = SigningKey::<ES512>::generate(&mut OsRng);
        assert_eq!(key.algorithm(), "ES512");

        let digest = sha2::Sha512::digest(b"test message");
        let sig = key.sign(&digest);
        assert_eq!(sig.len(), 132);

        assert!(key.verifying_key().verify(&digest, &sig));
    }

    #[test]
    fn ed25519_generate_and_sign() {
        let key = SigningKey::<Ed25519>::generate(&mut OsRng);
        assert_eq!(key.algorithm(), "Ed25519");
        assert_eq!(key.verifying_key().public_key_bytes().len(), 32);

        // Ed25519 signs the message directly, not a digest
        let msg = b"test message";
        let sig = key.sign(msg);
        assert_eq!(sig.len(), 64);

        assert!(key.verifying_key().verify(msg, &sig));
    }

    #[test]
    fn thumbprint_is_deterministic() {
        let key1 = SigningKey::<ES256>::generate(&mut OsRng);
        let key2 = SigningKey::<ES256>::generate(&mut OsRng);

        // Different keys should have different thumbprints
        assert_ne!(key1.thumbprint().as_bytes(), key2.thumbprint().as_bytes());

        // Same key should produce same thumbprint
        let tmb1 = key1.thumbprint().to_b64();
        let tmb2 = key1.thumbprint().to_b64();
        assert_eq!(tmb1, tmb2);
    }

    #[test]
    fn thumbprint_format() {
        let key = SigningKey::<ES256>::generate(&mut OsRng);
        let tmb = key.thumbprint().to_b64();

        // Should be 43 characters (32 bytes in base64 without padding)
        assert_eq!(tmb.len(), 43);
        // Should not contain padding
        assert!(!tmb.contains('='));
        // Should be URL-safe
        assert!(!tmb.contains('+'));
        assert!(!tmb.contains('/'));
    }

    #[test]
    fn verify_wrong_signature_fails() {
        let key = SigningKey::<ES256>::generate(&mut OsRng);
        let digest = sha2::Sha256::digest(b"test message");
        let sig = key.sign(&digest);

        // Tamper with signature
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;

        assert!(!key.verifying_key().verify(&digest, &bad_sig));
    }

    #[test]
    fn verify_wrong_digest_fails() {
        let key = SigningKey::<ES256>::generate(&mut OsRng);
        let digest1 = sha2::Sha256::digest(b"message 1");
        let digest2 = sha2::Sha256::digest(b"message 2");
        let sig = key.sign(&digest1);

        assert!(!key.verifying_key().verify(&digest2, &sig));
    }
}
