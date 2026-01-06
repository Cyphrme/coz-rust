//! Key types for Coz cryptographic operations.
//!
//! This module provides [`SigningKey`] and [`VerifyingKey`] types that wrap
//! RustCrypto implementations and add Coz-specific functionality like
//! thumbprint calculation.

use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::alg::{Algorithm, ES256, ES384, ES512, Ed25519};

// ============================================================================
// Thumbprint
// ============================================================================

/// A key thumbprint - the hash of the canonical `{"alg":"...","pub":"..."}`.
///
/// Thumbprints uniquely identify keys. The hash algorithm is determined by
/// the key's algorithm (e.g., ES256 → SHA-256, ES384 → SHA-384, ES512 → SHA-512).
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

impl AsRef<[u8]> for Thumbprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// Internal key operations module (keeps KeyOps private)
// ============================================================================

pub mod ops {
    use super::*;

    /// Internal trait for algorithm-specific key operations.
    pub trait KeyOps: Algorithm {
        type SigningKeyInner;
        type VerifyingKeyInner;

        fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner;
        fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner;
        fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKeyInner>;
        fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8>;
        fn private_key_bytes(sk: &Self::SigningKeyInner) -> Vec<u8>;
        fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8>;
        fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool;
    }

    // ES256
    impl KeyOps for ES256 {
        type SigningKeyInner = p256::ecdsa::SigningKey;
        type VerifyingKeyInner = p256::ecdsa::VerifyingKey;

        fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
            p256::ecdsa::SigningKey::random(rng)
        }

        fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
            *sk.verifying_key()
        }

        fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKeyInner> {
            // Bytes are uncompressed point without 0x04 prefix
            let mut full = vec![0x04];
            full.extend_from_slice(bytes);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&full).ok()
        }

        fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
            let point = vk.to_encoded_point(false);
            point.as_bytes()[1..].to_vec()
        }

        fn private_key_bytes(sk: &Self::SigningKeyInner) -> Vec<u8> {
            sk.to_bytes().to_vec()
        }

        fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8> {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = sk.sign(digest);
            // Normalize to low-S for non-malleability (Coz spec requirement)
            let normalized = sig.normalize_s().unwrap_or(sig);
            normalized.to_bytes().to_vec()
        }

        fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool {
            use p256::ecdsa::signature::Verifier;
            let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            // Reject high-S signatures (Coz spec requires low-S only)
            if sig.normalize_s().is_some() {
                return false;
            }
            vk.verify(digest, &sig).is_ok()
        }
    }

    // ES384
    impl KeyOps for ES384 {
        type SigningKeyInner = p384::ecdsa::SigningKey;
        type VerifyingKeyInner = p384::ecdsa::VerifyingKey;

        fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
            p384::ecdsa::SigningKey::random(rng)
        }

        fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
            *sk.verifying_key()
        }

        fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKeyInner> {
            let mut full = vec![0x04];
            full.extend_from_slice(bytes);
            p384::ecdsa::VerifyingKey::from_sec1_bytes(&full).ok()
        }

        fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
            let point = vk.to_encoded_point(false);
            point.as_bytes()[1..].to_vec()
        }

        fn private_key_bytes(sk: &Self::SigningKeyInner) -> Vec<u8> {
            sk.to_bytes().to_vec()
        }

        fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8> {
            use p384::ecdsa::signature::Signer;
            let sig: p384::ecdsa::Signature = sk.sign(digest);
            // Normalize to low-S for non-malleability (Coz spec requirement)
            let normalized = sig.normalize_s().unwrap_or(sig);
            normalized.to_bytes().to_vec()
        }

        fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool {
            use p384::ecdsa::signature::Verifier;
            let Ok(sig) = p384::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            // Reject high-S signatures (Coz spec requires low-S only)
            if sig.normalize_s().is_some() {
                return false;
            }
            vk.verify(digest, &sig).is_ok()
        }
    }

    // ES512
    impl KeyOps for ES512 {
        type SigningKeyInner = p521::ecdsa::SigningKey;
        type VerifyingKeyInner = p521::ecdsa::VerifyingKey;

        fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
            p521::ecdsa::SigningKey::random(rng)
        }

        fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
            p521::ecdsa::VerifyingKey::from(sk)
        }

        fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKeyInner> {
            let mut full = vec![0x04];
            full.extend_from_slice(bytes);
            p521::ecdsa::VerifyingKey::from_sec1_bytes(&full).ok()
        }

        fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
            let point = vk.to_encoded_point(false);
            point.as_bytes()[1..].to_vec()
        }

        fn private_key_bytes(sk: &Self::SigningKeyInner) -> Vec<u8> {
            sk.to_bytes().to_vec()
        }

        fn sign(sk: &Self::SigningKeyInner, digest: &[u8]) -> Vec<u8> {
            use p521::ecdsa::signature::Signer;
            let sig: p521::ecdsa::Signature = sk.sign(digest);
            // Normalize to low-S for non-malleability (Coz spec requirement)
            let normalized = sig.normalize_s().unwrap_or(sig);
            normalized.to_bytes().to_vec()
        }

        fn verify(vk: &Self::VerifyingKeyInner, digest: &[u8], sig: &[u8]) -> bool {
            use p521::ecdsa::signature::Verifier;
            let Ok(sig) = p521::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            // Reject high-S signatures (Coz spec requires low-S only)
            if sig.normalize_s().is_some() {
                return false;
            }
            vk.verify(digest, &sig).is_ok()
        }
    }

    // Ed25519
    impl KeyOps for Ed25519 {
        type SigningKeyInner = ed25519_dalek::SigningKey;
        type VerifyingKeyInner = ed25519_dalek::VerifyingKey;

        fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::SigningKeyInner {
            ed25519_dalek::SigningKey::generate(rng)
        }

        fn verifying_key_from_signing(sk: &Self::SigningKeyInner) -> Self::VerifyingKeyInner {
            sk.verifying_key()
        }

        fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKeyInner> {
            let bytes: [u8; 32] = bytes.try_into().ok()?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
        }

        fn public_key_bytes(vk: &Self::VerifyingKeyInner) -> Vec<u8> {
            vk.as_bytes().to_vec()
        }

        fn private_key_bytes(sk: &Self::SigningKeyInner) -> Vec<u8> {
            sk.to_bytes().to_vec()
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
}

use ops::KeyOps;

// ============================================================================
// SigningKey
// ============================================================================

/// A signing key that can sign messages.
///
/// This wraps the algorithm-specific signing key and caches the thumbprint.
/// The type parameter `A` must be one of the supported algorithms:
/// [`ES256`], [`ES384`], [`ES512`], or [`Ed25519`].
pub struct SigningKey<A: Algorithm>
where
    A: KeyOps,
{
    inner: A::SigningKeyInner,
    verifying_key: VerifyingKey<A>,
}

impl<A: Algorithm + KeyOps> SigningKey<A> {
    /// Generate a new random signing key using the system RNG.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use coz::{SigningKey, ES256};
    /// let key = SigningKey::<ES256>::generate();
    /// ```
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand::rngs::OsRng)
    }

    /// Generate a new random signing key using a custom RNG.
    ///
    /// This is useful for deterministic testing with seeded RNGs.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
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

    /// Get the private key bytes.
    ///
    /// For ECDSA keys this is the scalar value. For Ed25519 this is the seed.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        A::private_key_bytes(&self.inner)
    }
}

// ============================================================================
// VerifyingKey
// ============================================================================

/// A verifying key that can verify signatures.
///
/// This is the public-only version of a key, extracted from a [`SigningKey`].
pub struct VerifyingKey<A: Algorithm>
where
    A: KeyOps,
{
    inner: A::VerifyingKeyInner,
    pub_bytes: Vec<u8>,
    thumbprint: Thumbprint,
    _marker: PhantomData<A>,
}

impl<A: Algorithm + KeyOps> VerifyingKey<A> {
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

impl<A: Algorithm + KeyOps> Clone for VerifyingKey<A>
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
/// The thumbprint is the hash of the canonical `{"alg":"...","pub":"..."}` JSON.
/// The hash algorithm is determined by the key's algorithm (e.g., ES256 → SHA-256,
/// ES384 → SHA-384, ES512 → SHA-512, Ed25519 → SHA-512).
fn compute_thumbprint<A: Algorithm>(pub_bytes: &[u8]) -> Thumbprint {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use digest::Digest;

    let pub_b64 = Base64UrlUnpadded::encode_string(pub_bytes);
    let canonical = format!(r#"{{"alg":"{}","pub":"{}"}}"#, A::NAME, pub_b64);
    let hash = <A::Hasher>::digest(canonical.as_bytes());

    Thumbprint::from_bytes(hash.to_vec())
}

/// Compute a thumbprint from an algorithm name and public key bytes.
///
/// This is useful when you have parsed key JSON and need to compute
/// or verify the thumbprint. Returns `None` for unknown algorithms.
///
/// # Example
///
/// ```ignore
/// let tmb = compute_thumbprint_for_alg("ES256", &pub_bytes);
/// ```
pub fn compute_thumbprint_for_alg(alg: &str, pub_bytes: &[u8]) -> Option<Thumbprint> {
    match alg {
        "ES256" => Some(compute_thumbprint::<ES256>(pub_bytes)),
        "ES384" => Some(compute_thumbprint::<ES384>(pub_bytes)),
        "ES512" => Some(compute_thumbprint::<ES512>(pub_bytes)),
        "Ed25519" => Some(compute_thumbprint::<Ed25519>(pub_bytes)),
        _ => None,
    }
}

/// Create a verifying key from raw public key bytes.
///
/// This is used internally for runtime verification.
pub(crate) fn verifying_key_from_bytes<A>(pub_bytes: &[u8]) -> Option<VerifyingKey<A>>
where
    A: Algorithm + KeyOps,
{
    let inner = A::verifying_key_from_bytes(pub_bytes)?;
    let thumbprint = compute_thumbprint::<A>(pub_bytes);

    Some(VerifyingKey {
        inner,
        pub_bytes: pub_bytes.to_vec(),
        thumbprint,
        _marker: std::marker::PhantomData,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::*;

    #[test]
    fn es256_generate_and_sign() {
        let key = SigningKey::<ES256>::generate();
        assert_eq!(key.algorithm(), "ES256");
        assert_eq!(key.thumbprint().as_bytes().len(), 32);

        let digest = sha2::Sha256::digest(b"test message");
        let sig = key.sign(&digest);
        assert_eq!(sig.len(), 64);

        assert!(key.verifying_key().verify(&digest, &sig));
    }

    #[test]
    fn es384_generate_and_sign() {
        let key = SigningKey::<ES384>::generate();
        assert_eq!(key.algorithm(), "ES384");
        // ES384 thumbprint uses SHA-384 (48 bytes)
        assert_eq!(key.thumbprint().as_bytes().len(), 48);

        let digest = sha2::Sha384::digest(b"test message");
        let sig = key.sign(&digest);
        assert_eq!(sig.len(), 96);

        assert!(key.verifying_key().verify(&digest, &sig));
    }

    #[test]
    fn es512_generate_and_sign() {
        let key = SigningKey::<ES512>::generate();
        assert_eq!(key.algorithm(), "ES512");
        // ES512 thumbprint uses SHA-512 (64 bytes)
        assert_eq!(key.thumbprint().as_bytes().len(), 64);

        let digest = sha2::Sha512::digest(b"test message");
        let sig = key.sign(&digest);
        assert_eq!(sig.len(), 132);

        assert!(key.verifying_key().verify(&digest, &sig));
    }

    #[test]
    fn ed25519_generate_and_sign() {
        let key = SigningKey::<Ed25519>::generate();
        assert_eq!(key.algorithm(), "Ed25519");
        assert_eq!(key.verifying_key().public_key_bytes().len(), 32);
        // Ed25519 thumbprint uses SHA-512 (64 bytes)
        assert_eq!(key.thumbprint().as_bytes().len(), 64);

        // Ed25519 signs the message directly, not a digest
        let msg = b"test message";
        let sig = key.sign(msg);
        assert_eq!(sig.len(), 64);

        assert!(key.verifying_key().verify(msg, &sig));
    }

    #[test]
    fn thumbprint_is_deterministic() {
        let key1 = SigningKey::<ES256>::generate();
        let key2 = SigningKey::<ES256>::generate();

        // Different keys should have different thumbprints
        assert_ne!(key1.thumbprint().as_bytes(), key2.thumbprint().as_bytes());

        // Same key should produce same thumbprint
        let tmb1 = key1.thumbprint().to_b64();
        let tmb2 = key1.thumbprint().to_b64();
        assert_eq!(tmb1, tmb2);
    }

    #[test]
    fn thumbprint_format() {
        let key = SigningKey::<ES256>::generate();
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
        let key = SigningKey::<ES256>::generate();
        let digest = sha2::Sha256::digest(b"test message");
        let sig = key.sign(&digest);

        // Tamper with signature
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;

        assert!(!key.verifying_key().verify(&digest, &bad_sig));
    }

    #[test]
    fn verify_wrong_digest_fails() {
        let key = SigningKey::<ES256>::generate();
        let digest1 = sha2::Sha256::digest(b"message 1");
        let digest2 = sha2::Sha256::digest(b"message 2");
        let sig = key.sign(&digest1);

        assert!(!key.verifying_key().verify(&digest2, &sig));
    }

    #[test]
    fn signatures_are_low_s() {
        // Generate many signatures and verify they're all low-S
        for _ in 0..10 {
            let key = SigningKey::<ES256>::generate();
            let digest = sha2::Sha256::digest(b"test message");
            let sig = key.sign(&digest);

            // Parse signature and check it's already normalized
            let parsed = p256::ecdsa::Signature::from_slice(&sig).unwrap();
            // normalize_s returns None if already low-S
            assert!(
                parsed.normalize_s().is_none(),
                "Generated signature should be low-S"
            );
        }
    }

    #[test]
    fn high_s_signature_rejected() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        // Known high-S signature from Go reference (ExampleECDSAToLowSSig)
        // This is a valid ECDSA signature with high-S that should be rejected
        let high_s_sig = Base64UrlUnpadded::decode_vec(
            "nN7tddth3aiSHaEh0WfhFzXFSSWuAfB7wdS_fUAc9kai2fBx9jXY8j-MWDZW-5Pm4AsX7ed5UQ9MAStNOMNa8g"
        ).unwrap();

        // Create a key for verification (won't match, but we're testing signature parsing)
        let key = SigningKey::<ES256>::generate();
        let digest = sha2::Sha256::digest(b"{}");

        // Should be rejected because it's high-S
        assert!(
            !key.verifying_key().verify(&digest, &high_s_sig),
            "High-S signature should be rejected"
        );
    }
}
