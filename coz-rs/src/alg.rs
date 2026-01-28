//! Algorithm definitions for Coz cryptographic operations.
//!
//! This module defines the sealed [`Algorithm`] trait and marker types for
//! each supported algorithm: [`ES256`], [`ES384`], [`ES512`], and [`Ed25519`].

use digest::Digest;
use sha2::{Sha256, Sha384, Sha512};

// ============================================================================
// Sealed trait pattern - prevents external implementations
// ============================================================================

mod private {
    pub trait Sealed {}
}

// ============================================================================
// Algorithm trait
// ============================================================================

/// Trait for Coz-supported cryptographic algorithms.
///
/// This trait is sealed and cannot be implemented outside this crate.
/// It provides associated types and constants for each algorithm.
pub trait Algorithm: private::Sealed + Sized + 'static {
    /// Algorithm name as it appears in JSON (e.g., "ES256").
    const NAME: &'static str;

    /// Signature size in bytes.
    const SIG_SIZE: usize;

    /// Public key size in bytes.
    const PUB_SIZE: usize;

    /// Private key size in bytes.
    const PRV_SIZE: usize;

    /// The hashing algorithm used for digests.
    type Hasher: Digest + Clone;
}

// ============================================================================
// ECDSA Algorithms
// ============================================================================

/// ES256: ECDSA using P-256 and SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ES256;

impl private::Sealed for ES256 {}

impl Algorithm for ES256 {
    type Hasher = Sha256;

    const NAME: &'static str = "ES256";
    // Uncompressed X || Y (without 0x04 prefix)
    const PRV_SIZE: usize = 32;
    const PUB_SIZE: usize = 64;
    const SIG_SIZE: usize = 64;
}

/// ES384: ECDSA using P-384 and SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ES384;

impl private::Sealed for ES384 {}

impl Algorithm for ES384 {
    type Hasher = Sha384;

    const NAME: &'static str = "ES384";
    const PRV_SIZE: usize = 48;
    const PUB_SIZE: usize = 96;
    const SIG_SIZE: usize = 96;
}

/// ES512: ECDSA using P-521 and SHA-512.
///
/// Note: P-521 uses 66-byte components (521 bits rounded up to 528 bits = 66 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ES512;

impl private::Sealed for ES512 {}

impl Algorithm for ES512 {
    type Hasher = Sha512;

    const NAME: &'static str = "ES512";
    // 66 * 2
    const PRV_SIZE: usize = 66;
    // 66 * 2
    const PUB_SIZE: usize = 132;
    const SIG_SIZE: usize = 132;
}

// ============================================================================
// EdDSA Algorithms
// ============================================================================

/// Ed25519: EdDSA using Curve25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519;

impl private::Sealed for Ed25519 {}

impl Algorithm for Ed25519 {
    type Hasher = Sha512;

    const NAME: &'static str = "Ed25519";
    const PRV_SIZE: usize = 32;
    const PUB_SIZE: usize = 32;
    const SIG_SIZE: usize = 64; // Ed25519 internally uses SHA-512
}

// ============================================================================
// Runtime Algorithm Selector
// ============================================================================

/// Runtime algorithm selector for type-safe dispatch.
///
/// Use this enum when the algorithm is determined at runtime (e.g., from user
/// input or configuration). It provides a single parse point via [`Alg::from_str`]
/// and methods that delegate to the generic [`Algorithm`] implementations.
///
/// # Example
///
/// ```ignore
/// use coz::Alg;
///
/// let alg = Alg::from_str("ES256").expect("valid algorithm");
/// assert_eq!(alg.name(), "ES256");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    /// ES256: ECDSA using P-256 and SHA-256.
    ES256,
    /// ES384: ECDSA using P-384 and SHA-384.
    ES384,
    /// ES512: ECDSA using P-521 and SHA-512.
    ES512,
    /// Ed25519: EdDSA using Curve25519.
    Ed25519,
}

impl Alg {
    /// Parse algorithm name from string.
    ///
    /// Returns `None` if the algorithm is not recognized.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use coz::Alg;
    ///
    /// assert_eq!(Alg::from_str("ES256"), Some(Alg::ES256));
    /// assert_eq!(Alg::from_str("unknown"), None);
    /// ```
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::ES256),
            "ES384" => Some(Self::ES384),
            "ES512" => Some(Self::ES512),
            "Ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }

    /// Get the algorithm name as a static string.
    ///
    /// This returns the same value as `Algorithm::NAME` for the corresponding type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ES256 => ES256::NAME,
            Self::ES384 => ES384::NAME,
            Self::ES512 => ES512::NAME,
            Self::Ed25519 => Ed25519::NAME,
        }
    }

    /// Get the public key size in bytes.
    #[must_use]
    pub const fn pub_size(self) -> usize {
        match self {
            Self::ES256 => ES256::PUB_SIZE,
            Self::ES384 => ES384::PUB_SIZE,
            Self::ES512 => ES512::PUB_SIZE,
            Self::Ed25519 => Ed25519::PUB_SIZE,
        }
    }

    /// Get the private key size in bytes.
    #[must_use]
    pub const fn prv_size(self) -> usize {
        match self {
            Self::ES256 => ES256::PRV_SIZE,
            Self::ES384 => ES384::PRV_SIZE,
            Self::ES512 => ES512::PRV_SIZE,
            Self::Ed25519 => Ed25519::PRV_SIZE,
        }
    }
}

impl std::fmt::Display for Alg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_names() {
        assert_eq!(ES256::NAME, "ES256");
        assert_eq!(ES384::NAME, "ES384");
        assert_eq!(ES512::NAME, "ES512");
        assert_eq!(Ed25519::NAME, "Ed25519");
    }

    #[test]
    fn es256_sizes() {
        assert_eq!(ES256::SIG_SIZE, 64);
        assert_eq!(ES256::PUB_SIZE, 64);
        assert_eq!(ES256::PRV_SIZE, 32);
    }

    #[test]
    fn es384_sizes() {
        assert_eq!(ES384::SIG_SIZE, 96);
        assert_eq!(ES384::PUB_SIZE, 96);
        assert_eq!(ES384::PRV_SIZE, 48);
    }

    #[test]
    fn es512_sizes() {
        // P-521: 521 bits = 66 bytes per component
        assert_eq!(ES512::SIG_SIZE, 132);
        assert_eq!(ES512::PUB_SIZE, 132);
        assert_eq!(ES512::PRV_SIZE, 66);
    }

    #[test]
    fn ed25519_sizes() {
        assert_eq!(Ed25519::SIG_SIZE, 64);
        assert_eq!(Ed25519::PUB_SIZE, 32);
        assert_eq!(Ed25519::PRV_SIZE, 32);
    }
}
