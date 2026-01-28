//! # Coz
//!
//! A Rust implementation of the [Coz](https://github.com/Cyphrme/Coz)
//! cryptographic JSON messaging specification.
//!
//! ## Example
//!
//! ```ignore
//! use coz::{SigningKey, ES256, PayBuilder};
//!
//! let key = SigningKey::<ES256>::generate();
//! let coz = PayBuilder::new()
//!     .msg("Hello, Coz!")
//!     .sign(&key)?;
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod alg;
pub mod b64;
pub mod canon;
pub mod coz;
pub mod error;
#[cfg(test)]
mod golden;
pub mod key;
pub mod revoke;

pub use alg::{Alg, Algorithm, ES256, ES384, ES512, Ed25519};
// Re-export crypto primitives for downstream crates
pub use base64ct;
pub use canon::{
    CZD_CANON, Cad, Czd, KEY_CANON, canon, canonical, canonical_hash, canonical_hash_for_alg,
    czd_for_alg,
};
pub use coz::{Coz, CozJson, Pay, PayBuilder, sign_json, verify_json};
pub use error::{Error, Result};
pub use key::{
    KeyPair, SigningKey, Thumbprint, VerifyingKey, compute_thumbprint_for_alg,
    signing_key_from_bytes,
};
pub use revoke::{RVK_MAX_SIZE, is_valid_rvk, revoke, revoke_json, validate_revoke_size};
pub use {digest, sha2};
