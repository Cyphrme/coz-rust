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

pub mod alg;
pub mod b64;
pub mod error;
pub mod key;

pub use alg::{Algorithm, ES256, ES384, ES512, Ed25519};
pub use error::{Error, Result};
pub use key::{SigningKey, Thumbprint, VerifyingKey};
