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

pub mod b64;
