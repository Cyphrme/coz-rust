//! Error types for the Coz library.

use thiserror::Error;

/// The main error type for Coz operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Base64 decoding failed.
    #[error("invalid base64: {0}")]
    Base64(#[from] base64ct::Error),

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerification,

    /// Invalid signature format or encoding.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid key format or encoding.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Thumbprint mismatch.
    #[error("thumbprint mismatch: expected {expected}, got {actual}")]
    ThumbprintMismatch {
        /// Expected thumbprint.
        expected: String,
        /// Actual thumbprint.
        actual: String,
    },

    /// Algorithm mismatch between key and payload.
    #[error("algorithm mismatch: key uses {key_alg}, payload specifies {pay_alg}")]
    AlgorithmMismatch {
        /// Algorithm from the key.
        key_alg: &'static str,
        /// Algorithm from the payload.
        pay_alg: String,
    },

    /// Revoke payload exceeds maximum size.
    #[error("revoke payload size {size} exceeds maximum {max}")]
    RevokeTooLarge {
        /// Actual size of the payload.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid timestamp value.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Canonicalization failed.
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
}

/// Result type alias for Coz operations.
pub type Result<T> = std::result::Result<T, Error>;
