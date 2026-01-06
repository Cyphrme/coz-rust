//! Key revocation support.
//!
//! Coz keys can be self-revoked by signing a payload containing the `rvk` field.
//! Revoke payloads are limited to [`RVK_MAX_SIZE`] bytes (default 2048) to
//! prevent denial-of-service attacks.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::alg::Algorithm;
use crate::coz::{Coz, Pay, PayBuilder};
use crate::error::{Error, Result};
use crate::key::SigningKey;

/// Maximum allowed payload size for revoke messages (default 2048 bytes).
///
/// This limit prevents denial-of-service attacks via oversized revoke payloads.
/// Set to 0 to disable the limit.
pub const RVK_MAX_SIZE: usize = 2048;

/// Maximum safe integer for JavaScript compatibility (2^53 - 1).
const MAX_SAFE_INTEGER: i64 = 9007199254740991;

/// Create a revoke payload for the given signing key.
///
/// This creates a self-revocation message that can be signed and published
/// to mark the key as revoked.
///
/// # Arguments
///
/// * `key` - The signing key to revoke
/// * `now` - Optional Unix timestamp. If `None`, uses current time.
///
/// # Returns
///
/// A signed [`Coz`] message containing the revocation.
pub fn revoke<A>(key: &SigningKey<A>, now: Option<i64>) -> Result<Coz<A>>
where
    A: Algorithm + crate::key::ops::KeyOps,
{
    let timestamp = match now {
        Some(t) => t,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::InvalidTimestamp(e.to_string()))?
            .as_secs() as i64,
    };

    // Validate timestamp
    if timestamp <= 0 || timestamp > MAX_SAFE_INTEGER {
        return Err(Error::InvalidTimestamp(format!(
            "rvk must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }

    PayBuilder::new().now(timestamp).rvk(timestamp).sign(key)
}

/// Validate that a revoke payload does not exceed the size limit.
///
/// Returns an error if the payload is a revoke message and exceeds
/// [`RVK_MAX_SIZE`] bytes.
pub fn validate_revoke_size(pay: &Pay, size: usize) -> Result<()> {
    if pay.is_revoke() && RVK_MAX_SIZE > 0 && size > RVK_MAX_SIZE {
        return Err(Error::RevokeTooLarge {
            size,
            max: RVK_MAX_SIZE,
        });
    }
    Ok(())
}

/// Check if a timestamp represents a valid revocation.
///
/// A valid revocation timestamp is positive and <= 2^53 - 1.
pub fn is_valid_rvk(rvk: i64) -> bool {
    rvk > 0 && rvk <= MAX_SAFE_INTEGER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::ES256;

    #[test]
    fn revoke_creates_valid_coz() {
        let key = SigningKey::<ES256>::generate();
        let coz = revoke(&key, Some(1623132000)).unwrap();

        assert!(coz.verify(key.verifying_key()));
        assert_eq!(coz.pay.now, Some(1623132000));
        assert!(coz.pay.is_revoke());
    }

    #[test]
    fn revoke_with_current_time() {
        let key = SigningKey::<ES256>::generate();
        let coz = revoke(&key, None).unwrap();

        assert!(coz.verify(key.verifying_key()));
        assert!(coz.pay.now.unwrap() > 0);
        assert!(coz.pay.is_revoke());
    }

    #[test]
    fn revoke_invalid_timestamp() {
        let key = SigningKey::<ES256>::generate();

        // Zero is invalid
        let result = revoke(&key, Some(0));
        assert!(result.is_err());

        // Negative is invalid
        let result = revoke(&key, Some(-1));
        assert!(result.is_err());
    }

    #[test]
    fn validate_revoke_size_ok() {
        let mut pay = Pay::new();
        pay.rvk = Some(1623132000);

        // Under limit is ok
        assert!(validate_revoke_size(&pay, 100).is_ok());
        assert!(validate_revoke_size(&pay, RVK_MAX_SIZE).is_ok());
    }

    #[test]
    fn validate_revoke_size_exceeds() {
        let mut pay = Pay::new();
        pay.rvk = Some(1623132000);

        // Over limit is error
        let result = validate_revoke_size(&pay, RVK_MAX_SIZE + 1);
        assert!(result.is_err());
    }

    #[test]
    fn validate_non_revoke_size_ok() {
        let pay = Pay::new();

        // Non-revoke can be any size
        assert!(validate_revoke_size(&pay, 10000).is_ok());
    }

    #[test]
    fn is_valid_rvk_values() {
        assert!(!is_valid_rvk(0));
        assert!(!is_valid_rvk(-1));
        assert!(is_valid_rvk(1));
        assert!(is_valid_rvk(1623132000));
        assert!(is_valid_rvk(MAX_SAFE_INTEGER));
        assert!(!is_valid_rvk(MAX_SAFE_INTEGER + 1));
    }
}
