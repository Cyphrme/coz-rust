//! Golden test vectors from the Coz specification.
//!
//! These tests verify cross-compatibility with the Go reference implementation.

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};

    use crate::alg::{Algorithm, ES256};
    use crate::canon::{canonical, canonical_hash};

    // ========================================================================
    // Golden values from Go reference (key_test.go)
    // ========================================================================

    /// Golden key public component (X || Y, 64 bytes for ES256)
    const GOLDEN_PUB: &str =
        "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g";

    /// Golden key private component (d, 32 bytes for ES256)
    const GOLDEN_PRV: &str = "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA";

    /// Golden thumbprint (SHA-256 of canonical {"alg":"ES256","pub":"..."})
    const GOLDEN_TMB: &str = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

    /// Golden canonical digest of GOLDEN_PAY
    const GOLDEN_CAD: &str = "XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU";

    /// Golden coz digest
    const GOLDEN_CZD: &str = "k0-4mPqRJkY3g0pX14wLiIpZkTsVv453xJ4vYZKcLJE";

    /// Golden signature over GOLDEN_CAD
    const GOLDEN_SIG: &str =
        "1EWsiwvnrjAODbiWH1WLwjSY5Go89KnvyJLjB5gWlSF9l0-3xXdZ1jcq7AHcSfiazAf-lquI_okZ48uPSBPRpg";

    /// Golden payload JSON (compact form for hashing)
    const GOLDEN_PAY_COMPACT: &str = r#"{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"}"#;

    // ========================================================================
    // Thumbprint tests
    // ========================================================================

    #[test]
    fn golden_thumbprint_computation() {
        // Thumbprint = SHA-256({"alg":"ES256","pub":"..."})
        let canonical_key = format!(r#"{{"alg":"ES256","pub":"{}"}}"#, GOLDEN_PUB);
        let hash = Sha256::digest(canonical_key.as_bytes());
        let tmb_b64 = Base64UrlUnpadded::encode_string(&hash);

        assert_eq!(tmb_b64, GOLDEN_TMB);
    }

    #[test]
    fn golden_thumbprint_decode() {
        let tmb_bytes = Base64UrlUnpadded::decode_vec(GOLDEN_TMB).unwrap();
        assert_eq!(tmb_bytes.len(), 32);
    }

    // ========================================================================
    // Canonical digest tests
    // ========================================================================

    #[test]
    fn golden_cad_computation() {
        // cad = SHA-256(compact(pay))
        let cad = canonical_hash::<ES256>(GOLDEN_PAY_COMPACT.as_bytes(), None).unwrap();
        assert_eq!(cad.to_b64(), GOLDEN_CAD);
    }

    #[test]
    fn golden_cad_decode() {
        let cad_bytes = Base64UrlUnpadded::decode_vec(GOLDEN_CAD).unwrap();
        assert_eq!(cad_bytes.len(), 32);
    }

    // ========================================================================
    // Coz digest tests
    // ========================================================================

    #[test]
    fn golden_czd_computation() {
        // czd = SHA-256({"cad":"...","sig":"..."})
        let czd_input = format!(r#"{{"cad":"{}","sig":"{}"}}"#, GOLDEN_CAD, GOLDEN_SIG);
        let hash = Sha256::digest(czd_input.as_bytes());
        let czd_b64 = Base64UrlUnpadded::encode_string(&hash);

        assert_eq!(czd_b64, GOLDEN_CZD);
    }

    #[test]
    fn golden_czd_decode() {
        let czd_bytes = Base64UrlUnpadded::decode_vec(GOLDEN_CZD).unwrap();
        assert_eq!(czd_bytes.len(), 32);
    }

    // ========================================================================
    // Signature tests
    // ========================================================================

    #[test]
    fn golden_sig_decode() {
        let sig_bytes = Base64UrlUnpadded::decode_vec(GOLDEN_SIG).unwrap();
        assert_eq!(sig_bytes.len(), 64); // ES256 signature size
    }

    // ========================================================================
    // Key component tests
    // ========================================================================

    #[test]
    fn golden_pub_decode() {
        let pub_bytes = Base64UrlUnpadded::decode_vec(GOLDEN_PUB).unwrap();
        assert_eq!(pub_bytes.len(), 64); // ES256 public key (X || Y)
    }

    #[test]
    fn golden_prv_decode() {
        let prv_bytes = Base64UrlUnpadded::decode_vec(GOLDEN_PRV).unwrap();
        assert_eq!(prv_bytes.len(), 32); // ES256 private key
    }

    // ========================================================================
    // Canonicalization tests
    // ========================================================================

    #[test]
    fn golden_pay_canonical_form() {
        // Verify canonical form is compact JSON (no structural whitespace)
        let canonical_bytes = canonical(GOLDEN_PAY_COMPACT.as_bytes(), None).unwrap();
        let canonical_str = String::from_utf8(canonical_bytes).unwrap();

        // Should have no newlines or tabs (structural whitespace)
        assert!(!canonical_str.contains('\n'));
        assert!(!canonical_str.contains('\t'));
        // Should start and end with braces (valid JSON object)
        assert!(canonical_str.starts_with('{'));
        assert!(canonical_str.ends_with('}'));
        // Should not have spaces around colons or commas (JSON structural)
        assert!(!canonical_str.contains(": "));
        assert!(!canonical_str.contains(" :"));
        assert!(!canonical_str.contains(", "));
        assert!(!canonical_str.contains(" ,"));
    }

    #[test]
    fn canon_key_order() {
        // Verify KEY_CANON order matches spec
        assert_eq!(crate::canon::KEY_CANON, &["alg", "pub"]);
    }

    #[test]
    fn canon_czd_order() {
        // Verify CZD_CANON order matches spec
        assert_eq!(crate::canon::CZD_CANON, &["cad", "sig"]);
    }

    // ========================================================================
    // Algorithm size verification
    // ========================================================================

    #[test]
    fn es256_sizes_match_spec() {
        assert_eq!(ES256::SIG_SIZE, 64);
        assert_eq!(ES256::PUB_SIZE, 64);
        assert_eq!(ES256::PRV_SIZE, 32);
    }

    #[test]
    fn es384_sizes_match_spec() {
        use crate::alg::ES384;
        assert_eq!(ES384::SIG_SIZE, 96);
        assert_eq!(ES384::PUB_SIZE, 96);
        assert_eq!(ES384::PRV_SIZE, 48);
    }

    #[test]
    fn es512_sizes_match_spec() {
        use crate::alg::ES512;
        assert_eq!(ES512::SIG_SIZE, 132);
        assert_eq!(ES512::PUB_SIZE, 132);
        assert_eq!(ES512::PRV_SIZE, 66);
    }

    #[test]
    fn ed25519_sizes_match_spec() {
        use crate::alg::Ed25519;
        assert_eq!(Ed25519::SIG_SIZE, 64);
        assert_eq!(Ed25519::PUB_SIZE, 32);
        assert_eq!(Ed25519::PRV_SIZE, 32);
    }
}
