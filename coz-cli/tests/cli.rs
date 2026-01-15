//! Integration tests for the Coz CLI.
//!
//! These tests verify end-to-end functionality by invoking the CLI binary.

use std::io::Write;

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::NamedTempFile;

/// Get a Command for the coz binary.
fn coz() -> Command {
    cargo_bin_cmd!("coz")
}

#[test]
fn newkey_default_algorithm() {
    coz()
        .arg("newkey")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\":\"Ed25519\""))
        .stdout(predicate::str::contains("\"prv\":"))
        .stdout(predicate::str::contains("\"pub\":"))
        .stdout(predicate::str::contains("\"tmb\":"));
}

#[test]
fn newkey_es256() {
    coz()
        .args(["newkey", "es256"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\":\"ES256\""));
}

#[test]
fn newkey_es384() {
    coz()
        .args(["newkey", "es384"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\":\"ES384\""));
}

#[test]
fn newkey_es512() {
    coz()
        .args(["newkey", "es512"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\":\"ES512\""));
}

#[test]
fn tmb_from_inline_json() {
    // Generate a key first
    let output = coz().arg("newkey").output().unwrap();
    let key = String::from_utf8(output.stdout).unwrap();

    // Calculate thumbprint
    coz()
        .args(["tmb", &key])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn signpay_and_verify_roundtrip() {
    // Generate key
    let key_output = coz().arg("newkey").output().unwrap();
    let key = String::from_utf8(key_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Extract alg and tmb from key for the pay
    let key_json: serde_json::Value = serde_json::from_str(&key).unwrap();
    let alg = key_json["alg"].as_str().unwrap();
    let tmb = key_json["tmb"].as_str().unwrap();

    // Sign a payload with required alg and tmb
    let pay = format!(r#"{{"alg":"{}","msg":"Hello, Coz!","tmb":"{}"}}"#, alg, tmb);
    let msg_output = coz().args(["signpay", &pay, &key]).output().unwrap();
    let msg = String::from_utf8(msg_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Verify the signature
    coz()
        .args(["verify", &msg, &key])
        .assert()
        .success()
        .stdout("true\n");
}

#[test]
fn verify_wrong_key_fails() {
    // Generate two keys
    let key1_output = coz().arg("newkey").output().unwrap();
    let key1 = String::from_utf8(key1_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    let key2_output = coz().arg("newkey").output().unwrap();
    let key2 = String::from_utf8(key2_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Extract alg and tmb from key1 for the pay
    let key1_json: serde_json::Value = serde_json::from_str(&key1).unwrap();
    let alg = key1_json["alg"].as_str().unwrap();
    let tmb = key1_json["tmb"].as_str().unwrap();

    // Sign with key1
    let pay = format!(r#"{{"alg":"{}","msg":"test","tmb":"{}"}}"#, alg, tmb);
    let msg_output = coz().args(["signpay", &pay, &key1]).output().unwrap();
    let msg = String::from_utf8(msg_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Verify with key2 should fail (signature won't match)
    coz()
        .args(["verify", &msg, &key2])
        .assert()
        .success()
        .stdout("false\n");
}

#[test]
fn sign_resigns_with_same_key() {
    // sign command is for re-signing with the SAME key (refreshing signature)
    // For signing with a different key, you need to update pay.alg and pay.tmb first
    let key_output = coz().arg("newkey").output().unwrap();
    let key = String::from_utf8(key_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Extract alg and tmb from key
    let key_json: serde_json::Value = serde_json::from_str(&key).unwrap();
    let alg = key_json["alg"].as_str().unwrap();
    let tmb = key_json["tmb"].as_str().unwrap();

    // Sign with key
    let pay = format!(r#"{{"alg":"{}","msg":"test","tmb":"{}"}}"#, alg, tmb);
    let msg1_output = coz().args(["signpay", &pay, &key]).output().unwrap();
    let msg1 = String::from_utf8(msg1_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Re-sign with same key (should work)
    let msg2_output = coz().args(["sign", &msg1, &key]).output().unwrap();
    assert!(msg2_output.status.success(), "sign failed");
    let msg2 = String::from_utf8(msg2_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Verify with key should succeed
    coz()
        .args(["verify", &msg2, &key])
        .assert()
        .success()
        .stdout("true\n");
}

#[test]
fn meta_computes_digests() {
    // Generate key and sign
    let key_output = coz().arg("newkey").output().unwrap();
    let key = String::from_utf8(key_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Extract alg and tmb from key
    let key_json: serde_json::Value = serde_json::from_str(&key).unwrap();
    let alg = key_json["alg"].as_str().unwrap();
    let tmb = key_json["tmb"].as_str().unwrap();

    let pay = format!(r#"{{"alg":"{}","msg":"test","tmb":"{}"}}"#, alg, tmb);
    let msg_output = coz().args(["signpay", &pay, &key]).output().unwrap();
    let msg = String::from_utf8(msg_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Compute meta
    coz()
        .args(["meta", &msg])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"can\":"))
        .stdout(predicate::str::contains("\"cad\":"))
        .stdout(predicate::str::contains("\"czd\":"));
}

#[test]
fn revoke_generates_valid_message() {
    // Generate key
    let key_output = coz().arg("newkey").output().unwrap();
    let key = String::from_utf8(key_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Generate revocation
    let rvk_output = coz().args(["revoke", &key]).output().unwrap();
    let rvk = String::from_utf8(rvk_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Should contain rvk field
    assert!(rvk.contains("\"rvk\":"));

    // Verify the revocation message
    coz()
        .args(["verify", &rvk, &key])
        .assert()
        .success()
        .stdout("true\n");
}

#[test]
fn key_from_file() {
    // Generate key
    let key_output = coz().arg("newkey").output().unwrap();
    let key = String::from_utf8(key_output.stdout).unwrap();

    // Write to temp file
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(key.as_bytes()).unwrap();

    // Use file path for tmb
    coz()
        .args(["tmb", file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn all_algorithms_roundtrip() {
    for alg_name in ["ed25519", "es256", "es384", "es512"] {
        // Generate key
        let key_output = coz().args(["newkey", alg_name]).output().unwrap();
        let key = String::from_utf8(key_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Extract alg and tmb from key
        let key_json: serde_json::Value = serde_json::from_str(&key).unwrap();
        let alg = key_json["alg"].as_str().unwrap();
        let tmb = key_json["tmb"].as_str().unwrap();

        // Sign with properly-formed pay
        let pay = format!(r#"{{"alg":"{}","msg":"test","tmb":"{}"}}"#, alg, tmb);
        let msg_output = coz().args(["signpay", &pay, &key]).output().unwrap();
        let msg = String::from_utf8(msg_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Verify
        coz()
            .args(["verify", &msg, &key])
            .assert()
            .success()
            .stdout("true\n");
    }
}

/// Regression test: signpay output must be verifiable immediately.
///
/// This test guards against a bug where signpay would sign one serialization
/// of the pay object but output a different serialization (due to re-serializing
/// the object, which could change field order). The fix ensures we output the
/// exact bytes that were signed.
#[test]
fn signpay_output_matches_signed_bytes() {
    // Use ES256 deterministically
    let key = r#"{"alg":"ES256","prv":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA","pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g","tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"}"#;

    // Sign a payload with specific field order (alg and tmb are required)
    let pay = r#"{"alg":"ES256","zzz":"last","aaa":"first","msg":"hello","tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"}"#;
    let msg_output = coz().args(["signpay", pay, key]).output().unwrap();
    assert!(msg_output.status.success(), "signpay failed");

    let msg = String::from_utf8(msg_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Verify the signature - this will fail if output bytes don't match signed bytes
    coz()
        .args(["verify", &msg, key])
        .assert()
        .success()
        .stdout("true\n");
}

/// Regression test: sign (re-sign) output must be verifiable immediately.
///
/// Similar to signpay_output_matches_signed_bytes, but for the sign command
/// that re-signs an existing coz with the same key.
#[test]
fn sign_output_matches_signed_bytes() {
    let key = r#"{"alg":"ES256","prv":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA","pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g","tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"}"#;

    // Sign with key
    let pay = r#"{"alg":"ES256","msg":"test","tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"}"#;
    let msg1_output = coz().args(["signpay", pay, key]).output().unwrap();
    let msg1 = String::from_utf8(msg1_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Re-sign with same key
    let msg2_output = coz().args(["sign", &msg1, key]).output().unwrap();
    assert!(msg2_output.status.success(), "sign failed");
    let msg2 = String::from_utf8(msg2_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Verify with key - will fail if output bytes don't match signed bytes
    coz()
        .args(["verify", &msg2, key])
        .assert()
        .success()
        .stdout("true\n");
}
