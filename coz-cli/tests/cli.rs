//! Integration tests for the Coz CLI.
//!
//! These tests verify end-to-end functionality by invoking the CLI binary.

use std::io::Write;

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
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

    // Sign a payload
    let msg_output = coz()
        .args(["signpay", r#"{"msg":"Hello, Coz!"}"#, &key])
        .output()
        .unwrap();
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

    // Sign with key1
    let msg_output = coz()
        .args(["signpay", r#"{"msg":"test"}"#, &key1])
        .output()
        .unwrap();
    let msg = String::from_utf8(msg_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Verify with key2 should fail
    coz()
        .args(["verify", &msg, &key2])
        .assert()
        .success()
        .stdout("false\n");
}

#[test]
fn sign_resigns_with_new_key() {
    // Generate two keys
    let key1_output = coz().arg("newkey").output().unwrap();
    let key1 = String::from_utf8(key1_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    let key2_output = coz().args(["newkey", "es256"]).output().unwrap();
    let key2 = String::from_utf8(key2_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Sign with key1
    let msg1_output = coz()
        .args(["signpay", r#"{"msg":"test"}"#, &key1])
        .output()
        .unwrap();
    let msg1 = String::from_utf8(msg1_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Re-sign with key2
    let msg2_output = coz().args(["sign", &msg1, &key2]).output().unwrap();
    let msg2 = String::from_utf8(msg2_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Should contain ES256 (key2's algorithm)
    assert!(msg2.contains("\"alg\":\"ES256\""));

    // Verify with key2 should succeed
    coz()
        .args(["verify", &msg2, &key2])
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

    let msg_output = coz()
        .args(["signpay", r#"{"msg":"test"}"#, &key])
        .output()
        .unwrap();
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
    for alg in ["ed25519", "es256", "es384", "es512"] {
        // Generate key
        let key_output = coz().args(["newkey", alg]).output().unwrap();
        let key = String::from_utf8(key_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Sign
        let msg_output = coz()
            .args(["signpay", r#"{"msg":"test"}"#, &key])
            .output()
            .unwrap();
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
