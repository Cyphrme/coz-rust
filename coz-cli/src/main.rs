//! Coz CLI - Command line interface for Coz cryptographic JSON messaging.

mod input;

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand, ValueEnum};
use input::{CozInput, KeyInput, PayInput};

/// CLI for Coz cryptographic JSON messaging
#[derive(Parser)]
#[command(name = "coz")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Supported signature algorithms
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Alg {
    ES256,
    ES384,
    ES512,
    Ed25519,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new key
    Newkey {
        /// Signature algorithm
        #[arg(default_value = "ed25519")]
        alg: Alg,
    },

    /// Calculate thumbprint for a key
    Tmb {
        /// Key (JSON string or file path)
        key: KeyInput,
    },

    /// Sign a Coz message
    Sign {
        /// Coz message (JSON string or file path)
        coz: CozInput,
        /// Private key (JSON string or file path)
        key: KeyInput,
    },

    /// Sign a payload, return Coz message
    Signpay {
        /// Payload (JSON string or file path)
        pay: PayInput,
        /// Private key (JSON string or file path)
        key: KeyInput,
    },

    /// Verify a Coz signature
    Verify {
        /// Coz message (JSON string or file path)
        coz: CozInput,
        /// Public key (JSON string or file path)
        key: KeyInput,
    },

    /// Compute metadata (cad, czd, can)
    Meta {
        /// Coz message (JSON string or file path)
        coz: CozInput,
    },

    /// Generate a revocation message
    Revoke {
        /// Private key (JSON string or file path)
        key: KeyInput,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Newkey { alg } => cmd_newkey(alg),
        Command::Tmb { key } => cmd_tmb(key),
        Command::Sign { coz, key } => cmd_sign(coz, key),
        Command::Signpay { pay, key } => cmd_signpay(pay, key),
        Command::Verify { coz, key } => cmd_verify(coz, key),
        Command::Meta { coz } => cmd_meta(coz),
        Command::Revoke { key } => cmd_revoke(key),
    }
}

/// Generate a new key and print as JSON.
fn cmd_newkey(alg: Alg) -> Result<()> {
    match alg {
        Alg::ES256 => print_key(coz_rs::SigningKey::<coz_rs::ES256>::generate()),
        Alg::ES384 => print_key(coz_rs::SigningKey::<coz_rs::ES384>::generate()),
        Alg::ES512 => print_key(coz_rs::SigningKey::<coz_rs::ES512>::generate()),
        Alg::Ed25519 => print_key(coz_rs::SigningKey::<coz_rs::Ed25519>::generate()),
    }
    Ok(())
}

/// Print a signing key as Coz JSON format.
fn print_key<A>(key: coz_rs::SigningKey<A>)
where
    A: coz_rs::Algorithm + coz_rs::key::ops::KeyOps,
{
    let alg = key.algorithm();
    let prv = Base64UrlUnpadded::encode_string(&key.private_key_bytes());
    let pub_key = Base64UrlUnpadded::encode_string(key.verifying_key().public_key_bytes());
    let tmb = key.thumbprint().to_b64();

    // Output in Coz JSON key format (field order: alg, prv, pub, tmb)
    println!(
        r#"{{"alg":"{}","prv":"{}","pub":"{}","tmb":"{}"}}"#,
        alg, prv, pub_key, tmb
    );
}

/// Calculate and print the thumbprint for a key.
fn cmd_tmb(key: KeyInput) -> Result<()> {
    use anyhow::Context;

    let json = key.load()?;

    // Extract alg and pub from key JSON
    let alg = json
        .get("alg")
        .and_then(|v| v.as_str())
        .context("key missing 'alg' field")?;

    let pub_b64 = json
        .get("pub")
        .and_then(|v| v.as_str())
        .context("key missing 'pub' field")?;

    // Decode public key bytes
    let pub_bytes =
        Base64UrlUnpadded::decode_vec(pub_b64).context("invalid base64 in 'pub' field")?;

    // Compute thumbprint
    let tmb = coz_rs::compute_thumbprint_for_alg(alg, &pub_bytes)
        .with_context(|| format!("unsupported algorithm: {alg}"))?;

    println!("{}", tmb.to_b64());
    Ok(())
}

fn cmd_sign(_coz: CozInput, _key: KeyInput) -> Result<()> {
    todo!("sign coz")
}

/// Sign a payload and return a Coz message.
fn cmd_signpay(pay: PayInput, key: KeyInput) -> Result<()> {
    use anyhow::Context;

    let pay_json = pay.load()?;
    let key_json = key.load()?;

    // Extract key fields
    let alg = key_json
        .get("alg")
        .and_then(|v| v.as_str())
        .context("key missing 'alg' field")?;
    let prv_b64 = key_json
        .get("prv")
        .and_then(|v| v.as_str())
        .context("key missing 'prv' field")?;
    let pub_b64 = key_json
        .get("pub")
        .and_then(|v| v.as_str())
        .context("key missing 'pub' field")?;
    let tmb_b64 = key_json
        .get("tmb")
        .and_then(|v| v.as_str())
        .context("key missing 'tmb' field")?;

    let prv_bytes = Base64UrlUnpadded::decode_vec(prv_b64).context("invalid base64 in 'prv'")?;
    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).context("invalid base64 in 'pub'")?;

    // Augment pay with alg and tmb
    let mut pay_obj = pay_json
        .as_object()
        .context("pay must be a JSON object")?
        .clone();
    pay_obj.insert("alg".to_string(), serde_json::json!(alg));
    pay_obj.insert("tmb".to_string(), serde_json::json!(tmb_b64));

    // Serialize the augmented pay
    let augmented_pay = serde_json::to_vec(&pay_obj)?;

    // Sign
    let (sig, _cad) = coz_rs::sign_json(&augmented_pay, alg, &prv_bytes, &pub_bytes)
        .with_context(|| format!("failed to sign with algorithm: {alg}"))?;

    // Output Coz JSON
    let sig_b64 = Base64UrlUnpadded::encode_string(&sig);
    println!(
        r#"{{"pay":{},"sig":"{}"}}"#,
        serde_json::to_string(&pay_obj)?,
        sig_b64
    );

    Ok(())
}

/// Verify a Coz message signature.
fn cmd_verify(coz: CozInput, key: KeyInput) -> Result<()> {
    use anyhow::Context;

    let coz_json = coz.load()?;
    let key_json = key.load()?;

    // Extract pay and sig from coz
    let pay_value = coz_json.get("pay").context("coz missing 'pay' field")?;
    let pay_json = serde_json::to_vec(pay_value)?;

    let sig_b64 = coz_json
        .get("sig")
        .and_then(|v| v.as_str())
        .context("coz missing 'sig' field")?;
    let sig = Base64UrlUnpadded::decode_vec(sig_b64).context("invalid base64 in 'sig' field")?;

    // Extract alg and pub from key
    let alg = key_json
        .get("alg")
        .and_then(|v| v.as_str())
        .context("key missing 'alg' field")?;
    let pub_b64 = key_json
        .get("pub")
        .and_then(|v| v.as_str())
        .context("key missing 'pub' field")?;
    let pub_bytes =
        Base64UrlUnpadded::decode_vec(pub_b64).context("invalid base64 in 'pub' field")?;

    // Verify
    let valid = coz_rs::verify_json(&pay_json, &sig, alg, &pub_bytes)
        .with_context(|| format!("unsupported algorithm: {alg}"))?;

    println!("{}", valid);
    Ok(())
}

fn cmd_meta(_coz: CozInput) -> Result<()> {
    todo!("compute meta")
}

fn cmd_revoke(_key: KeyInput) -> Result<()> {
    todo!("generate revoke")
}
