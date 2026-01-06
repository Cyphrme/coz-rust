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

fn cmd_signpay(_pay: PayInput, _key: KeyInput) -> Result<()> {
    todo!("sign payload")
}

fn cmd_verify(_coz: CozInput, _key: KeyInput) -> Result<()> {
    todo!("verify signature")
}

fn cmd_meta(_coz: CozInput) -> Result<()> {
    todo!("compute meta")
}

fn cmd_revoke(_key: KeyInput) -> Result<()> {
    todo!("generate revoke")
}
