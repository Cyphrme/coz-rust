//! Coz CLI - Command line interface for Coz cryptographic JSON messaging.

mod input;

use anyhow::Result;
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

fn cmd_newkey(alg: Alg) -> Result<()> {
    match alg {
        Alg::ES256 => todo!("ES256 key generation"),
        Alg::ES384 => todo!("ES384 key generation"),
        Alg::ES512 => todo!("ES512 key generation"),
        Alg::Ed25519 => todo!("Ed25519 key generation"),
    }
}

fn cmd_tmb(_key: KeyInput) -> Result<()> {
    todo!("thumbprint calculation")
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
