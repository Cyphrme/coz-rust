//! Input types for CLI arguments.
//!
//! These types wrap raw string arguments and provide file-or-JSON detection.

use std::str::FromStr;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Input that can be a JSON literal or file path (for key data).
#[derive(Clone, Debug)]
pub struct KeyInput(String);

impl FromStr for KeyInput {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl KeyInput {
    /// Load and parse as JSON.
    ///
    /// If the input starts with `{`, it's parsed as a JSON literal.
    /// Otherwise, it's treated as a file path and read from disk.
    pub fn load(&self) -> Result<serde_json::Value> {
        if self.0.starts_with('{') {
            serde_json::from_str(&self.0).context("failed to parse key JSON")
        } else {
            let content = std::fs::read_to_string(&self.0).context("failed to read key file")?;
            serde_json::from_str(&content).context("failed to parse key file as JSON")
        }
    }
}

/// Input that can be a JSON literal or file path (for Coz messages).
#[derive(Clone, Debug)]
pub struct CozInput(String);

impl FromStr for CozInput {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// Parsed Coz message with preserved raw pay bytes.
#[derive(Debug, Deserialize)]
pub struct CozParsed<'a> {
    /// Raw pay JSON (preserved exactly as input, no re-serialization)
    #[serde(borrow)]
    pub pay: &'a serde_json::value::RawValue,
    /// Signature (base64url encoded)
    pub sig: String,
}

impl CozInput {
    /// Load and parse as JSON.
    pub fn load(&self) -> Result<serde_json::Value> {
        if self.0.starts_with('{') {
            serde_json::from_str(&self.0).context("failed to parse coz JSON")
        } else {
            let content = std::fs::read_to_string(&self.0).context("failed to read coz file")?;
            serde_json::from_str(&content).context("failed to parse coz file as JSON")
        }
    }

    /// Load raw content as string for parsing with preserved raw values.
    pub fn load_raw_str(&self) -> Result<String> {
        if self.0.starts_with('{') {
            Ok(self.0.clone())
        } else {
            std::fs::read_to_string(&self.0).context("failed to read coz file")
        }
    }
}

/// Input that can be a JSON literal or file path (for Pay payloads).
#[derive(Clone, Debug)]
pub struct PayInput(String);

impl FromStr for PayInput {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl PayInput {
    /// Load and parse as JSON.
    pub fn load(&self) -> Result<serde_json::Value> {
        if self.0.starts_with('{') {
            serde_json::from_str(&self.0).context("failed to parse pay JSON")
        } else {
            let content = std::fs::read_to_string(&self.0).context("failed to read pay file")?;
            serde_json::from_str(&content).context("failed to parse pay file as JSON")
        }
    }
}
