# Coz Rust

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE.md)

A Rust implementation of the [Coz](https://github.com/Cyphrme/Coz) cryptographic
JSON messaging specification.

## What is Coz?

**Coz** is a cryptographic JSON messaging specification that uses digital
signatures and hashes to ensure secure, human-readable, and interoperable
communication.

### Example Coz Message

```json
{
  "pay": {
    "msg": "Coz is a cryptographic JSON messaging specification.",
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/msg/create"
  },
  "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
}
```

## Design Goals

1. **Idiomatic Rust** - Leverage Rust's type system and ownership model
2. **Minimal dependencies** - Production-ready with a small footprint
3. **Specification compliance** - Match the Go reference implementation behavior
4. **Interoperability** - Compatible with Go Coz and CozJS

## Status

🚧 **Under Development** - This library is being built incrementally.

### Algorithm Support

| Algorithm | Status      | Notes                          |
| --------- | ----------- | ------------------------------ |
| ES256     | ✅ Planned  | ECDSA P-256                    |
| ES384     | ✅ Planned  | ECDSA P-384                    |
| ES512     | ✅ Planned  | ECDSA P-521                    |
| Ed25519   | ✅ Planned  | EdDSA                          |
| Ed25519ph | 🔮 Future   | Pre-hashed Ed25519             |
| ES256k    | 🔮 Future   | secp256k1 for Bitcoin/Ethereum |
| ES224     | ⏸️ Deferred | P-224 crate less mature        |

### Features

- **Type-safe** - Leverages Rust's type system for compile-time correctness
- **Minimal dependencies** - RustCrypto ecosystem
- **MSRV 1.75** - Minimum supported Rust version

## Specification Overview

### Standard Fields

#### Pay (Payload) Fields

| Field | Description                 | Example                 |
| ----- | --------------------------- | ----------------------- |
| `alg` | Signing algorithm           | `"ES256"`               |
| `now` | Unix timestamp of signature | `1623132000`            |
| `tmb` | Key thumbprint              | `"U5XUZ..."`            |
| `typ` | Application-defined type    | `"cyphr.me/msg/create"` |
| `msg` | Message payload             | `"Hello, world!"`       |
| `dig` | Digest of external content  | `"LSgWE..."`            |

#### Key Fields

| Field | Description                       | Example      |
| ----- | --------------------------------- | ------------ |
| `alg` | Algorithm                         | `"ES256"`    |
| `pub` | Public key component              | `"2nTOa..."` |
| `prv` | Private key component             | `"bNstg..."` |
| `tmb` | Thumbprint (hash of `[alg, pub]`) | `"U5XUZ..."` |
| `tag` | Human-readable label              | `"My Key"`   |
| `rvk` | Revocation timestamp              | `1623132000` |

#### Coz Object Fields

| Field | Description                 |
| ----- | --------------------------- |
| `pay` | Signed payload              |
| `sig` | Signature over `cad`        |
| `cad` | Canonical digest of `pay`   |
| `czd` | Digest of `[cad, sig]`      |
| `can` | Canon (ordered field names) |

### Algorithms (Coz Specification)

The full Coz specification supports these algorithms. See status table above for
this implementation's current coverage.

- **ECDSA**: ES224, ES256, ES384, ES512, ES256k
- **EdDSA**: Ed25519, Ed25519ph

### Canonicalization

Coz uses JSON canonicalization for creating digests, signing, and verification:

1. Omit fields not in canon
2. Order fields by canon
3. Omit insignificant whitespace

The key thumbprint (`tmb`) uses the fixed canon `["alg", "pub"]`.

### Binary Encoding

All binary values use [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648)
base64 URL-safe encoding with padding truncated (b64ut).

## Usage

```rust
use coz::{SigningKey, ES256, PayBuilder};
use rand::rngs::OsRng;

// Generate a new ES256 signing key
let signing_key = SigningKey::<ES256>::generate(&mut OsRng);

// Create and sign a message using the builder pattern
let coz = PayBuilder::new()
    .msg("Hello from Coz Rust!")
    .typ("example/hello")
    .sign(&signing_key)?;

// Extract the verifying key (public only)
let verifying_key = signing_key.verifying_key();

// Verify the message
assert!(verifying_key.verify(&coz));

// Thumbprint is algorithm-aware
let tmb: &Thumbprint<ES256> = signing_key.thumbprint();
println!("Key thumbprint: {}", tmb);
```

## Related Projects

- [Coz (Go)](https://github.com/Cyphrme/Coz) - Reference implementation
- [CozJS](https://github.com/Cyphrme/CozJS) - JavaScript implementation
- [Coz CLI](https://github.com/Cyphrme/CozeCLI) - Command-line tool

## License

BSD-3-Clause. See [LICENSE.md](LICENSE.md).

---

_Coz is created by [Cyphr.me](https://cyphr.me)._
