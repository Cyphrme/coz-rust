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

## Features

- **Type-safe** - Compile-time algorithm correctness via generics
- **Spec compliant** - Cross-verified with Go reference implementation
- **Non-malleable** - ECDSA signatures normalized to low-S form
- **Minimal dependencies** - RustCrypto ecosystem only
- **MSRV 1.85** - Minimum supported Rust version

## Algorithm Support

| Algorithm | Status      | Notes                          |
| --------- | ----------- | ------------------------------ |
| ES256     | ✅          | ECDSA P-256                    |
| ES384     | ✅          | ECDSA P-384                    |
| ES512     | ✅          | ECDSA P-521                    |
| Ed25519   | ✅          | EdDSA                          |
| Ed25519ph | 🔮 Future   | Pre-hashed Ed25519             |
| ES256k    | 🔮 Future   | secp256k1 for Bitcoin/Ethereum |
| ES224     | ⏸️ Deferred | P-224 crate less mature        |

## Usage

```rust
use coz::{SigningKey, ES256, PayBuilder};

// Generate a new ES256 signing key
let key = SigningKey::<ES256>::generate();

// Create and sign a message
let coz = PayBuilder::new()
    .msg("Hello from Coz Rust!")
    .typ("example/hello")
    .sign(&key)?;

// Verify the message
assert!(coz.verify(key.verifying_key()));

// Get key thumbprint
println!("Key: {}", key.thumbprint());
```

## API Overview

### Key Types

```rust
// Generate keys
let key = SigningKey::<ES256>::generate();
let verifying_key = key.verifying_key();
let thumbprint = key.thumbprint();

// Sign raw digests
let sig = key.sign(&digest);
let valid = verifying_key.verify(&digest, &sig);
```

### PayBuilder

```rust
let pay = PayBuilder::new()
    .msg("Hello")                    // Message content
    .typ("example/type")             // Application type
    .now(1623132000)                 // Unix timestamp
    .dig(hash_bytes)                 // External digest
    .field("custom", json_value)     // Custom fields
    .build();                        // Build Pay

// Or sign directly
let coz = PayBuilder::new().msg("Hi").sign(&key)?;
```

### Coz Message

```rust
// Sign a payload
let coz = Coz::sign(pay, &key)?;

// Verify
assert!(coz.verify(&verifying_key));

// Access fields
let cad = coz.cad();  // Canonical digest
let czd = coz.czd();  // Coz digest
let sig = coz.sig();  // Signature bytes
```

### Canonicalization

```rust
use coz::{canon, canonical, canonical_hash, KEY_CANON, CZD_CANON};

// Extract field order
let fields = canon(json)?;

// Generate canonical form
let compact = canonical(json, None)?;
let ordered = canonical(json, Some(&["a", "b"]))?;

// Compute canonical digest
let cad = canonical_hash::<ES256>(json, None)?;
```

### Revocation

```rust
use coz::{revoke, is_valid_rvk, RVK_MAX_SIZE};

// Create self-revocation
let rvk_coz = revoke(&key, None)?;

// Check revocation validity
assert!(is_valid_rvk(1623132000));
```

## Specification

See the [Coz Specification](Coz/README.md) for full details.

## Related Projects

- [Coz (Go)](https://github.com/Cyphrme/Coz) - Reference implementation
- [CozJS](https://github.com/Cyphrme/CozJS) - JavaScript implementation
- [Coz CLI](https://github.com/Cyphrme/CozeCLI) - Command-line tool

## License

BSD-3-Clause. See [LICENSE.md](LICENSE.md).

---

_Coz is created by [Cyphr.me](https://cyphr.me)._
