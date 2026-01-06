# Publishing to crates.io

This document describes the publishing workflow for the Coz Rust workspace.

## Crates

| Crate     | Description | crates.io                                                    |
| --------- | ----------- | ------------------------------------------------------------ |
| `coz-rs`  | Library     | [crates.io/crates/coz-rs](https://crates.io/crates/coz-rs)   |
| `coz-cli` | CLI binary  | [crates.io/crates/coz-cli](https://crates.io/crates/coz-cli) |

## Publishing Order

**Important:** `coz-rs` must be published before `coz-cli` because `coz-cli` depends on `coz-rs`.

## Workflow

### 1. Update Versions

Update version numbers in:

- `coz-rs/Cargo.toml` - bump `version`
- `coz-cli/Cargo.toml` - bump `version` and `coz-rs` dependency version

### 2. Verify Builds

```sh
cargo build --release
cargo test
cargo clippy
```

### 3. Dry Run (Optional)

```sh
cargo publish --dry-run -p coz-rs
```

### 4. Publish Library

```sh
cargo publish -p coz-rs
```

Wait for crates.io to index the new version (usually a few seconds).

### 5. Publish CLI

```sh
cargo publish -p coz-cli
```

## Dependency Configuration

The `coz-cli/Cargo.toml` uses both `path` and `version`:

```toml
coz-rs = { path = "../coz-rs", version = "0.2" }
```

- `path` - Used for local development
- `version` - Used when published to crates.io

## Version Coordination

When bumping `coz-rs` version:

1. Update `coz-rs/Cargo.toml` version
2. Update `coz-cli/Cargo.toml` `coz-rs` dependency version to match
3. Publish `coz-rs` first
4. Publish `coz-cli` second
