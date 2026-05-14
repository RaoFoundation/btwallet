# btwallet

Substrate-based key management, encryption, and signing for the [Bittensor](https://bittensor.com) network.

[![Crates.io](https://img.shields.io/crates/v/btwallet.svg)](https://crates.io/crates/btwallet)
[![Documentation](https://docs.rs/btwallet/badge.svg)](https://docs.rs/btwallet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`btwallet` provides wallet creation, mnemonic-based key derivation, keyfile encryption/decryption (NaCl, Ansible Vault, Fernet), and SS58 address utilities for Bittensor.

## Usage

```toml
[dependencies]
btwallet = "4"
```

```rust
use bittensor_wallet::keyfile;
use bittensor_wallet::keypair::Keypair;

let keypair = Keypair::create_from_mnemonic("your twelve word mnemonic ...");
```

## Features

| Feature | Description |
|---|---|
| *(default)* | Pure Rust — no Python dependency |
| `python-bindings` | Enables PyO3 bindings for use from Python |
| `extension-module` | Builds as a Python extension module (used by maturin) |
| `vendored-openssl` | Vendors OpenSSL for static linking |

## Python package

This crate also powers the [`bittensor-wallet`](https://pypi.org/project/bittensor-wallet/) Python package on PyPI. If you're looking for the Python SDK, see the [README](https://github.com/opentensor/btwallet#readme).

## License

MIT
