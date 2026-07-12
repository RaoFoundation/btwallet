# ⚠️ This package is superseded

**`bittensor-wallet` is superseded by the [`bittensor`](https://pypi.org/project/bittensor/) package (Bittensor 11), where the wallet ships as `bittensor.wallet`.** New projects should `pip install bittensor` instead. Development happens in the [subtensor monorepo](https://github.com/RaoFoundation/subtensor), and documentation lives at [bittensor.com/docs](https://bittensor.com/docs).

The on-disk keyfile format is unchanged — existing wallets work as-is. Existing `bittensor-wallet` releases remain installable from PyPI, but this repository is no longer maintained and no further feature releases will be cut from it.

---

<div align="center">

# Bittensor Wallet <!-- omit in toc -->

[![Discord Chat](https://img.shields.io/discord/308323056592486420.svg)](https://discord.gg/bittensor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://badge.fury.io/py/bittensor-wallet.svg)](https://badge.fury.io/py/bittensor-wallet)

[![Crates.io](https://img.shields.io/crates/v/btwallet.svg)](https://crates.io/crates/btwallet)
[![Documentation](https://docs.rs/btwallet/badge.svg)](https://docs.rs/btwallet)
---

## Internet-scale Neural Networks <!-- omit in toc -->

[Bittensor SDK](https://github.com/opentensor/bittensor/tree/master) • [BTCLI](https://github.com/opentensor/btcli) • [Research](https://bittensor.com/whitepaper)

</div>

## Bittensor Wallet

The Bittensor Wallet SDK is a Python interface for a powerful Rust-based Bittensor wallet functionality. You do not need to know Rust to use this Wallet SDK. However, if you want to contribute to the Rust components of this Wallet SDK, the Rust source is located in the [src](./src) directory. You can look at the development history by inspecting the Changelog.md.

### Contributing
#### Signed Commits

All commits in pull requests must be signed. We require signed commits to verify the authenticity of contributions and ensure code integrity.

To sign your commits, you must have GPG signing configured in Git:

```bash
git commit -S -m "your commit message"
```

Or configure Git to sign all commits automatically:

```bash
git config --global commit.gpgsign true
```

For instructions on setting up GPG key signing, see [GitHub's documentation on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

> **Note:** Pull requests containing unsigned commits will not be merged.


## Documentation

For full documentation, see [bittensor.com/docs](https://bittensor.com/docs).

---

## Before you proceed

If you installed either Bittensor SDK version `9.x.x` or BTCLI version `9.x.x` then the Wallet SDK 3.x.x is already installed. The below installation steps are only for a standalone installation of the Wallet SDK 3.x.x package.

## Install

Follow the below steps to install the Bittensor Wallet SDK:

### From PyPI

Use this option if you want to use the Wallet SDK.

```bash
python3 -m venv btwallet-venv  # create a virtual env
source btwallet-venv/bin/activate  # activate the env
pip install bittensor-wallet  # install bittensor-wallet
```

### From source

Use this option if you want to develop your application using the Wallet SDK.

```bash
python3 -m venv btwallet-venv  # create a virtual env
source venv/bin/activate  # activate the env
git clone https://github.com/opentensor/btwallet.git
cd btwallet
pip install maturin
maturin develop
```

After the `maturin develop` command completes, run the below command:

```bash
pip list
```

You will see `bittensor-wallet` in the list on installed packages. This means the installation was successful.

---

## Verify your installation

In the `python3` interpreter, run the below code to verify that your installation was successful. See an example output below:

```py
# python3
# Python 3.12.4 (v3.12.4:8e8a4baf65, Jun  6 2024, 17:33:18) [Clang 13.0.0 (clang-1300.0.29.30)] on darwin
# Type "help", "copyright", "credits" or "license" for more information.

import bittensor_wallet
print(bittensor_wallet.__version__)
>>> 3.x.x
```

The above will print the Wallet SDK version you just installed, i.e., `3.x.x`, confirming that the installation was successful.

---

## Usage examples

**1. Create a wallet**

In the `python3` interpreter, run the below code:

```python
from bittensor_wallet import Wallet

# creates wallet with name `default`
wallet = Wallet()
wallet.create()
```

If a wallet with the name "default" already exists, then you will see a message. If it doesn't exist, then the above code will create both a coldkey and a hotkey and displays the following information, including your mnemonic **(mnemonics are replaced with `x` in the below example for security)**:

```bash
IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.

The mnemonic to the new coldkey is:

forward xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xx actress

You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:
btcli w regen-coldkey --mnemonic "forward xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xx actress"

Specify password for key encryption:
Retype your password:

IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.

The mnemonic to the new hotkey is:

fuel xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xxx bind

You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:
btcli w regen-hotkey --mnemonic "fuel xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xxx bind"

name: 'default', hotkey: 'default', path: '~/.bittensor/wallets/'
>>> print(wallet)
Wallet (Name: 'default', Hotkey: 'default', Path: '~/.bittensor/wallets/')
>>>
```

**2. Pass arguments to a class other than the default**

```bash
name (str): The name of the wallet, used to identify it among possibly multiple wallets.
hotkey (str): String identifier for the hotkey.
path (str): File system path where wallet keys are stored.
config (Config): Bittensor configuration object.
```

In the `python3` interpreter, run the below code. See an example below (only partial is shown):

```py
# python3
# Python 3.12.4 (v3.12.4:8e8a4baf65, Jun  6 2024, 17:33:18) [Clang 13.0.0 (clang-1300.0.29.30)] on darwin
# Type "help", "copyright", "credits" or "license" for more information.

from bittensor_wallet import Wallet

my_name = "my_wallet_name"
my_path = "path_to_my_wallet"
my_hotkey = "name_of_my_hotkey"

my_wallet = Wallet(name=my_name, path=my_path, hotkey=my_hotkey)
my_wallet.create()

>>> IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.
```
The above will create a wallet with "my_wallet_name". 

---

## Rust crate

This project is also published as a pure Rust crate [`btwallet`](https://crates.io/crates/btwallet) on crates.io for use without Python. See the [crate documentation](https://docs.rs/btwallet) for details.
