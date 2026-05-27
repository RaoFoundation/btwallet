# Changelog

## 4.1.0 /2026-05-27

## What's Changed
* Release/4.0.1 by @basfroman in https://github.com/latent-to/btwallet/pull/168
* Allows running e2e tests by community PRs. by @thewhaleking in https://github.com/latent-to/btwallet/pull/169
* updated docstrings by @chideraao in https://github.com/latent-to/btwallet/pull/170
* Enable publishing btwallet as a standalone Rust crate on crates.io by @basfroman in https://github.com/latent-to/btwallet/pull/176
* Fix clippy warnings and simplify check-rust workflow by @basfroman in https://github.com/latent-to/btwallet/pull/177
* Add info about signed commits by @thewhaleking in https://github.com/latent-to/btwallet/pull/184
* Maintenance by @thewhaleking in https://github.com/latent-to/btwallet/pull/194
* Add `ED25519` support with `encrypt`/`decrypt` by @basfroman in https://github.com/latent-to/btwallet/pull/196
* Add ED25519 crypto type support by @basfroman in https://github.com/latent-to/btwallet/pull/195
* Complete pub-fn docstring coverage on keypair, utils, wallet by @omipheo in https://github.com/latent-to/btwallet/pull/193
* fix(keyfile): correctly honor user confirmation in check_and_update_encryption by @boskodev790 in https://github.com/latent-to/btwallet/pull/188

## New Contributors
* @chideraao made their first contribution in https://github.com/latent-to/btwallet/pull/170
* @omipheo made their first contribution in https://github.com/latent-to/btwallet/pull/193
* @boskodev790 made their first contribution in https://github.com/latent-to/btwallet/pull/188

**Full Changelog**: https://github.com/latent-to/btwallet/compare/v4.0.1...v4.1.0

## 4.0.1 /2025-10-28

## What's Changed
* Support Python 3.14 by @thewhaleking in https://github.com/opentensor/btwallet/pull/166

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v4.0.0...v4.0.1

## 4.0.0 /2025-08-06

## What's Changed
* make when_created field optional for json file import by @camfairchild in https://github.com/opentensor/btwallet/pull/160
* Fix hotkeypub by @thewhaleking in https://github.com/opentensor/btwallet/pull/161

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.1.0...v4.0.0

## 3.1.0 /2025-07-07

## What's Changed
* Add `hotkeypub` to bittensor-wallet by @basfroman in https://github.com/opentensor/btwallet/pull/156

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.11...v3.1.0

## 3.0.11 /2025-06-26

## What's Changed
* update deps by @basfroman in https://github.com/opentensor/btwallet/pull/141
* Improvements on the top of https://github.com/opentensor/btwallet/pull/140 by @basfroman in https://github.com/opentensor/btwallet/pull/145
* chore(pyo3): use CARGO_PKG_VERSION to auto-sync Python binding version with crate by @LVivona in https://github.com/opentensor/btwallet/pull/140
* Add `arm64` wheels by @basfroman in https://github.com/opentensor/btwallet/pull/147
* Replace py-bip39-bindings deps with stored list of words by @basfroman in https://github.com/opentensor/btwallet/pull/151

## New Contributors
* @LVivona made their first contribution in https://github.com/opentensor/btwallet/pull/140

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.10...v3.0.11

## 3.0.11-rc.1 /2025-06-11

## What's Changed
* update deps by @basfroman in https://github.com/opentensor/btwallet/pull/141
* Improvements on the top of https://github.com/opentensor/btwallet/pull/140 by @basfroman in https://github.com/opentensor/btwallet/pull/145
* chore(pyo3): use CARGO_PKG_VERSION to auto-sync Python binding version with crate by @LVivona in https://github.com/opentensor/btwallet/pull/140
* Add `arm64` wheels by @basfroman in https://github.com/opentensor/btwallet/pull/147

## New Contributors
* @LVivona made their first contribution in https://github.com/opentensor/btwallet/pull/140

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.10...v3.0.11-rc.1

## 3.0.10 /2025-05-12

## What's Changed
* Fix regenerate key by seed (`seed.trim_start_matches("0x")) by @basfroman in https://github.com/opentensor/btwallet/pull/136

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.9...v3.0.10

## 3.0.9 /2025-04-28

## What's Changed
* Small fixes by @basfroman in https://github.com/opentensor/btwallet/pull/131
* Update deps by @basfroman in https://github.com/opentensor/btwallet/pull/132

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.8...v3.0.9

## 3.0.8 /2025-04-09

## What's Changed
* backmerge-main-staging-v3.0.7 by @basfroman in https://github.com/opentensor/btwallet/pull/126
* Remove unused requirements by @thewhaleking in https://github.com/opentensor/btwallet/pull/128

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.7...v3.0.8

## 3.0.7 /2025-04-03

## What's Changed
* Fixes, improvement, refactoring by @roman-opentensor in https://github.com/opentensor/btwallet/pull/124

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.6...v3.0.7

## 3.0.6 /2025-04-02

## What's Changed
* Improve release workflow by @roman-opentensor in #122

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.5...v3.0.6

## 3.0.5 /2025-04-02

## What's Changed
* BT Wallet v.3 (python improvement) by @roman-opentensor in #105
* Test workflow by @igorsyl in #104
* Add skip-check-rust label check in .github/workflows/check-rust.yml workflow by @roman-opentensor in #110
* Fix wallet.create_coldkey_from_uri broken by @roman-opentensor in #109
* Add workflows for run SDK and BTCLI tests if labels are applied by @roman-opentensor in #106
* Add back srt and repr for Wallet and Keypair by @roman-opentensor in #111
* Add trigger for check-rust workflow by @roman-opentensor in #113
* Update readme by @roman-opentensor in #112
* Update docker image name by @roman-opentensor in #114
* fix returns for rust and pyi by @roman-opentensor in #119

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.4...v3.0.5

## 3.0.4 /2025-02-19

## What's Changed
* Fix `pyo3_runtime.PanicException` when encrypted password has `NUL byte` by @roman-opentensor in https://github.com/opentensor/btwallet/pull/99
* Backmerge main to staging 303 by @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/102

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.3...v3.0.4

## 3.0.3 /2025-02-13

## What's Changed
* Fix KeyPair.regenerate_* methods using seed @roman-opentensor in https://github.com/opentensor/btwallet/pull/96

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.2...v3.0.3

## 3.0.2 /2025-02-06

## What's Changed
* Remove pyi file temporarily by @roman-opentensor in https://github.com/opentensor/btwallet/pull/92

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.1...v3.0.2

## 3.0.1 /2025-02-05

## What's Changed
* Redundant aliases by @thewhaleking in https://github.com/opentensor/btwallet/pull/84
* Add some python type hints for keypair by @camfairchild in https://github.com/opentensor/btwallet/pull/87
* Add Keyfile.keypair property back for btwallet v.3 the same as it was in btwallet v.2 by @roman-opentensor in https://github.com/opentensor/btwallet/pull/89
* Backmerge main to staging for 300 by @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/90

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v3.0.0...v3.0.1

## 3.0.0 /2024-12-18

## What's Changed
* Feat/wallet lib by @distributedstatemachine, @keithtensor, @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/73
* Remove `py-substrate-interface` from deps by @roman-opentensor in https://github.com/opentensor/btwallet/pull/83
* Add `subclass` into `pyclass` macro for classes by @roman-opentensor in https://github.com/opentensor/btwallet/pull/82

## New Contributors
* @distributedstatemachine made their first contribution in https://github.com/opentensor/btwallet/pull/73
* @keithtensor made their first contribution in https://github.com/opentensor/btwallet/pull/73

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.1.3...v3.0.0

## 2.1.3 /2024-11-27

## What's Changed
* Removes ansible completely by @roman-opentensor in https://github.com/opentensor/btwallet/pull/77

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.1.2...v2.1.3

## 2.1.2 /2024-11-27

## What's Changed
* Removes ansible from requirements. But the second requirements. by @thewhaleking in https://github.com/opentensor/btwallet/pull/74

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.1.1...v2.1.2

## 2.1.1 /2024-11-18

## What's Changed
* Fix ruff by @camfairchild in https://github.com/opentensor/btwallet/pull/62
* add rustup to CI by @camfairchild in https://github.com/opentensor/btwallet/pull/63
* Fix `~/` in wallet path by @roman-opentensor in https://github.com/opentensor/btwallet/pull/67
* Removes ansible as requirement by @thewhaleking in https://github.com/opentensor/btwallet/pull/68
* fix: Prevent infinite loop when password is not strong enough by @Ham3798 in https://github.com/opentensor/btwallet/pull/60
* Add base and mro updating logic before add Wallet Keypair class to the main_module by @roman-opentensor in https://github.com/opentensor/btwallet/pull/69

## New Contributors
* @Ham3798 made their first contribution in https://github.com/opentensor/btwallet/pull/60

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.1.0...v2.1.1

## 2.1.0 /2024-11-12

## What's Changed

* Fix hot/coldkey passwords in env by @roman-opentensor in https://github.com/opentensor/btwallet/pull/55
* Fix wallet paths outside userhome by @camfairchild in https://github.com/opentensor/btwallet/pull/59
* fix https://github.com/opentensor/btwallet/issues/51 by @camfairchild in https://github.com/opentensor/btwallet/pull/56
* password fixes and new PasswordError by @roman-opentensor 

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.0.2...v2.1.0

## 2.0.2 /2024-10-10

## What's Changed

* Add the ability to use environment variables to store hot/coldkey passwords by @roman-opentensor in https://github.com/opentensor/btwallet/pull/46
* Fix wallet paths outside userhome by @camfairchild in https://github.com/opentensor/btwallet/pull/59
* fix https://github.com/opentensor/btwallet/issues/51 by @camfairchild in https://github.com/opentensor/btwallet/pull/56
* password fixes by @roman-opentensor 
* fix/roman/fix-config-parsing by @roman-opentensor in https://github.com/opentensor/btwallet/pull/47

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.0.1...v2.0.2

## 2.0.1 /2024-10-04

## What's Changed
* add keypair getter to Keyfile by @roman-opentensor in https://github.com/opentensor/btwallet/pull/41
* fix/roman/avoid-double-asking-password-in-unlocking by @roman-opentensor in https://github.com/opentensor/btwallet/pull/43

**Full Changelog**: https://github.com/opentensor/btwallet/compare/v2.0.0...v2.0.1

## 2.0.0 /2024-10-03

## What's Changed

# Revamped Bittensor Wallet written in Rust from the ground up

* Updates Changelog by @ibraheem-opentensor in 5966932
* Merge conflicts. by @opendansor in a5d0ebd
* Bumps to 2.0.0 by @ibraheem-opentensor in fbc835e
* Bumps to a5 by @ibraheem-opentensor in ff7ab41
* Feat/ci/add release (#38) by @Cameron Fairchild in ffc995b
* remove utils by @Cameron Fairchild in a4521a4
* Merge pull request #31 from opentensor/rajk/update-README by @Roman in 7904b81
* update tests by @Roman in 1ba42fc
* Add re-trying to type the password after wallet creation by @Roman in 60ec77a
* move `keypair::Keypair.private_key` outside the python scope by @Roman in 241fcd0
* use pypi trusted release by @Cameron Fairchild in e5d4c49
* chore: ruff by @Cameron Fairchild in 0c051db
* Cam/no excepts (#32) by @Cameron Fairchild in 6685852
* wallet.hotkey.ss58_address doesn't ask typing pass after waller.unlock_hotkey() by @Roman in 591889d
* wallet.coldkey.ss58_address doesn't ask typing pass after waller.unlock_coldkey() by @Roman in fde4794
* Fix typos in status messages by @opendansor in 6953184
* delete double import by @Roman in a02ec3a
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in 1979480
* fix panic error to KeyFileError by @Roman in 8388ddb
* remove import by @Cameron Fairchild in f186944
* wrap with err by @Cameron Fairchild in 246988b
* Refactor error handling in keyfile.rs by @opendansor in b294357
* update config::Config -> add getters by @Roman in f03db92
* Add wallet::Wallet.add_args by @Roman in 192c447
* try eval bound with import first by @Cameron Fairchild in 3f122b1
* Adds extra line after print by @ibraheem-opentensor in 2cbf0cb
* chore: clippy by @Cameron Fairchild in 0aa5877
* add prompt and prompt password by @Cameron Fairchild in 19dfabf
* Updated readme docs by @Watchmaker in 7bf89dd
* Add getters for name and path in Keyfile by @opendansor in 8c31b65
* use pythons stdout (#30) by @Cameron Fairchild in 9566fc2
* Add getter methods for wallet name, path, and hotkey by @opendansor in e8eb8ff
* add tests to readme by @Roman in 984a43f
* add ScaleCodec to keypair::Keypair.sign and keypair::Keypair.verify by @Roman in de21752
* fix create_from_seed (add union str, bytes) processing by @Roman in 29fc083
* Merge remote-tracking branch 'origin/rust-fix-test' into rust-fix-test by @Roman in b8b23e0
* unused imports by @Roman in 1b5c8c3
* add version by @Cameron Fairchild in 4863a39
* add back extension-module feature by @Cameron Fairchild in 25ae0cb
* move assert into match arm by @Cameron Fairchild in b775256
* Refactor keypair decoding and wallet initialization by @opendansor in 228886b
* use new instead of init by @Cameron Fairchild in 9cee953
* add *args, **kwargs by @Roman in 2659496
* update for wallets properties by @Roman in f822741
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in f3fd9c4
* use direct import for error types in utils.rs by @Roman in e8d1124
* use direct import for error types in wallet.rs by @Roman in 19baa56
* use direct import for error types in keypair.rs by @Roman in ded234c
* update .gitignore by @Roman in 562bf4a
* use direct import for errors types in keyfile.rs by @Roman in 665a2b2
* Update version to 2.0.0 by @opendansor in 8ff86e5
* add `rpassword::prompt_password` instead of input for asking password. by @Roman in dd3afcc
* can't mock functions that are not implemented yet (rust doesn't accept this way). This limits testing from Python. temporarily commenting on mocking tests. by @Roman in 2726151
* update types of errors in keypair by @Roman in 881790a
* update types of errors in keypair by @Roman in e06cf62
* update errors by @Roman in 80bb4f3
* update ConfigurationError usage for Keypair::new by @Roman in 4f0280a
* add bittensor_wallet.keypair submodule by @Roman in ed4d619
* add error into the module by @Roman in dfe99b0
* add pyo3 signature to  keypair::Keypair methods (functions) by @Roman in ff4b65e
* improve keyfile::Keyfile.new logic by @Roman in c2d7692
* add errors::ConfigurationError by @Roman in 490f980
* fix classic import logic by @Roman in 199c748
* add export for wallet::display_mnemonic_msg by @Roman in 62b108b
* improve keyfile::Keyfile.__str__() by @Roman in c26397a
* add #[pyclass(subclass)] ability for main classes, add mock subpackage by @Roman in 5590e00
* update README (import logic) by @Roman in 31eb915
* Fix keypair::Keypair.create_from_encrypted_json by @Roman in 1562c5d
* lib.rs -> add classes on the package top level by @Roman in 1df5a6f
* README -> add test `create_from_encrypted_json` by @Roman in 19bcd43
* README, refactoring by @Roman in 25e9e14
* README, refactoring by @Roman in 9cb9071
* update python package structure by @Roman in 3e54d2b
* add errors::KeyFileError, add its usage in the same way as in python wallet by @Roman in 58728b4
* create correct python package structure by @Roman in af44b18
* temporarily remove incorrect private key usage in `create_from_encrypted_json` by @Roman in a4c433e
* keypair::Keypair.create_from_encrypted_json by @Roman in 1a36312
* import cleanup by @Roman in f2137d5
* deps cleanup by @Roman in 82bf3ca
* cls annotations fix by @Roman in b3c6e24
* add keypair::Keypair.create_from_encrypted_json by @Roman in e590f1f
* fixes by @Roman in f964492
* cleanup by @Roman in a54324d
* add wallet::Wallet.regenerate_coldkeypub, coldkey_file, coldkeypub_file, set_coldkey, set_coldkeypub, get_coldkeypub, get_coldkey, get_hotkey, regenerate_coldkey by @Roman in 90d343c
* fix keypair::Keypair.mnemonic() by @Roman in bdd30ba
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in b3f00e6
* add wallet::Wallet.regenerate_hotkey, wallet::Wallet.set_hotkey, wallet::Wallet.hotkey_file, update constants wallet path by @Roman in 431b7f7
* Add comprehensive tests for keyfile.rs by @opendansor in 99109e8
* Refactor wallet initialization to use config defaults by @Roman in 5041c3c
* fix cc compiler problem by @Roman in c085bce
* add some empty functions into wallet::Wallet by @Roman in 4a3213a
* add empty structure to wallet create, create some of the functions by @Roman in 67a1791
* make keypair::Keypair.create_from_uri public by @Roman in 9e01b53
* add list of functions into wallet.rs by @Roman in cbef1c1
* fix keyfile.rs by @Roman in 64fa38f
* update config by @Roman in a5c699f
* add wallet::Wallet.create_if_non_existent by @Roman in 247573a
* activate GPG key by @Roman in 235a0de
* Refactor keyfile encryption error handling by @Roman in 51c2c11
* Refactor `decrypt` to handle errors with `PyResult` by @opendansor in db1561b
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @opendansor in faf282f
* Improve file encryption and decryption error handling by @opendansor in 1090dc1
* add keypair::Keypair.check_and_update_encryption by @Roman in b8ea5a3
* add keypair::Keypair.get_keypair by @Roman in 7b69e6b
* commented keypair getter by @Roman in b9d7b43
* add keyfile::Keyfile.is_encrypted by @Roman in 72c384d
* move nacl_decrypt and legacy_decrypt into decrypt_keyfile_data by @Roman in 72f79c8
* add keypair::Keypair.set_keypair, fix: keypair::encrypt_keyfile_data, add printing messages by @Roman in f96d2fd
* Refactor `set_keypair` to handle encryption and file writing by @opendansor in 026702c
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in 0509f4f
* add keypair::decrypt_keyfile_data by @Roman in 9217363
* Update error handling and getter methods in keyfile.rs by @opendansor in 141b941
* update docstring + add pyo3 signature by @Roman in 6a163df
* update docstring by @Roman in 80a4dcf
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in 827bee1
* add keyfile::encrypt_keyfile_data by @Roman in 86a43f7
* Add legacy keyfile encryption function by @opendansor in ebd82b2
* Pins py-bip39-bindings (#25) by @ibraheem-opentensor in 8491a77
* add keyfile::keyfile_data_encryption_method by @Roman in a6f84aa
* fix input logic and messages by @Roman in c7023bf
* Enable encryption detection functions by @opendansor in 8745397
* Adds changelog (#24) by @ibraheem-opentensor in 7ce313c
* update README.md -> tests by @Roman in 2e59bf4
* update README.md -> tests by @Roman in 120a456
* remove unused prefixes and pub sign by @Roman in 9fc24ac
* formatter by @Roman in e3c6eae
* add pyo3 - signature: green build by @Roman in bdd1d02
* Refactor keyfile functions to use PyBytes instead of Vec<u8> by @opendansor in fc97001
* Deployment script + updates (#23) by @ibraheem-opentensor in aebb643
* update deps in Cargo.toml by @Roman in b9d25e1
* add TODOs by @Roman in 384345c
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in 0550d80
* add Keyfile::is_encrypted by @Roman in 766fad9
* Enable keyfile serialization and password validation by @opendansor in 8e8696a
* add Keyfile::_read_keyfile_data_from_file, Keyfile::is_writable by @Roman in 0544c31
* add Keyfile::is_readable by @Roman in 8a6fbd2
* add Keyfile::exists_on_device update by @Roman in 98f45cd
* add Keyfile::_write_keyfile_data_to_file by @Roman in 5b738f3
* add Keyfile::_may_overwrite by @Roman in 2689b78
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in 57bc8be
* add Keyfile::make_dirs by @Roman in 86964e4
* Add keyfile-related functions to library by @opendansor in 127f3c6
* add Keyfile::exists_on_device by @Roman in 53ae243
* add Keyfile.rs structure by @Roman in cf8af98
* add Keyfile.rs structure by @Roman in 456d2c2
* cargo files update by @Roman in 7eff490
* frm by @Roman in bb92e45
* Add comments with keyfile.py usage across the wallet, btcli, sdk by @Roman in b6ecbae
* cargo clippy GREEN by @Roman in 777039a
* cargo fmt by @Roman in 11d5803
* GREEEEN BUILD by @Roman in bb89aa4
* update Cargo.toml by @Roman in 5d8e837
* add funcs to the pymodule in the lib.rs by @Roman in fc8d30f
* update README.md by @Roman in 9e4f300
* utils done by @Roman in dbe7f66
* update README.md by @Roman in 2a0d92d
* keep support crypto_type 1 only (sr25519) by @Roman in 0fa29bc
* add utils::get_ss58_format + test by @Roman in 520b1d9
* fix utils::is_valid_ss58_address function + test by @Roman in d4c91ff
* fix utils::is_valid_ss58_address function by @Roman in fe5bd41
* Merge remote-tracking branch 'origin/main-rust' into main-rust by @Roman in cb458e6
* add verify function + manual test case by @Roman in 67b03f1
* BROKEN: Add SS58 address validation utility by @opendansor in 7075052
* add sign function + manual test case by @Roman in a113cb6
* add the checker `If public_key is missing (ss58_address wasn't created), return an error` by @Roman in 366da8e
* add creation with ss58_address by @Roman in b35e4c5
* remove comments from public_key getter by @Roman in 644bb04
* update manual test script by @Roman in 46dde7d
* add creating from public_key by @Roman in 78e1dd8
* fix ci by @Roman in ab8b8c3
* update README with a test for Keypair by @Roman in 7101925
* add print for test by @Roman in 26821a2
* Minimum functionality done by @Roman in 2f18751
* add __repr__ and __str__ by @Roman in bed0f13
* all fields in Keypair work by @Roman in a70ce44
* add getters ss58_address and seed_hex by @Roman in 4829eae
* add pair by @Roman in 0bfac83
* impl Default for Keypair by @Roman in 5e0c146
* empty struct Keypair and getters by @Roman in 6ee130a
* convert private_key to bytes by @Roman in 0b93c3c
* convert public_key to bytes by @Roman in 7ae4ad4
* update structure by @Roman in e5174b1
* delete pyproject.toml by @Roman in 628291f
* fix Keypair `#pyclass` macros by @Roman in 6f9005c
* update structure by @Roman in 7d8db72
* working by @Roman in 14c8275
* update python package folder name by @Roman in 07ce2d6
* update structure by @Roman in 171fdd1
* wip restructure by @Gus in 258e702
* Test signed commit by @Gus in 91f2c2c
* Merge pull request #21 from opentensor/fix/roman/cryptography-version-to-43.0.1 by @Roman in be61bd9
* bump up cryptography version until 43.0.1 by @Roman in 5e3726d
* Apply changes from #2237 (#18) by @Benjamin Himes in 83983f9
* Merge pull request #20 from opentensor/feat/roman/bump-up-version by @Roman in 89ba61f
* bump up the version by @Roman in 527a7aa
* Merge pull request #19 from opentensor/feat/thewhaleking/raise-exception-on-unlock-failure by @Benjamin Himes in 8e724c1
* Raises a KeyFileError when one is encountered when unlocking. by @Benjamin Himes in fdef4ba
* encrypt using secret box access by @Gus in 2faf3a4
* wallet integration with python wip by @Gus in 218ccad
* Merge pull request #17 from opentensor/fix/update-mnemonic-command by @ibraheem-opentensor in 5fa01d9
* Updates mnemonic command output by @ibraheem-opentensor in 7789a9a
* clean up by @Gus in a3b58d5
* adds coldkey gen by @Gus in 88eb46b
* password working - needs cleanup by @Gus in 6ce4476
* docs and signing working by @Gus in 742fbb4
* testing sign by @Gus in 4b668e4
* clean up and todos by @Gus in 4987d39
* fmt by @Gus in 722c9e9
* feat: wallet & hotkey file write by @Gus in 411d7be
* feat: mnemonic & hotkey pair by @Gus in 43a4704
* adds tests by @Gus in e8a2ac6
* adds documentation by @Gus in f903f03

## New Contributors
* @camfairchild made their first contribution in https://github.com/opentensor/btwallet/pull/30
* @rajkaramchedu made their first contribution in https://github.com/opentensor/btwallet/pull/31
* @opendansor made their first contribution in 707505209df4089581d4d2ca17b26a6e162c7f05

**Full Changelog**: https://github.com/opentensor/btwallet/commits/v2.0.0

## 1.0.0 /2024-09-25

## What's Changed

Bittensor wallet separated as a standalone package:

* Release 1.0.0 - Changelog by @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/24
* Deployment script + updates by @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/23
* bump up cryptography version until 43.0.1 by @roman-opentensor in https://github.com/opentensor/btwallet/pull/21
* bump up the version by @roman-opentensor in https://github.com/opentensor/btwallet/pull/20
* Raises a KeyFileError when one is encountered when unlocking. by @thewhaleking in https://github.com/opentensor/btwallet/pull/19
* Password unlocking changes  by @thewhaleking in https://github.com/opentensor/btwallet/pull/18
* Updates mnemonic command output by @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/17
* Add `unlock_hotkeypub` method to the wallet. Add unit tests. by @roman-opentensor in https://github.com/opentensor/btwallet/pull/12
* Add `unlock_hotkey` method to the wallet. Add unit tests. by @roman-opentensor in https://github.com/opentensor/btwallet/pull/11
* Add unlock method for wallet coldkey by @thewhaleking in https://github.com/opentensor/btwallet/pull/10
* License fix by @roman-opentensor in https://github.com/opentensor/btwallet/pull/9
* bug/roman/requirements by @roman-opentensor in https://github.com/opentensor/btwallet/pull/8
* Initial commit: circleci testing config by @ibraheem-opentensor in https://github.com/opentensor/btwallet/pull/6
* Fix flaky tests by @roman-opentensor in https://github.com/opentensor/btwallet/pull/5
* Bump substrate-interface to 1.7.9 by @thewhaleking in https://github.com/opentensor/btwallet/pull/3
* Massive wallet change after copy-paste by @roman-opentensor in https://github.com/opentensor/btwallet/pull/1

## New Contributors
* @roman-opentensor made their first contribution in https://github.com/opentensor/btwallet/pull/1
* @thewhaleking made their first contribution in https://github.com/opentensor/btwallet/pull/3
* @ibraheem-opentensor made their first contribution in https://github.com/opentensor/btwallet/pull/6
