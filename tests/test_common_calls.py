import argparse
import json
import os

import bittensor as bt
from scalecodec.base import ScaleBytes
from substrateinterface.keypair import Keypair as SKeypair

from bittensor_wallet import (
    Keypair as WKeypair,
    Wallet as WWallet,
    Keyfile as WKeyfile,
    __version__,
)
from bittensor_wallet.keyfile import (
    serialized_keypair_to_keyfile_data,
    deserialize_keypair_from_keyfile_data,
    decrypt_keyfile_data,
    encrypt_keyfile_data,
    keyfile_data_is_encrypted,
)
from bittensor_wallet.utils import (
    get_ss58_format,
    is_valid_ss58_address,
    is_valid_ed25519_pubkey,
    is_valid_bittensor_address_or_public_key,
)


def test_common_calls():
    """Tests for Keypair."""
    kps = SKeypair.create_from_mnemonic(
        "stool feel open east woman high can denial forget screen trust salt"
    )
    kpw = WKeypair.create_from_mnemonic(
        "stool feel open east woman high can denial forget screen trust salt"
    )
    assert kps.ss58_address == kpw.ss58_address
    assert kps.public_key == kpw.public_key
    kps = SKeypair.create_from_seed(
        "0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf"
    )
    kpw = WKeypair.create_from_seed(
        "0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf"
    )
    assert kps.ss58_address == kpw.ss58_address
    assert kps.public_key == kpw.public_key

    # substrateinterface has a bug -> can't create the KP without `ss58_format` passed
    kps = SKeypair.create_from_private_key(
        "0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f",
        ss58_format=42,
    )
    kpw = WKeypair.create_from_private_key(
        "0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f"
    )
    assert kps.ss58_address == kpw.ss58_address
    assert kps.public_key == kpw.public_key
    kps = SKeypair.create_from_uri("//Alice")
    kpw = WKeypair.create_from_uri("//Alice")
    assert kps.ss58_address == kpw.ss58_address
    assert kps.public_key == kpw.public_key

    # substrateinterface has a bug -> can't create the KP without `ss58_format` passed
    from_private_key_new_kps = SKeypair(public_key=kps.public_key.hex(), ss58_format=42)
    from_private_key_new_kpw = WKeypair(public_key=kps.public_key.hex())
    assert (
        from_private_key_new_kps.ss58_address == from_private_key_new_kpw.ss58_address
    )
    assert from_private_key_new_kps.public_key == from_private_key_new_kpw.public_key
    from_address_kps = SKeypair(
        ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    )
    from_address_kpw = WKeypair(
        ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    )
    assert from_address_kps.ss58_address == from_address_kpw.ss58_address
    assert from_address_kps.public_key == from_address_kpw.public_key

    # check signature
    assert kps.verify("asd", kpw.sign("asd")) is True

    # check verify
    assert kpw.verify("asd", kps.sign("asd")) is True

    # check create_from_encrypted_json
    data = '{"encoded":"Z1yzxASuj21ej3CANbZKc3ibDaOpQPMahTT0qkniyZgAgAAAAQAAAAgAAACSDgflXWKXrX36EmX9XcA6cRpkN+oZX30/9FhtNP17krIG/yHLKmDnL1km1W/nZ+BpC7Qid6IuBvbZeboFyewFeXsKtcoY/bRY6nx/cLB5BND9WpXXS6Enf4RXAX7vPu/BY+o2z7VwPaXyFARfyPTiqJKqLDJWm3W5ZlvK0ks8FBv66mWEBYc+lLx8jvuzDNkdD3pnV3G802OwwHTy","encoding":{"content":["pkcs8","sr25519"],"type":["scrypt","xsalsa20-poly1305"],"version":"3"},"address":"5CuByUQBWZci5AtXonuHHhcbRL3yxM5xDdJsTNaYN3vPDY6f","meta":{"genesisHash":null,"name":"test","whenCreated":1727395683981}}'
    passphrase = "Password123"

    skp = SKeypair.create_from_encrypted_json(data, passphrase)
    wkp = WKeypair.create_from_encrypted_json(data, passphrase)
    assert skp.ss58_format == wkp.ss58_format
    assert skp.public_key == wkp.public_key
    assert skp.public_key.hex() == wkp.public_key.hex()


def test_signature_and_verify_with_scaleBytes():
    """Check signature and verify with ScaleBytes."""
    kps = SKeypair.create_from_uri("//Alice")
    kpw = WKeypair.create_from_uri("//Alice")

    message = ScaleBytes(b"my message")

    # cross-check
    assert kps.verify(message, kpw.sign(message)) is True
    assert kpw.verify(message, kps.sign(message)) is True

    # itself check
    assert kpw.verify(message, kpw.sign(message)) is True
    assert kps.verify(message, kps.sign(message)) is True


def test_utils_functions():
    """Tests for utils' functions."""
    # check get_ss58_format
    assert get_ss58_format("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == 42

    # check is_valid_ss58_address
    assert (
        is_valid_ss58_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
        is True
    )
    assert is_valid_ss58_address("blabla") is False

    # check is_valid_ed25519_pubkey
    assert is_valid_ed25519_pubkey("a" * 64) is True
    assert (
        is_valid_ed25519_pubkey("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
        is False
    )
    assert (
        is_valid_ed25519_pubkey(
            "0x86eb46a3f42935d901acc3b8910ca301d969b76cfc2a80f0eac733a8eda7ed24"
        )
        is True
    )
    assert (
        is_valid_ed25519_pubkey(
            "86eb46a3f42935d901acc3b8910ca301d969b76cfc2a80f0eac733a8eda7ed24"
        )
        is True
    )
    assert is_valid_ed25519_pubkey("") is False

    # check is_valid_bittensor_address_or_public_key
    assert is_valid_bittensor_address_or_public_key("blabla") is False
    assert is_valid_bittensor_address_or_public_key("a" * 64) is False
    assert (
        is_valid_bittensor_address_or_public_key(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        is True
    )
    assert is_valid_bittensor_address_or_public_key(100) is False


def test_serialization_and_deserialization():
    """Test serialization and deserialization."""
    kp = WKeypair.create_from_mnemonic(
        "stool feel open east woman high can denial forget screen trust salt"
    )
    kf_data = serialized_keypair_to_keyfile_data(kp)
    assert isinstance(kf_data, bytes)
    kp_2 = deserialize_keypair_from_keyfile_data(kf_data)
    assert isinstance(kp_2, WKeypair)
    assert kp.ss58_address == kp_2.ss58_address
    assert kp.public_key == kp_2.public_key


def test_keyfile_encrypt_and_decrypt(tmp_path):
    """Test Keyfile encrypt and decrypt."""
    # Preps
    assert tmp_path.exists()
    assert tmp_path.is_dir()

    wallet_name = "test_wallet"
    password = "testing123!"

    wallet = WWallet(name=wallet_name, path=str(tmp_path))
    wallet.create(
        coldkey_use_password=True,
        hotkey_use_password=False,
        save_coldkey_to_env=True,
        save_hotkey_to_env=False,
        coldkey_password=password,
        overwrite=True,
        suppress=True,
    )
    # Calls + Assertions

    # KF is an already encrypted key
    kf = WKeyfile(wallet.coldkey_file.path, name="default")
    assert kf.data[:5] == b"$NACL"
    kf.decrypt(password)
    # Decrypt data...
    json_data = json.loads(kf.data)
    assert set(json_data.keys()) == {
        "accountId",
        "cryptoType",
        "privateKey",
        "secretSeed",
        "publicKey",
        "secretPhrase",
        "ss58Address",
    }
    kf.encrypt(password)
    # Encryption data...
    assert kf.data[:5] == b"$NACL"


def test_is_encrypted_decrypt_encrypt_and_check_and_update_encryption(tmp_path):
    """Test Keyfile is_encrypted, decrypt, encrypt and check_and_update_encryption."""
    # Preps
    assert tmp_path.exists()
    assert tmp_path.is_dir()

    wallet_name = "test_wallet"
    password = "testing123!"

    wallet = WWallet(name=wallet_name, path=str(tmp_path))
    wallet.create(
        coldkey_use_password=True,
        hotkey_use_password=False,
        save_coldkey_to_env=True,
        save_hotkey_to_env=False,
        coldkey_password=password,
        overwrite=True,
        suppress=True,
    )

    # Calls + Assertions
    kf = WKeyfile(wallet.hotkey_file.path, name="default")
    assert keyfile_data_is_encrypted(kf.data) is False
    encrypted_kf_data = encrypt_keyfile_data(kf.data, "testing")
    # Encryption data...
    assert keyfile_data_is_encrypted(encrypted_kf_data) is True
    decrypted_kf_data = decrypt_keyfile_data(encrypted_kf_data, "testing")
    # Decrypt data...
    assert decrypted_kf_data == kf.data


def test_keyfile_encryption_and_decryption_with_password(tmp_path):
    """Test Keyfile make_dirs, is_writable, is_readable, get_keypair and exists_on_device."""
    kf = WKeyfile(os.path.join(str(tmp_path), "new_keyfile"), name="default")
    kp = WKeypair.create_from_mnemonic(
        "stool feel open east woman high can denial forget screen trust salt"
    )

    assert kf.exists_on_device() is False
    assert kf.is_writable() is False
    assert kf.is_readable() is False

    kf.set_keypair(kp, False, False)
    kf.make_dirs()

    assert kf.exists_on_device() is True
    assert kf.is_writable() is True
    assert kf.is_readable() is True


def test_config_parsing():
    """Config parsing test."""
    parser = argparse.ArgumentParser(description="My parser")

    bt.Wallet.add_args(parser)
    bt.Subtensor.add_args(parser)
    bt.Axon.add_args(parser)
    bt.logging.add_args(parser)

    config = bt.Config(parser)

    config.wallet.name = "new_wallet_name"
    config.wallet.hotkey = "new_hotkey"
    config.wallet.path = "/some/not_default/path"

    wallet = bt.Wallet(config=config)

    assert wallet.name == config.wallet.name
    assert wallet.hotkey_str == config.wallet.hotkey
    assert wallet.path == config.wallet.path


def test__version__():
    """Test version is provided."""
    assert __version__
