import json
import os
import shutil
import time
from unittest import mock

import pytest

from bittensor_wallet import Wallet, CRYPTO_ED25519, CRYPTO_SR25519
from bittensor_wallet.errors import ConfigurationError, KeyFileError
from bittensor_wallet.keyfile import Keyfile
from bittensor_wallet.keyfile import get_coldkey_password_from_environment
from bittensor_wallet.keypair import Keypair
from utils.bip39 import bip39_validate


def test_generate_mnemonic():
    """
    Test the generation of a mnemonic and its validation.
    """
    mnemonic = Keypair.generate_mnemonic()
    assert bip39_validate(mnemonic) is True


def test_invalid_mnemonic():
    """
    Test the validation of an invalid mnemonic.
    """
    mnemonic = "This is an invalid mnemonic"
    assert bip39_validate(mnemonic) is False


def test_create_sr25519_keypair():
    """
    Test the creation of a sr25519 keypair from a mnemonic and verify the SS58 address.
    """
    mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
    keypair = Keypair.create_from_mnemonic(mnemonic)
    assert keypair.ss58_address == "5HDvhV6WDCjCKyrXqGQSDYqQAzkzabNhctmiDYEqgBC66BsX"


def test_only_provide_ss58_address():
    """
    Test the creation of a keypair with only the SS58 address provided.
    """
    keypair = Keypair(ss58_address="16ADqpMa4yzfmWs3nuTSMhfZ2ckeGtvqhPWCNqECEGDcGgU2")

    assert (
        f"0x{keypair.public_key.hex()}"
        == "0xe4359ad3e2716c539a1d663ebd0a51bdc5c98a12e663bb4c4402db47828c9446"
    )


def test_only_provide_public_key():
    """
    Test the creation of a keypair with only the public key provided.
    """
    keypair = Keypair(
        public_key="0xe4359ad3e2716c539a1d663ebd0a51bdc5c98a12e663bb4c4402db47828c9446",
        ss58_format=42,
    )

    assert keypair.ss58_address == "5HDvhV6WDCjCKyrXqGQSDYqQAzkzabNhctmiDYEqgBC66BsX"


def test_provide_no_ss58_address_and_public_key():
    """
    Test the creation of a keypair without providing SS58 address and public key.
    """
    with pytest.raises(ValueError):
        Keypair()


def test_incorrect_private_key_length_sr25519():
    """
    Test the creation of a keypair with an incorrect private key length for sr25519.
    """
    with pytest.raises(ValueError):
        Keypair(
            private_key="0x23",
            ss58_address="16ADqpMa4yzfmWs3nuTSMhfZ2ckeGtvqhPWCNqECEGDcGgU2",
        )


def test_incorrect_public_key():
    """
    Test the creation of a keypair with an incorrect public key.
    """
    with pytest.raises(ValueError):
        Keypair(public_key="0x23")


def test_sign_and_verify():
    """
    Test the signing and verification of a message using a keypair.
    """
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    signature = keypair.sign("Test1231223123123")
    assert keypair.verify("Test1231223123123", signature) is True


def test_sign_and_verify_hex_data():
    """
    Test the signing and verification of hex data using a keypair.
    """
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    signature = keypair.sign("0x1234")
    assert keypair.verify("0x1234", signature) is True


def test_sign_missing_private_key():
    """
    Test signing a message with a keypair that is missing the private key.
    """
    keypair = Keypair(ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
    with pytest.raises(ConfigurationError):
        keypair.sign("0x1234")


def test_sign_and_verify_incorrect_signature():
    """
    Test verifying an incorrect signature for a signed message.
    """
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    signature = "0x4c291bfb0bb9c1274e86d4b666d13b2ac99a0bacc04a4846fb8ea50bda114677f83c1f164af58fc184451e5140cc8160c4de626163b11451d3bbb208a1889f8a"
    assert keypair.verify("Test1231223123123", signature) is False


def test_sign_and_verify_invalid_signature():
    """
    Test verifying an invalid signature format for a signed message.
    """
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    signature = "Test"
    with pytest.raises(ValueError):
        keypair.verify("Test1231223123123", signature)


def test_sign_and_verify_invalid_message():
    """
    Test verifying a signature against an incorrect message.
    """
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    signature = keypair.sign("Test1231223123123")
    assert keypair.verify("OtherMessage", signature) is False


def test_unsupport_crypto_type():
    """
    Test creating a keypair with an unsupported crypto type.
    """
    with pytest.raises(TypeError):
        Keypair.create_from_seed(
            seed_hex="0xda3cf5b1e9144931?a0f0db65664aab662673b099415a7f8121b7245fb0be4143",
            crypto_type=2,
        )


def test_create_keypair_from_private_key():
    """
    Test creating a keypair from a private key and verify the public key.
    """
    keypair = Keypair.create_from_private_key(
        private_key="0x1f1995bdf3a17b60626a26cfe6f564b337d46056b7a1281b64c649d592ccda0a9cffd34d9fb01cae1fba61aeed184c817442a2186d5172416729a4b54dd4b84e",
    )
    assert (
        f"0x{keypair.public_key.hex()}"
        == "0xe4359ad3e2716c539a1d663ebd0a51bdc5c98a12e663bb4c4402db47828c9446"
    )


def test_hdkd_hard_path():
    """
    Test hierarchical deterministic key derivation with a hard derivation path.
    """
    mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
    derivation_address = "5FEiH8iuDUw271xbqWTWuB6WrDjv5dnCeDX1CyHubAniXDNN"
    derivation_path = "//Alice"
    derived_keypair = Keypair.create_from_uri(mnemonic + derivation_path)
    assert derivation_address == derived_keypair.ss58_address


def test_hdkd_soft_path():
    """
    Test hierarchical deterministic key derivation with a soft derivation path.
    """
    derivation_address = "5GNXbA46ma5dg19GXdiKi5JH3mnkZ8Yea3bBtZAvj7t99P9i"
    mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
    derived_keypair = Keypair.create_from_uri(f"{mnemonic}/Alice")
    assert derivation_address == derived_keypair.ss58_address


def test_hdkd_default_to_dev_mnemonic():
    """
    Test hierarchical deterministic key derivation with a default development mnemonic.
    """
    derivation_address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    derivation_path = "//Alice"
    derived_keypair = Keypair.create_from_uri(derivation_path)
    assert derivation_address == derived_keypair.ss58_address


def test_hdkd_nested_hard_soft_path():
    """
    Test hierarchical deterministic key derivation with a nested hard and soft derivation path.
    """
    derivation_address = "5CJGwWiKXSE16WJaxBdPZhWqUYkotgenLUALv7ZvqQ4TXeqf"
    derivation_path = "//Bob/test"
    derived_keypair = Keypair.create_from_uri(derivation_path)
    assert derivation_address == derived_keypair.ss58_address


def test_hdkd_nested_soft_hard_path():
    """
    Test hierarchical deterministic key derivation with a nested soft and hard derivation path.
    """
    derivation_address = "5Cwc8tShrshDJUp1P1M21dKUTcYQpV9GcfSa4hUBNmMdV3Cx"
    derivation_path = "/Bob//test"
    derived_keypair = Keypair.create_from_uri(derivation_path)
    assert derivation_address == derived_keypair.ss58_address


def test_hdkd_path_gt_32_bytes():
    """
    Test hierarchical deterministic key derivation with a derivation path longer than 32 bytes.
    """
    derivation_address = "5GR5pfZeNs1uQiSWVxZaQiZou3wdZiX894eqgvfNfHbEh7W2"
    derivation_path = "//PathNameLongerThan32BytesWhichShouldBeHashed"
    derived_keypair = Keypair.create_from_uri(derivation_path)
    assert derivation_address == derived_keypair.ss58_address


def create_keyfile(root_path):
    """
    Creates a keyfile object with two keypairs: alice and bob.

    Args:
        root_path (str): The root path for the keyfile.

    Returns:
        bittensor.keyfile: The created keyfile object.
    """
    keyfile = Keyfile(path=os.path.join(root_path, "keyfile"))

    mnemonic = Keypair.generate_mnemonic(12)
    alice = Keypair.create_from_mnemonic(mnemonic)
    keyfile.set_keypair(
        alice, encrypt=True, overwrite=True, password="thisisafakepassword"
    )

    bob = Keypair.create_from_uri("/Bob")
    keyfile.set_keypair(
        bob, encrypt=True, overwrite=True, password="thisisafakepassword"
    )

    return keyfile


@pytest.fixture(scope="session")
def keyfile_setup_teardown():
    root_path = f"/tmp/pytest{time.time()}"
    os.makedirs(root_path, exist_ok=True)

    create_keyfile(root_path)

    yield root_path

    shutil.rmtree(root_path)


def test_create(keyfile_setup_teardown):
    """
    Test case for creating a keyfile and performing various operations on it.
    """
    root_path = keyfile_setup_teardown
    keyfile = Keyfile(path=os.path.join(root_path, "keyfile"))

    mnemonic = Keypair.generate_mnemonic(12)
    alice = Keypair.create_from_mnemonic(mnemonic)
    keyfile.set_keypair(
        alice, encrypt=True, overwrite=True, password="thisisafakepassword"
    )
    assert keyfile.is_readable()
    assert keyfile.is_writable()
    assert keyfile.is_encrypted()
    keyfile.decrypt(password="thisisafakepassword")
    assert not keyfile.is_encrypted()
    keyfile.encrypt(password="thisisafakepassword")
    assert keyfile.is_encrypted()
    str(keyfile)
    keyfile.decrypt(password="thisisafakepassword")
    assert not keyfile.is_encrypted()
    str(keyfile)

    assert (
        keyfile.get_keypair(password="thisisafakepassword").ss58_address
        == alice.ss58_address
    )
    assert (
        keyfile.get_keypair(password="thisisafakepassword").public_key
        == alice.public_key
    )

    bob = Keypair.create_from_uri("/Bob")
    keyfile.set_keypair(
        bob, encrypt=True, overwrite=True, password="thisisafakepassword"
    )
    assert (
        keyfile.get_keypair(password="thisisafakepassword").ss58_address
        == bob.ss58_address
    )
    assert (
        keyfile.get_keypair(password="thisisafakepassword").public_key == bob.public_key
    )

    repr(keyfile)


def test_overwriting(keyfile_setup_teardown):
    """
    Test case for overwriting a keypair in the keyfile.
    """
    root_path = keyfile_setup_teardown
    keyfile = Keyfile(path=os.path.join(root_path, "keyfile"))
    alice = Keypair.create_from_uri("/Alice")
    keyfile.set_keypair(
        alice, encrypt=True, overwrite=True, password="thisisafakepassword"
    )
    bob = Keypair.create_from_uri("/Bob")

    with pytest.raises(KeyFileError):
        with mock.patch("builtins.input", return_value="n"):
            keyfile.set_keypair(
                bob, encrypt=True, overwrite=False, password="thisisafakepassword"
            )


def test_serialized_keypair_to_keyfile_data(keyfile_setup_teardown):
    """
    Test case for serializing a keypair to keyfile data.

    This test case verifies that the `serialized_keypair_to_keyfile_data` function correctly
    serializes a keypair to keyfile data. It then deserializes the keyfile data and asserts
    that the deserialized keypair matches the original keypair.
    """
    from bittensor_wallet.keyfile import serialized_keypair_to_keyfile_data

    root_path = keyfile_setup_teardown
    keyfile = Keyfile(path=os.path.join(root_path, "keyfile"))

    mnemonic = Keypair.generate_mnemonic(12)
    keypair = Keypair.create_from_mnemonic(mnemonic)

    keyfile.set_keypair(
        keypair, encrypt=True, overwrite=True, password="thisisafakepassword"
    )
    keypair_data = serialized_keypair_to_keyfile_data(keypair)
    decoded_keypair_data = json.loads(keypair_data.decode())

    assert decoded_keypair_data["ss58Address"] == keypair.ss58_address
    assert decoded_keypair_data["publicKey"] == f"0x{keypair.public_key.hex()}"
    assert decoded_keypair_data["accountId"] == f"0x{keypair.public_key.hex()}"


def test_deserialize_keypair_from_keyfile_data(keyfile_setup_teardown):
    """
    Test case for deserializing a keypair from keyfile data.

    This test case verifies that the `deserialize_keypair_from_keyfile_data` function correctly
    deserializes keyfile data to a keypair. It first serializes a keypair to keyfile data and
    then deserializes the keyfile data to a keypair. It then asserts that the deserialized keypair
    matches the original keypair.
    """
    from bittensor_wallet.keyfile import serialized_keypair_to_keyfile_data
    from bittensor_wallet.keyfile import deserialize_keypair_from_keyfile_data

    root_path = keyfile_setup_teardown
    keyfile = Keyfile(path=os.path.join(root_path, "keyfile"))

    mnemonic = Keypair.generate_mnemonic(12)
    keypair = Keypair.create_from_mnemonic(mnemonic)

    keyfile.set_keypair(
        keypair, encrypt=True, overwrite=True, password="thisisafakepassword"
    )
    keypair_data = serialized_keypair_to_keyfile_data(keypair)
    deserialized_keypair = deserialize_keypair_from_keyfile_data(keypair_data)

    assert deserialized_keypair.ss58_address == keypair.ss58_address
    assert deserialized_keypair.public_key == keypair.public_key


@pytest.mark.parametrize(
    "encrypted,decrypted",
    [
        ("c2ZsZGJpaG1q", "123456789"),
        ("ID0rJDIxLDoh", "bittensor"),
        ("NjEsJD4xOA==", "testing"),
    ],
)
def test_get_coldkey_password_from_environment(tmp_path, encrypted, decrypted):
    # Preps
    assert tmp_path.exists()
    assert tmp_path.is_dir()

    wallet_name = "test_wallet"

    wallet = Wallet(name=wallet_name, path=str(tmp_path))
    wallet.create(
        coldkey_use_password=True,
        hotkey_use_password=False,
        save_coldkey_to_env=True,
        save_hotkey_to_env=False,
        coldkey_password=decrypted,
        overwrite=True,
        suppress=True,
    )

    # Call
    wallet.coldkey_file.save_password_to_env(decrypted)

    # Calls + Assertions
    assert (
        get_coldkey_password_from_environment(wallet.coldkey_file.env_var_name())
        == decrypted
    )
    assert get_coldkey_password_from_environment("non_existent_env_variable") is None


# --- ED25519 Keypair tests ---


def test_create_ed25519_keypair():
    """Test creation of an ED25519 keypair from a mnemonic."""
    mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
    keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    assert keypair.crypto_type == CRYPTO_ED25519
    assert keypair.ss58_address is not None
    assert len(keypair.public_key) == 32


def test_ed25519_different_address_from_sr25519():
    """Test that ED25519 and SR25519 produce different addresses from the same mnemonic."""
    mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
    sr = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_SR25519)
    ed = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    assert sr.ss58_address != ed.ss58_address
    assert sr.public_key != ed.public_key


def test_ed25519_sign_and_verify():
    """Test ED25519 signing and verification."""
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    signature = keypair.sign("Test1231223123123")
    assert keypair.verify("Test1231223123123", signature) is True


def test_ed25519_sign_and_verify_invalid_message():
    """Test ED25519 verification fails with wrong message."""
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    signature = keypair.sign("Test1231223123123")
    assert keypair.verify("OtherMessage", signature) is False


def test_ed25519_from_seed():
    """Test creating an ED25519 keypair from a hex seed."""
    seed = "0x" + "ff" * 32
    keypair = Keypair.create_from_seed(seed, crypto_type=CRYPTO_ED25519)
    assert keypair.crypto_type == CRYPTO_ED25519
    assert keypair.ss58_address is not None
    assert len(keypair.public_key) == 32


def test_ed25519_from_uri():
    """Test creating an ED25519 keypair from a URI."""
    keypair = Keypair.create_from_uri("//Alice", crypto_type=CRYPTO_ED25519)
    assert keypair.crypto_type == CRYPTO_ED25519
    assert keypair.ss58_address is not None


def test_ed25519_default_is_sr25519():
    """Test that default crypto_type is SR25519."""
    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    assert keypair.crypto_type == CRYPTO_SR25519


def test_set_crypto_type_on_active_keypair_raises():
    """Test that setting crypto_type on an initialized keypair raises ValueError."""
    keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    with pytest.raises(ValueError):
        keypair.crypto_type = CRYPTO_ED25519


def test_set_crypto_type_on_pubonly_keypair():
    """Test that setting crypto_type on a pub-only keypair works."""
    keypair = Keypair(ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
    keypair.crypto_type = CRYPTO_ED25519
    assert keypair.crypto_type == CRYPTO_ED25519


# --- ED25519 Keyfile serialization tests ---


def test_ed25519_serialized_keypair_contains_crypto_type():
    """Test that serialized ED25519 keypair JSON contains cryptoType field."""
    from bittensor_wallet.keyfile import serialized_keypair_to_keyfile_data

    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    data = json.loads(serialized_keypair_to_keyfile_data(keypair).decode())
    assert data["cryptoType"] == CRYPTO_ED25519


def test_sr25519_serialized_keypair_contains_crypto_type():
    """Test that serialized SR25519 keypair JSON contains cryptoType field."""
    from bittensor_wallet.keyfile import serialized_keypair_to_keyfile_data

    mnemonic = Keypair.generate_mnemonic()
    keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_SR25519)
    data = json.loads(serialized_keypair_to_keyfile_data(keypair).decode())
    assert data["cryptoType"] == CRYPTO_SR25519


def test_ed25519_deserialize_roundtrip():
    """Test ED25519 keypair serialize/deserialize roundtrip preserves identity."""
    from bittensor_wallet.keyfile import serialized_keypair_to_keyfile_data
    from bittensor_wallet.keyfile import deserialize_keypair_from_keyfile_data

    mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
    original = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    data = serialized_keypair_to_keyfile_data(original)
    restored = deserialize_keypair_from_keyfile_data(data)

    assert restored.ss58_address == original.ss58_address
    assert restored.crypto_type == CRYPTO_ED25519
    assert restored.public_key == original.public_key


def test_legacy_keyfile_without_crypto_type_defaults_sr25519():
    """Test that legacy keyfile JSON without cryptoType defaults to SR25519."""
    from bittensor_wallet.keyfile import deserialize_keypair_from_keyfile_data

    legacy_json = json.dumps(
        {
            "secretPhrase": "old leopard transfer rib spatial phone calm indicate online fire caution review",
            "ss58Address": "5HDvhV6WDCjCKyrXqGQSDYqQAzkzabNhctmiDYEqgBC66BsX",
        }
    ).encode()
    kp = deserialize_keypair_from_keyfile_data(legacy_json)
    assert kp.crypto_type == CRYPTO_SR25519
    assert kp.ss58_address == "5HDvhV6WDCjCKyrXqGQSDYqQAzkzabNhctmiDYEqgBC66BsX"


# --- Crypto type constants tests ---


def test_crypto_constants_produce_correct_keypair_types():
    """Test that exported constants work as crypto_type and produce distinct key types."""
    mnemonic = Keypair.generate_mnemonic()
    ed = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_ED25519)
    sr = Keypair.create_from_mnemonic(mnemonic, crypto_type=CRYPTO_SR25519)

    assert ed.crypto_type == CRYPTO_ED25519
    assert sr.crypto_type == CRYPTO_SR25519
    assert ed.ss58_address != sr.ss58_address
    assert ed.public_key != sr.public_key


def test_crypto_constants_importable_from_keypair_submodule():
    """Test that crypto type constants are importable from the keypair submodule."""
    from bittensor_wallet.keypair import (
        CRYPTO_ED25519 as KP_ED,
        CRYPTO_SR25519 as KP_SR,
    )

    kp = Keypair.create_from_uri("//Bob", crypto_type=KP_ED)
    assert kp.crypto_type == KP_ED
    assert KP_ED == CRYPTO_ED25519
    assert KP_SR == CRYPTO_SR25519
