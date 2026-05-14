# Excluded from CI unit tests — requires ansible_vault which is not a core dependency
import json
import time
from unittest.mock import patch

import pytest
from ansible_vault import Vault

from bittensor_wallet import Wallet, keyfile


def create_wallet(default_updated_password):
    # create an nacl wallet
    wallet = Wallet(
        name=f"mock-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    with patch.object(
        keyfile,
        "ask_password_to_encrypt",
        return_value=default_updated_password,
    ):
        wallet.create()
        assert "NaCl" in str(wallet.coldkey_file)

    return wallet


@pytest.fixture
def wallet_update_setup():
    # Setup the default passwords and wallets
    default_updated_password = "nacl_password"
    default_legacy_password = "ansible_password"
    empty_wallet = Wallet(
        name=f"mock-empty-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    legacy_wallet = create_legacy_wallet(
        default_legacy_password=default_legacy_password
    )
    wallet = create_wallet(default_updated_password)

    return {
        "default_updated_password": default_updated_password,
        "default_legacy_password": default_legacy_password,
        "empty_wallet": empty_wallet,
        "legacy_wallet": legacy_wallet,
        "wallet": wallet,
    }


def test_encrypt_and_decrypt():
    """Test message can be encrypted and decrypted successfully with ansible/nacl."""
    json_data = {
        "address": "This is the address.",
        "id": "This is the id.",
        "key": "This is the key.",
    }
    message = json.dumps(json_data).encode()

    # encrypt and decrypt with nacl
    encrypted_message = keyfile.encrypt_keyfile_data(message, "password")
    decrypted_message = keyfile.decrypt_keyfile_data(encrypted_message, "password")
    assert decrypted_message == message
    assert keyfile.keyfile_data_is_encrypted(encrypted_message)
    assert not keyfile.keyfile_data_is_encrypted(decrypted_message)
    assert not keyfile.keyfile_data_is_encrypted_ansible(decrypted_message)
    assert keyfile.keyfile_data_is_encrypted_nacl(encrypted_message)

    # encrypt and decrypt with legacy ansible
    encrypted_message = legacy_encrypt_keyfile_data(message, "password")
    decrypted_message = keyfile.decrypt_keyfile_data(encrypted_message, "password")
    assert decrypted_message == message
    assert keyfile.keyfile_data_is_encrypted(encrypted_message)
    assert not keyfile.keyfile_data_is_encrypted(decrypted_message)
    assert not keyfile.keyfile_data_is_encrypted_nacl(decrypted_message)
    assert keyfile.keyfile_data_is_encrypted_ansible(encrypted_message)


def legacy_encrypt_keyfile_data(keyfile_data: bytes, password: str = None) -> bytes:
    vault = Vault(password)
    return vault.vault.encrypt(keyfile_data)


def create_legacy_wallet(default_legacy_password=None, legacy_password=None):
    def _legacy_encrypt_keyfile_data(*args, **kwargs):
        args = {
            k: v
            for k, v in zip(
                legacy_encrypt_keyfile_data.__code__.co_varnames[: len(args)],
                args,
            )
        }
        kwargs = {**args, **kwargs, "password": legacy_password}
        return legacy_encrypt_keyfile_data(**kwargs)

    legacy_wallet = Wallet(
        name=f"mock-legacy-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    legacy_password = (
        default_legacy_password if legacy_password is None else legacy_password
    )

    # create a legacy ansible wallet
    with patch.object(
        keyfile,
        "encrypt_keyfile_data",
        new=_legacy_encrypt_keyfile_data,
        # new = TestWalletUpdate.legacy_encrypt_keyfile_data,
    ):
        legacy_wallet.create()
        assert "Ansible" in str(legacy_wallet.coldkey_file)

    return legacy_wallet
