import time

import pytest

from bittensor_wallet import Wallet
from bittensor_wallet.errors import KeyFileError


@pytest.fixture
def mock_wallet():
    wallet = Wallet(
        name=f"mock-{str(time.time())}",
        hotkey=f"mock-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    wallet.create_new_coldkey(use_password=False, overwrite=True, suppress=True)
    wallet.create_new_hotkey(use_password=False, overwrite=True, suppress=True)

    return wallet


def test_unlock_hotkey(mock_wallet):
    """Verify that `unlock_hotkey` works correctly."""

    # Call
    result = mock_wallet.unlock_hotkey()
    # Assertions
    assert result.ss58_address == mock_wallet.get_hotkey().ss58_address
    assert result.public_key == mock_wallet.get_hotkey().public_key
    assert result.ss58_format == mock_wallet.get_hotkey().ss58_format
    assert result.crypto_type == mock_wallet.get_hotkey().crypto_type


def test_unlock_coldkey(mock_wallet):
    """Verify that `unlock_coldkey` works correctly."""

    # Call
    result = mock_wallet.unlock_coldkey()
    # Assertions
    assert result.ss58_address == mock_wallet.get_coldkey().ss58_address
    assert result.public_key == mock_wallet.get_coldkey().public_key
    assert result.ss58_format == mock_wallet.get_coldkey().ss58_format
    assert result.crypto_type == mock_wallet.get_coldkey().crypto_type


def test_unlock_coldkeypub(mock_wallet):
    """Verify that `unlock_coldkeypub` works correctly."""
    # Call
    coldkeypub = mock_wallet.unlock_coldkeypub()

    # Assertions
    assert coldkeypub.ss58_address == mock_wallet.get_coldkeypub().ss58_address
    assert coldkeypub.public_key == mock_wallet.get_coldkeypub().public_key
    assert coldkeypub.ss58_format == mock_wallet.get_coldkeypub().ss58_format
    assert coldkeypub.crypto_type == mock_wallet.get_coldkeypub().crypto_type


def test_unlock_hotkeypub(mock_wallet):
    # Call
    hotkeypub = mock_wallet.unlock_hotkeypub()

    # Assertations
    assert hotkeypub.ss58_address == mock_wallet.get_hotkeypub().ss58_address
    assert hotkeypub.public_key == mock_wallet.get_hotkeypub().public_key
    assert hotkeypub.ss58_format == mock_wallet.get_hotkeypub().ss58_format
    assert hotkeypub.crypto_type == mock_wallet.get_hotkeypub().crypto_type


def test_wallet_string_representation_with_default_arguments():
    """Tests wallet string representation with default arguments."""
    # Call
    w = Wallet()

    # Asserts
    assert (
        str(w)
        == "Wallet (Name: 'default', Hotkey: 'default', Path: '~/.bittensor/wallets/')"
    )
    assert w.name == "default"
    assert w.hotkey_str == "default"
    assert w.path == "~/.bittensor/wallets/"


def test_wallet_string_representation_with_custom_arguments():
    """Tests wallet string representation with custom arguments."""
    # Preps
    wallet_name = "test_wallet"
    wallet_hotkey = "test_hotkey"
    wallet_path = "/tmp/tests_wallets/"

    # Call
    w = Wallet(name="test_wallet", hotkey="test_hotkey", path="/tmp/tests_wallets/")

    # Asserts
    assert (
        str(w)
        == f"Wallet (Name: '{wallet_name}', Hotkey: '{wallet_hotkey}', Path: '{wallet_path}')"
    )
    assert w.name == wallet_name
    assert w.hotkey_str == wallet_hotkey
    assert w.path == wallet_path


def test_create_coldkey_from_uri():
    """Tests create_coldkey_from_uri method."""
    # Preps
    wallet_name = "test_wallet"
    wallet_hotkey = "test_hotkey"
    wallet_path = "/tmp/tests_wallets/"

    # Call
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)
    w.create_coldkey_from_uri("//test", use_password=False, overwrite=True)

    # Asserts
    assert w.coldkey.ss58_address is not None
    assert w.coldkeypub.ss58_address is not None


def test_hotkey_coldkey_from_uri():
    """Tests create_coldkey_from_uri method."""
    # Preps
    wallet_name = "test_wallet"
    wallet_hotkey = "test_hotkey"
    wallet_path = "/tmp/tests_wallets/"

    # Call
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)
    w.create_hotkey_from_uri("//test", use_password=False, overwrite=True)

    # Asserts
    assert w.coldkey.ss58_address is not None
    assert w.coldkeypub.ss58_address is not None


def test_regenerate_hotkeypub(tmp_path):
    """Tests any type of regenerating."""

    # Preps
    wallet_name = "test_wallet_new"
    wallet_hotkey = "test_hotkey_new"
    wallet_path = (tmp_path / "test_wallets_new").resolve().as_posix()

    # Call
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)

    with pytest.raises(KeyFileError):
        _ = w.coldkey

    with pytest.raises(KeyFileError):
        _ = w.hotkey

    with pytest.raises(KeyFileError):
        _ = w.coldkeypub

    with pytest.raises(KeyFileError):
        _ = w.hotkeypub

    w.create(coldkey_use_password=False)

    ss58_coldkey = w.coldkey.ss58_address
    ss58_coldkeypub = w.coldkeypub.ss58_address
    ss58_hotkey = w.hotkey.ss58_address
    ss58_hotkeypub = w.hotkeypub.ss58_address

    w.regenerate_hotkeypub(ss58_address=ss58_hotkey, overwrite=True)

    new_ss58_hotkeypub = w.hotkeypub.ss58_address

    # Assert
    assert ss58_coldkey == ss58_coldkeypub
    assert ss58_hotkey == ss58_hotkeypub
    assert ss58_hotkeypub == new_ss58_hotkeypub
