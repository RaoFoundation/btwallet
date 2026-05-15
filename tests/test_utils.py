import pytest
from bittensor_wallet import utils


def test_get_ss58_format():
    """Checks that `get_ss58_format` function uses `ss58.get_ss58_format` call."""
    # Preps
    fake_ss58_addressss58_address = "5FvUhL6sQ5egLAvnyiY1n7gTuhmYg9sD3oJbvASWkpNULt3n"

    # Assertions
    assert utils.get_ss58_format(fake_ss58_addressss58_address) == 42


@pytest.mark.parametrize(
    "address, expected_result",
    [
        # Valid ss58 address for SS58_FORMAT
        ("5F3sa2TJAWMqDhXG6jhV4N8ko9rLbc4B52kmxXJoN5D3ue8w", False),
        # Valid ss58 address for default substrate format
        ("5HQV5mjTgcM9aEBi4xbnbiJdz8aez92tWyRc1U53rLYuYEMk", True),
        # Invalid ss58 address
        ("InvalidAddress", False),
    ],
)
def test_is_valid_ss58_address(address, expected_result):
    """Test `is_valid_ss58_address` function with different inputs."""

    # Mock ss58.is_valid_ss58_address
    assert utils.is_valid_ss58_address(address) == expected_result


@pytest.mark.parametrize(
    "public_key, is_valid",
    [
        # Valid 64-character string public key
        ("a" * 64, True),
        # Valid 66-character string public key (with 0x prefix)
        ("0x" + "a" * 64, True),
        # Valid 32-byte public key
        (b"a" * 32, True),
        # Invalid: 63-character string public key
        ("a" * 63, False),
    ],
)
def test_is_valid_ed25519_pubkey(public_key, is_valid):
    """Test is_valid_ed25519_pubkey function with different inputs."""
    assert utils.is_valid_ed25519_pubkey(public_key) == is_valid


@pytest.mark.parametrize(
    "address, excepted_result",
    [
        # Valid ss58 address `a` * 64
        ("5FvUhL6sQ5egLAvnyiY1n7gTuhmYg9sD3oJbvASWkpNULt3n", True),
        # Valid 64-character ed25519 public key
        ("0x" + "a" * 64, True),
        # Valid 32-byte ed25519 public key
        (b"a" * 32, False),
    ],
)
def test_is_valid_bittensor_address_or_public_key_integration(address, excepted_result):
    """Integration test for is_valid_bittensor_address_or_public_key function."""

    assert utils.is_valid_bittensor_address_or_public_key(address) is excepted_result


# --- ED25519 Utils tests ---


def test_ed25519_address_is_valid_ss58():
    """Test that an ED25519-derived SS58 address passes validation."""
    from bittensor_wallet.keypair import Keypair

    keypair = Keypair.create_from_uri("//Alice", crypto_type=0)
    assert utils.is_valid_ss58_address(keypair.ss58_address) is True


def test_ed25519_pubkey_is_valid_bittensor_address():
    """Test that an ED25519 public key passes bittensor address validation."""
    from bittensor_wallet.keypair import Keypair

    keypair = Keypair.create_from_uri("//Alice", crypto_type=0)
    assert utils.is_valid_bittensor_address_or_public_key(keypair.ss58_address) is True
