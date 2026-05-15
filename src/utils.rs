use sp_core::crypto::{AccountId32, Ss58Codec};
use std::str;

use crate::constants::CRYPTO_ED25519;
use crate::keypair::Keypair;

pub(crate) const SS58_FORMAT: u8 = 42;

/// Returns the SS58 format of the given address string.
///
/// ```text
///     Arguments:
///         ss58_address (str): The SS58 address to extract the format from.
///     Returns:
///         format (u16): The SS58 format number.
/// ```
pub fn get_ss58_format(ss58_address: &str) -> Result<u16, &'static str> {
    match <AccountId32 as Ss58Codec>::from_ss58check_with_version(ss58_address) {
        Ok((_, format)) => Ok(u16::from(format)),
        Err(_) => Err("Invalid SS58 address."),
    }
}

/// Checks if the given address is a valid ss58 address.
///
/// ```text
///     Arguments:
///         address (str): The address to check.
///     Returns:
///         ``True`` if the address is a valid ss58 address for Bittensor, ``False`` otherwise.
/// ```
pub fn is_valid_ss58_address(address: &str) -> bool {
    if address.is_empty() {
        // Possibly there could be a debug log, but not a print
        // utils::print(format!("The given address is empty"));
        return false;
    }

    AccountId32::from_ss58check(address).is_ok()
}

///    Checks if the given public_key is a valid ed25519 key.
///
/// ```text
///     Arguments:
///         public_key (str): The public_key to check as string.
///     Returns:
///         valid (bool): ``True`` if the public_key is a valid ed25519 key, ``False`` otherwise.
/// ```
pub fn is_string_valid_ed25519_pubkey(public_key: &str) -> bool {
    if public_key.len() != 64 && public_key.len() != 66 {
        return false;
    }

    let pub_key_var = Some(public_key.to_string());
    let keypair_result = Keypair::new(None, pub_key_var, None, SS58_FORMAT, None, CRYPTO_ED25519);

    match keypair_result {
        Ok(keypair) => keypair.ss58_address().is_some(),
        Err(_) => false,
    }
}

///    Checks if the given public_key is a valid ed25519 key.
///
/// ```text
///     Arguments:
///         public_key (bytes): The public_key to check as bytes.
///     Returns:
///         valid (bool): ``True`` if the public_key is a valid ed25519 key, ``False`` otherwise.
/// ```
pub fn are_bytes_valid_ed25519_pubkey(public_key: &[u8]) -> bool {
    if public_key.len() != 32 {
        return false;
    }

    let pub_key_var = Some(hex::encode(public_key));
    let keypair_result = Keypair::new(None, pub_key_var, None, SS58_FORMAT, None, CRYPTO_ED25519);

    match keypair_result {
        Ok(keypair) => keypair.ss58_address().is_some(),
        Err(_) => false,
    }
}

///    Checks if the given address is a valid destination address.
///
/// ```text
///     Arguments:
///         address (str): The address to check.
///     Returns:
///         valid (bool): ``True`` if the address is a valid destination address, ``False`` otherwise.
/// ```
pub fn is_valid_bittensor_address_or_public_key(address: &str) -> bool {
    if let Some(stripped) = address.strip_prefix("0x") {
        if let Ok(bytes) = hex::decode(stripped) {
            are_bytes_valid_ed25519_pubkey(&bytes)
        } else {
            is_valid_ss58_address(address)
        }
    } else {
        is_valid_ss58_address(address)
    }
}

/// When running inside a Python process, output must go through Python's `sys.stdout`
/// to stay synchronized with Python-level I/O (e.g. Jupyter, logging redirects).
/// In pure Rust mode, standard stdout is used directly.
#[cfg(not(feature = "python-bindings"))]
pub fn print(s: String) {
    use std::io::{self, Write};
    print!("{}", s);
    io::stdout().flush().unwrap();
}

#[cfg(feature = "python-bindings")]
pub fn print(s: String) {
    use pyo3::types::{PyDict, PyDictMethods};
    use std::ffi::CString;
    pyo3::Python::attach(|py| {
        let locals = PyDict::new(py);
        locals.set_item("s", s).unwrap();
        let code = CString::new(
            r#"
import sys
print(s, end='')
sys.stdout.flush()
"#,
        )
        .unwrap();
        py.run(&code, None, Some(&locals)).unwrap();
    });
}

/// Prompts the user and returns the response, if any.
///    
/// ```text
///     Arguments:
///         prompt: String
///     Returns:
///         response: Option<String>
/// ```
pub fn prompt(prompt: String) -> Option<String> {
    use std::io::{self, Write};

    print!("{}", prompt);
    io::stdout().flush().ok()?;

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => Some(input.trim().to_string()),
        Err(_) => None,
    }
}

/// Prompts the user with a password entry and returns the response, if any.
///    
/// ```text
///     Arguments:
///         prompt (String): the prompt to ask the user with.
///     Returns:
///         response: Option<String>
/// ```
pub fn prompt_password(prompt: String) -> Option<String> {
    use rpassword::read_password;
    use std::io::{self, Write};

    print!("{}", prompt);
    io::stdout().flush().ok()?;

    match read_password() {
        Ok(password) => Some(password.trim().to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ss58_format_success() {
        let test_address = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
        assert!(is_valid_ss58_address(test_address));
    }

    #[test]
    fn test_ed25519_address_is_valid_ss58() {
        let kp = Keypair::create_from_uri("//Alice", CRYPTO_ED25519).unwrap();
        let addr = kp.ss58_address().unwrap();
        assert!(is_valid_ss58_address(&addr));
    }

    #[test]
    fn test_sr25519_address_still_valid_after_accountid32_change() {
        assert!(is_valid_ss58_address(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        ));
    }
}
