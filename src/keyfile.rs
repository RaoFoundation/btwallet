use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::from_utf8;

use ansible_vault::{decrypt_vault, encrypt_vault};
use fernet::Fernet;

use base64::{engine::general_purpose, Engine as _};
use passwords::analyzer;
use passwords::scorer;
use serde_json::json;

use crate::errors::KeyFileError;
use crate::keypair::Keypair;
use crate::utils;

use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;

const NACL_SALT: &[u8] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";
const LEGACY_SALT: &[u8] = b"Iguesscyborgslikemyselfhaveatendencytobeparanoidaboutourorigins";

/// Serializes keypair object into keyfile data.
///
///     Arguments:
///         keypair (Keypair): The keypair object to be serialized.
///     Returns:
///         data (bytes): Serialized keypair data.
pub fn serialized_keypair_to_keyfile_data(keypair: &Keypair) -> Result<Vec<u8>, KeyFileError> {
    let mut data: HashMap<&str, serde_json::Value> = HashMap::new();

    // publicKey and privateKey fields are optional. If they exist, hex prefix "0x" is added to them.
    if let Ok(Some(public_key)) = keypair.public_key() {
        let public_key_str = hex::encode(&public_key);
        data.insert("accountId", json!(format!("0x{}", public_key_str)));
        data.insert("publicKey", json!(format!("0x{}", public_key_str)));
    }
    if let Ok(Some(private_key)) = keypair.private_key() {
        let private_key_str = hex::encode(&private_key);
        data.insert("privateKey", json!(format!("0x{}", private_key_str)));
    }

    // mnemonic and ss58_address fields are optional.
    if let Some(mnemonic) = keypair.mnemonic() {
        data.insert("secretPhrase", json!(mnemonic.to_string()));
    }

    // the seed_hex field is optional. If it exists, hex prefix "0x" is added to it.
    if let Some(seed_hex) = keypair.seed_hex() {
        let seed_hex_str = match from_utf8(&seed_hex) {
            Ok(s) => s.to_string(),
            Err(_) => hex::encode(seed_hex),
        };
        data.insert("secretSeed", json!(format!("0x{}", seed_hex_str)));
    }

    if let Some(ss58_address) = keypair.ss58_address() {
        data.insert("ss58Address", json!(ss58_address.to_string()));
    }

    // Serialize the data into JSON string and return it as bytes
    let json_data = serde_json::to_string(&data)
        .map_err(|e| KeyFileError::SerializationError(format!("Serialization error: {}", e)))?;
    Ok(json_data.into_bytes())
}

/// Deserializes Keypair object from passed keyfile data.
///
///     Arguments:
///         keyfile_data (PyBytes): The keyfile data to be loaded.
///     Returns:
///         keypair (Keypair): The Keypair loaded from bytes.
///     Raises:
///         KeyFileError: Raised if the passed PyBytes cannot construct a keypair object.
pub fn deserialize_keypair_from_keyfile_data(keyfile_data: &[u8]) -> Result<Keypair, KeyFileError> {
    // Decode the keyfile data from bytes to a string
    let decoded = from_utf8(keyfile_data).map_err(|_| {
        KeyFileError::DeserializationError("Failed to decode keyfile data.".to_string())
    })?;

    // Parse the JSON string into a HashMap
    let keyfile_dict: HashMap<String, Option<String>> =
        serde_json::from_str(decoded).map_err(|_| {
            KeyFileError::DeserializationError("Failed to parse keyfile data.".to_string())
        })?;

    // Extract data from the keyfile
    let secret_seed = keyfile_dict.get("secretSeed").and_then(|v| v.clone());
    let secret_phrase = keyfile_dict.get("secretPhrase").and_then(|v| v.clone());
    let private_key = keyfile_dict.get("privateKey").and_then(|v| v.clone());
    let ss58_address = keyfile_dict.get("ss58Address").and_then(|v| v.clone());

    // Create the `Keypair` based on the available data
    if let Some(secret_phrase) = secret_phrase {
        Keypair::create_from_mnemonic(secret_phrase.as_str()).map_err(|e| KeyFileError::Generic(e))
    } else if let Some(seed) = secret_seed {
        // Remove 0x prefix if present
        let seed = seed.trim_start_matches("0x");
        let seed_bytes = hex::decode(seed).map_err(|e| KeyFileError::Generic(e.to_string()))?;
        Keypair::create_from_seed(seed_bytes).map_err(|e| KeyFileError::Generic(e))
    } else if let Some(private_key) = private_key {
        // Remove 0x prefix if present
        let key = private_key.trim_start_matches("0x");
        Keypair::create_from_private_key(key).map_err(|e| KeyFileError::Generic(e))
    } else if let Some(ss58) = ss58_address {
        Keypair::new(Some(ss58.clone()), None, None, 42, None, 1)
            .map_err(|e| KeyFileError::Generic(e.to_string()))
    } else {
        Err(KeyFileError::Generic(
            "Keypair could not be created from keyfile data.".to_string(),
        ))
    }
}

/// Validates the password against a password policy.
///
///     Arguments:
///         password (str): The password to verify.
///     Returns:
///         valid (bool): ``True`` if the password meets validity requirements.
pub fn validate_password(password: &str) -> Result<bool, KeyFileError> {
    // Check for an empty password
    if password.is_empty() {
        return Ok(false);
    }

    // Define the password policy
    let min_length = 6;
    let min_score = 20.0; // Adjusted based on the scoring system described in the documentation

    // Analyze the password
    let analyzed = analyzer::analyze(password);
    let score = scorer::score(&analyzed);

    // Check conditions
    if password.len() >= min_length && score >= min_score {
        // Prompt user to retype the password
        let password_verification_response =
            utils::prompt_password("Retype your password: ".to_string())
                .expect("Failed to read the password.");

        // Remove potential newline or whitespace at the end
        let password_verification = password_verification_response.trim();

        if password == password_verification {
            Ok(true)
        } else {
            utils::print("Passwords do not match.\n".to_string());
            Ok(false)
        }
    } else {
        utils::print("Password not strong enough. Try increasing the length of the password or the password complexity.\n".to_string());
        Ok(false)
    }
}

/// Prompts the user to enter a password for key encryption.
///
///     Arguments:
///         validation_required (bool): If ``True``, validates the password against policy requirements.
///     Returns:
///         password (str): The valid password entered by the user.
pub fn ask_password(validation_required: bool) -> Result<String, KeyFileError> {
    let mut valid = false;
    let mut password = utils::prompt_password("Enter your password: ".to_string());

    if validation_required {
        while !valid {
            if let Some(ref pwd) = password {
                valid = validate_password(&pwd)?;
                if !valid {
                    password = utils::prompt_password("Enter your password again: ".to_string());
                }
            } else {
                valid = true
            }
        }
    }

    Ok(password.unwrap_or("".to_string()).trim().to_string())
}

/// Returns `true` if the keyfile data is NaCl encrypted.
///
///     Arguments:
///         `keyfile_data` - Bytes to validate
///     Returns:
///         `is_nacl` - `true` if the data is ansible encrypted.
pub fn keyfile_data_is_encrypted_nacl(keyfile_data: &[u8]) -> bool {
    keyfile_data.starts_with(b"$NACL")
}

/// Returns true if the keyfile data is ansible encrypted.
///
///     Arguments:
///         `keyfile_data` - The bytes to validate.
///     Returns:
///         `is_ansible` - ``True`` if the data is ansible encrypted.
pub fn keyfile_data_is_encrypted_ansible(keyfile_data: &[u8]) -> bool {
    keyfile_data.starts_with(b"$ANSIBLE_VAULT")
}

/// Returns true if the keyfile data is legacy encrypted.
///
///     Arguments:
///         `keyfile_data` - The bytes to validate.
///     Returns:
///         `is_legacy` - `true` if the data is legacy encrypted.
pub fn keyfile_data_is_encrypted_legacy(keyfile_data: &[u8]) -> bool {
    keyfile_data.starts_with(b"gAAAAA")
}

/// Returns `true` if the keyfile data is encrypted.
///
///     Arguments:
///         keyfile_data (bytes): The bytes to validate.
///     Returns:
///         is_encrypted (bool): `true` if the data is encrypted.
pub fn keyfile_data_is_encrypted(keyfile_data: &[u8]) -> bool {
    let nacl = keyfile_data_is_encrypted_nacl(keyfile_data);
    let ansible = keyfile_data_is_encrypted_ansible(keyfile_data);
    let legacy = keyfile_data_is_encrypted_legacy(keyfile_data);
    nacl || ansible || legacy
}

/// Returns type of encryption method as a string.
///
///     Arguments:
///         keyfile_data (bytes): Bytes to validate.
///     Returns:
///         (str): A string representing the name of encryption method.
pub fn keyfile_data_encryption_method(keyfile_data: &[u8]) -> String {
    if keyfile_data_is_encrypted_nacl(keyfile_data) {
        "NaCl"
    } else if keyfile_data_is_encrypted_ansible(keyfile_data) {
        "Ansible Vault"
    } else if keyfile_data_is_encrypted_legacy(keyfile_data) {
        "legacy"
    } else {
        "unknown"
    }
    .to_string()
}

/// legacy_encrypt_keyfile_data.
///
///     Arguments:
///         keyfile_data (bytes): Bytes of data from the keyfile.
///         password (str): Optional string that represents the password.
///     Returns:
///         encrypted_data (bytes): The encrypted keyfile data in bytes.
pub fn legacy_encrypt_keyfile_data(
    keyfile_data: &[u8],
    password: Option<String>,
) -> Result<Vec<u8>, KeyFileError> {
    let password = password.unwrap_or_else(||
        // function to get password from user
        ask_password(true).unwrap());

    utils::print(
        ":exclamation_mark: Encrypting key with legacy encryption method...\n".to_string(),
    );

    // Encrypting key with legacy encryption method
    let encrypted_data = encrypt_vault(keyfile_data, password.as_str())
        .map_err(|err| KeyFileError::EncryptionError(format!("{}", err)))?;

    Ok(encrypted_data.into_bytes())
}

/// Retrieves the cold key password from the environment variables.
///
///     Arguments:
///         `coldkey_name` - The name of the cold key.
///     Returns:
///         `Option<String>` - The password retrieved from the environment variables, or `None` if not found.
pub fn get_password_from_environment(env_var_name: String) -> Result<Option<String>, KeyFileError> {
    match env::var(&env_var_name) {
        Ok(encrypted_password_base64) => {
            let encrypted_password = general_purpose::STANDARD
                .decode(&encrypted_password_base64)
                .map_err(|_| KeyFileError::Base64DecodeError("Invalid Base64".to_string()))?;
            let decrypted_password = decrypt_password(&encrypted_password, &env_var_name);
            Ok(Some(decrypted_password))
        }
        Err(_) => Ok(None),
    }
}

/// decrypt of keyfile_data with secretbox
fn derive_key(password: &[u8]) -> secretbox::Key {
    let nacl_salt = pwhash::argon2i13::Salt::from_slice(NACL_SALT).expect("Invalid NACL_SALT.");
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    pwhash::argon2i13::derive_key(
        &mut key.0,
        password,
        &nacl_salt,
        pwhash::argon2i13::OPSLIMIT_SENSITIVE,
        pwhash::argon2i13::MEMLIMIT_SENSITIVE,
    )
    .expect("Failed to derive key for NaCl decryption.");
    key
}

/// Encrypts the passed keyfile data using ansible vault.
///
///     Arguments:
///         keyfile_data (bytes): The bytes to encrypt.
///         password (str): The password used to encrypt the data. If `None`, asks for user input.
///     Returns:
///         encrypted_data (bytes): The encrypted data.
pub fn encrypt_keyfile_data(
    keyfile_data: &[u8],
    password: Option<String>,
) -> Result<Vec<u8>, KeyFileError> {
    // get password or ask user
    let password = match password {
        Some(pwd) => pwd,
        None => ask_password(true)?,
    };

    utils::print("Encrypting...\n".to_string());

    // crate the key with pwhash Argon2i
    let key = derive_key(password.as_bytes());

    // encrypt the data using SecretBox
    let nonce = secretbox::gen_nonce();
    let encrypted_data = secretbox::seal(keyfile_data, &nonce, &key);

    // concatenate with b"$NACL"
    let mut result = b"$NACL".to_vec();
    result.extend_from_slice(&nonce.0);
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

/// Decrypts the passed keyfile data using ansible vault.
///
///     Arguments:
///         keyfile_data (): The bytes to decrypt.
///         password (str): The password used to decrypt the data. If `None`, asks for user input.
///         coldkey_name (str): The name of the cold key. If provided, retrieves the password from environment variables.
///     Returns:
///         decrypted_data (bytes): The decrypted data.
pub fn decrypt_keyfile_data(
    keyfile_data: &[u8],
    password: Option<String>,
    password_env_var: Option<String>,
) -> Result<Vec<u8>, KeyFileError> {
    // decrypt of keyfile_data with secretbox
    fn nacl_decrypt(keyfile_data: &[u8], key: &secretbox::Key) -> Result<Vec<u8>, KeyFileError> {
        let data = &keyfile_data[5..]; // Remove the $NACL prefix
        let nonce = secretbox::Nonce::from_slice(&data[0..secretbox::NONCEBYTES]).ok_or(
            KeyFileError::InvalidEncryption("Invalid nonce.".to_string()),
        )?;
        let ciphertext = &data[secretbox::NONCEBYTES..];
        secretbox::open(ciphertext, &nonce, key).map_err(|_| {
            KeyFileError::DecryptionError("Wrong password for nacl decryption.".to_string())
        })
    }
    // decrypt of keyfile_data with legacy way
    fn legacy_decrypt(password: &str, keyfile_data: &[u8]) -> Result<Vec<u8>, KeyFileError> {
        let kdf = pbkdf2::pbkdf2_hmac::<sha2::Sha256>;
        let mut key = vec![0; 32];
        kdf(password.as_bytes(), LEGACY_SALT, 10000000, &mut key);

        let fernet_key = Fernet::generate_key();
        let fernet = Fernet::new(&fernet_key).unwrap();
        let keyfile_data_str = from_utf8(keyfile_data)
            .map_err(|e| KeyFileError::DeserializationError(e.to_string()))?;
        fernet.decrypt(keyfile_data_str).map_err(|_| {
            KeyFileError::DecryptionError("Wrong password for legacy decryption.".to_string())
        })
    }

    let mut password = password;

    // Retrieve password from environment variable if env_var_name is provided
    if let Some(env_var_name_) = password_env_var {
        if password.is_none() {
            password = get_password_from_environment(env_var_name_)?;
        }
    }

    // If password is still None, ask the user for input
    if password.is_none() {
        password = Some(ask_password(false)?);
    }

    let password = password.unwrap();

    utils::print("Decrypting...\n".to_string());
    // NaCl decryption
    if keyfile_data_is_encrypted_nacl(keyfile_data) {
        let key = derive_key(password.as_bytes());
        let decrypted_data = nacl_decrypt(keyfile_data, &key).map_err(|_| {
            KeyFileError::DecryptionError("Wrong password for decryption.".to_string())
        })?;
        return Ok(decrypted_data);
    }

    // Ansible Vault decryption
    if keyfile_data_is_encrypted_ansible(keyfile_data) {
        let decrypted_data = decrypt_vault(keyfile_data, password.as_str()).map_err(|_| {
            KeyFileError::DecryptionError("Wrong password for decryption.".to_string())
        })?;
        return Ok(decrypted_data);
    }

    // Legacy decryption
    if keyfile_data_is_encrypted_legacy(keyfile_data) {
        let decrypted_data = legacy_decrypt(&password, keyfile_data).map_err(|_| {
            KeyFileError::DecryptionError("Wrong password for decryption.".to_string())
        })?;
        return Ok(decrypted_data);
    }

    // If none of the methods work, raise error
    Err(KeyFileError::InvalidEncryption(
        "Invalid or unknown encryption method.".to_string(),
    ))
}

fn confirm_prompt(question: &str) -> bool {
    let choice = utils::prompt(format!("{} (y/N): ", question)).expect("Failed to read input.");
    choice.trim().to_lowercase() == "y"
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home_dir) = dirs::home_dir() {
            return path.replacen('~', home_dir.to_str().unwrap(), 1);
        }
    }
    path.to_string()
}

// Encryption password
fn encrypt_password(key: &str, value: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    value
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &c)| c ^ key_bytes[i % key_bytes.len()])
        .collect()
}

// Decrypting password
fn decrypt_password(data: &[u8], key: &str) -> String {
    let key_bytes = key.as_bytes();
    let decrypted_bytes: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &c)| c ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(decrypted_bytes).unwrap_or_else(|_| String::new())
}

#[derive(Clone)]
pub struct Keyfile {
    pub path: String,
    _path: PathBuf,
    name: String,
    should_save_to_env: bool,
}
impl std::fmt::Display for Keyfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.__str__() {
            Ok(s) => write!(f, "{}", s),
            Err(e) => write!(f, "Error displaying keyfile: {}", e),
        }
    }
}

impl Keyfile {
    /// Creates a new Keyfile instance.
    ///
    ///     Arguments:
    ///         path (String): The file system path where the keyfile is stored.
    ///         name (Option<String>): Optional name for the keyfile. Defaults to "Keyfile" if not provided.
    ///         should_save_to_env (bool): If ``True``, saves the password to environment variables.
    ///     Returns:
    ///         keyfile (Keyfile): A new Keyfile instance.
    pub fn new(
        path: String,
        name: Option<String>,
        should_save_to_env: bool,
    ) -> Result<Self, KeyFileError> {
        let expanded_path: PathBuf = PathBuf::from(expand_tilde(&path));
        let name = name.unwrap_or_else(|| "Keyfile".to_string());
        Ok(Keyfile {
            path,
            _path: expanded_path,
            name,
            should_save_to_env,
        })
    }

    #[allow(clippy::bool_comparison)]
    fn __str__(&self) -> Result<String, KeyFileError> {
        if self.exists_on_device()? != true {
            Ok(format!("keyfile (empty, {})>", self.path))
        } else if self.is_encrypted()? {
            let encryption_method = self._read_keyfile_data_from_file()?;
            Ok(format!(
                "Keyfile ({:?} encrypted, {})>",
                encryption_method, self.path
            ))
        } else {
            Ok(format!("keyfile (decrypted, {})>", self.path))
        }
    }

    fn __repr__(&self) -> Result<String, KeyFileError> {
        self.__str__()
    }

    /// Returns the keypair from path, decrypts data if the file is encrypted.
    ///
    ///     Arguments:
    ///         password (Option<String>): The password used to decrypt the data. If ``None``, asks for user input.
    ///     Returns:
    ///         keypair (Keypair): The Keypair loaded from the file.
    pub fn get_keypair(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        // read file
        let keyfile_data = self._read_keyfile_data_from_file()?;

        // check if encrypted
        let decrypted_keyfile_data = if keyfile_data_is_encrypted(&keyfile_data) {
            decrypt_keyfile_data(&keyfile_data, password, Some(self.env_var_name()?))?
        } else {
            keyfile_data
        };

        // deserialization data into the Keypair
        deserialize_keypair_from_keyfile_data(&decrypted_keyfile_data)
    }

    /// Loads the name from keyfile.name or raises an error.
    pub fn get_name(&self) -> Result<String, KeyFileError> {
        Ok(self.name.clone())
    }

    /// Loads the name from keyfile.path or raises an error.
    pub fn get_path(&self) -> Result<String, KeyFileError> {
        Ok(self.path.clone())
    }

    /// Returns the keyfile data under path.
    pub fn data(&self) -> Result<Vec<u8>, KeyFileError> {
        self._read_keyfile_data_from_file()
    }

    /// Returns the keyfile data under path.
    pub fn keyfile_data(&self) -> Result<Vec<u8>, KeyFileError> {
        self._read_keyfile_data_from_file()
    }

    /// Returns local environment variable key name based on Keyfile path.
    pub fn env_var_name(&self) -> Result<String, KeyFileError> {
        let path = &self
            .path
            .replace(std::path::MAIN_SEPARATOR, "_")
            .replace('.', "_");
        Ok(format!("BT_PW_{}", path.to_uppercase()))
    }

    /// Writes the keypair to the file and optionally encrypts data.
    ///
    ///     Arguments:
    ///         keypair (Keypair): The keypair object to be stored.
    ///         encrypt (bool): If ``True``, encrypts the keyfile data.
    ///         overwrite (bool): If ``True``, overwrites existing file without prompting.
    ///         password (Option<String>): The password used to encrypt the data. If ``None``, asks for user input.
    pub fn set_keypair(
        &self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        password: Option<String>,
    ) -> Result<(), KeyFileError> {
        self.make_dirs()?;

        let keyfile_data = serialized_keypair_to_keyfile_data(&keypair)?;

        let final_keyfile_data = if encrypt {
            let encrypted_data = encrypt_keyfile_data(&keyfile_data, password.clone())?;

            // store password to local env
            if self.should_save_to_env {
                self.save_password_to_env(password.clone())?;
            }

            encrypted_data
        } else {
            keyfile_data
        };

        self._write_keyfile_data_to_file(&final_keyfile_data, overwrite)?;

        Ok(())
    }

    /// Creates directories for the path if they do not exist.
    pub fn make_dirs(&self) -> Result<(), KeyFileError> {
        if let Some(directory) = self._path.parent() {
            // check if the dir is exit already
            if !directory.exists() {
                // create the dir if not
                fs::create_dir_all(directory)
                    .map_err(|e| KeyFileError::DirectoryCreation(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Returns ``True`` if the file exists on the device.
    ///
    ///     Returns:
    ///         readable (bool): ``True`` if the file is readable.
    pub fn exists_on_device(&self) -> Result<bool, KeyFileError> {
        Ok(self._path.exists())
    }

    /// Returns ``True`` if the file under path is readable.
    pub fn is_readable(&self) -> Result<bool, KeyFileError> {
        // check file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // get file metadata
        let metadata = fs::metadata(&self._path).map_err(|e| {
            KeyFileError::MetadataError(format!("Failed to get metadata for file: {}.", e))
        })?;

        // check permissions
        let permissions = metadata.permissions();
        let readable = permissions.mode() & 0o444 != 0; // check readability

        Ok(readable)
    }

    /// Returns ``True`` if the file under path is writable.
    ///
    ///     Returns:
    ///         writable (bool): ``True`` if the file is writable.
    pub fn is_writable(&self) -> Result<bool, KeyFileError> {
        // check if file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // get file metadata
        let metadata = fs::metadata(&self._path).map_err(|e| {
            KeyFileError::MetadataError(format!("Failed to get metadata for file: {}", e))
        })?;

        // check the permissions
        let permissions = metadata.permissions();
        let writable = permissions.mode() & 0o222 != 0; // check if file is writable

        Ok(writable)
    }

    /// Returns ``True`` if the file under path is encrypted.
    ///
    ///     Returns:
    ///         encrypted (bool): ``True`` if the file is encrypted.
    pub fn is_encrypted(&self) -> Result<bool, KeyFileError> {
        // check if file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // check readable
        if !self.is_readable()? {
            return Ok(false);
        }

        // get the data from file
        let keyfile_data = self._read_keyfile_data_from_file()?;

        // check if encrypted
        let is_encrypted = keyfile_data_is_encrypted(&keyfile_data);

        Ok(is_encrypted)
    }

    /// Asks the user if it is okay to overwrite the file.
    pub fn _may_overwrite(&self) -> bool {
        let choice = utils::prompt(format!(
            "File {} already exists. Overwrite? (y/N) ",
            self.path
        ))
        .expect("Failed to read input.");

        choice.trim().to_lowercase() == "y"
    }

    /// Check the version of keyfile and update if needed.
    ///
    ///     Arguments:
    ///         print_result (bool): If ``True``, prints the result of the encryption check.
    ///         no_prompt (bool): If ``True``, skips user prompts during the update process.
    ///     Returns:
    ///         updated (bool): ``True`` if the keyfile was successfully updated to the latest encryption method.
    pub fn check_and_update_encryption(
        &self,
        print_result: bool,
        no_prompt: bool,
    ) -> Result<bool, KeyFileError> {
        if !self.exists_on_device()? {
            if print_result {
                utils::print(format!("Keyfile '{}' does not exist.\n", self.path));
            }
            return Ok(false);
        }

        if !self.is_readable()? {
            if print_result {
                utils::print(format!("Keyfile '{}' is not readable.\n", self.path));
            }
            return Ok(false);
        }

        if !self.is_writable()? {
            if print_result {
                utils::print(format!("Keyfile '{}' is not writable.\n", self.path));
            }
            return Ok(false);
        }

        let update_keyfile = false;
        if !no_prompt {
            // read keyfile
            let keyfile_data = self._read_keyfile_data_from_file()?;

            // check if file is decrypted
            if keyfile_data_is_encrypted(&keyfile_data)
                && !keyfile_data_is_encrypted_nacl(&keyfile_data)
            {
                utils::print("You may update the keyfile to improve security...\n".to_string());

                // ask user for the confirmation for updating
                if update_keyfile == confirm_prompt("Update keyfile?") {
                    let mut stored_mnemonic = false;

                    // check mnemonic if saved
                    while !stored_mnemonic {
                        utils::print(
                            "Please store your mnemonic in case an error occurs...\n".to_string(),
                        );
                        if confirm_prompt("Have you stored the mnemonic?") {
                            stored_mnemonic = true;
                        } else if !confirm_prompt("Retry and continue keyfile update?") {
                            return Ok(false);
                        }
                    }

                    // try decrypt data
                    let mut decrypted_keyfile_data: Option<Vec<u8>> = None;
                    let mut password: Option<String> = None;
                    while decrypted_keyfile_data.is_none() {
                        let pwd = ask_password(false)?;
                        password = Some(pwd.clone());

                        match decrypt_keyfile_data(
                            &keyfile_data,
                            Some(pwd),
                            Some(self.env_var_name()?),
                        ) {
                            Ok(decrypted_data) => {
                                decrypted_keyfile_data = Some(decrypted_data);
                            }
                            Err(_) => {
                                if !confirm_prompt("Invalid password, retry?") {
                                    return Ok(false);
                                }
                            }
                        }
                    }

                    // encryption of updated data
                    if let Some(password) = password {
                        if let Some(decrypted_data) = decrypted_keyfile_data {
                            let encrypted_keyfile_data =
                                encrypt_keyfile_data(&decrypted_data, Some(password))?;
                            self._write_keyfile_data_to_file(&encrypted_keyfile_data, true)?;
                        }
                    }
                }
            }
        }

        if print_result || update_keyfile {
            // check and get result
            let keyfile_data = self._read_keyfile_data_from_file()?;

            return if !keyfile_data_is_encrypted(&keyfile_data) {
                if print_result {
                    utils::print("Keyfile is not encrypted.\n".to_string());
                }
                Ok(false)
            } else if keyfile_data_is_encrypted_nacl(&keyfile_data) {
                if print_result {
                    utils::print("Keyfile is updated.\n".to_string());
                }
                Ok(true)
            } else {
                if print_result {
                    utils::print("Keyfile is outdated, please update using 'btcli'.\n".to_string());
                }
                Ok(false)
            };
        }
        Ok(false)
    }

    /// Encrypts the file under the path.
    ///
    ///     Arguments:
    ///         password (Option<String>): The password used to encrypt the data. If ``None``, asks for user input.
    pub fn encrypt(&self, mut password: Option<String>) -> Result<(), KeyFileError> {
        // checkers
        if !self.exists_on_device()? {
            return Err(KeyFileError::FileNotFound(format!(
                "Keyfile at: {} does not exist",
                self.path
            )));
        }

        if !self.is_readable()? {
            return Err(KeyFileError::NotReadable(format!(
                "Keyfile at: {} is not readable",
                self.path
            )));
        }

        if !self.is_writable()? {
            return Err(KeyFileError::NotWritable(format!(
                "Keyfile at: {} is not writable",
                self.path
            )));
        }

        // read the data
        let keyfile_data = self._read_keyfile_data_from_file()?;

        let final_data = if !keyfile_data_is_encrypted(&keyfile_data) {
            let as_keypair = deserialize_keypair_from_keyfile_data(&keyfile_data)?;
            let serialized_data = serialized_keypair_to_keyfile_data(&as_keypair)?;

            // get password from local env if exist
            if password.is_none() {
                password = get_password_from_environment(self.env_var_name()?)?;
            }

            let encrypted_keyfile_data = encrypt_keyfile_data(&serialized_data, password.clone())?;

            if self.should_save_to_env {
                self.save_password_to_env(password.clone())?;
            }

            encrypted_keyfile_data
        } else {
            keyfile_data
        };

        // write back
        self._write_keyfile_data_to_file(&final_data, true)?;

        Ok(())
    }

    /// Decrypts the file under the path.
    ///
    ///     Arguments:
    ///         password (Option<String>): The password used to decrypt the data. If ``None``, asks for user input.
    pub fn decrypt(&self, password: Option<String>) -> Result<(), KeyFileError> {
        // checkers
        if !self.exists_on_device()? {
            return Err(KeyFileError::FileNotFound(format!(
                "Keyfile at: {} does not exist.",
                self.path
            )));
        }
        if !self.is_readable()? {
            return Err(KeyFileError::NotReadable(format!(
                "Keyfile at: {} is not readable.",
                self.path
            )));
        }
        if !self.is_writable()? {
            return Err(KeyFileError::NotWritable(format!(
                "Keyfile at: {} is not writable.",
                self.path
            )));
        }

        // read data
        let keyfile_data = self._read_keyfile_data_from_file()?;

        let decrypted_data = if keyfile_data_is_encrypted(&keyfile_data) {
            decrypt_keyfile_data(&keyfile_data, password, Some(self.env_var_name()?))?
        } else {
            keyfile_data
        };

        let as_keypair = deserialize_keypair_from_keyfile_data(&decrypted_data)?;

        let serialized_data = serialized_keypair_to_keyfile_data(&as_keypair)?;
        self._write_keyfile_data_to_file(&serialized_data, true)?;
        Ok(())
    }

    /// Reads the keyfile data from the file.
    ///
    ///     Returns:
    ///         keyfile_data (Vec<u8>): The keyfile data stored under the path.
    ///     Raises:
    ///         KeyFileError: Raised if the file does not exist or is not readable.
    pub fn _read_keyfile_data_from_file(&self) -> Result<Vec<u8>, KeyFileError> {
        // Check if the file exists
        if !self.exists_on_device()? {
            return Err(KeyFileError::FileNotFound(format!(
                "Keyfile at: {} does not exist.",
                self.path
            )));
        }

        // Check if the file is readable
        if !self.is_readable()? {
            return Err(KeyFileError::NotReadable(format!(
                "Keyfile at: {} is not readable.",
                self.path
            )));
        }

        // Open and read the file
        let mut file = fs::File::open(&self._path)
            .map_err(|e| KeyFileError::FileOpen(format!("Failed to open file: {}.", e)))?;
        let mut data_vec = Vec::new();
        file.read_to_end(&mut data_vec)
            .map_err(|e| KeyFileError::FileRead(format!("Failed to read file: {}.", e)))?;

        Ok(data_vec)
    }

    /// Writes the keyfile data to the file.
    ///
    ///     Arguments:
    ///         keyfile_data: The byte data to store under the path.
    ///         overwrite: If true, overwrites the data without asking for permission from the user. Default is false.
    pub fn _write_keyfile_data_to_file(
        &self,
        keyfile_data: &[u8],
        overwrite: bool,
    ) -> Result<(), KeyFileError> {
        // ask user for rewriting
        if self.exists_on_device()? && !overwrite && !self._may_overwrite() {
            return Err(KeyFileError::NotWritable(format!(
                "Keyfile at: {} is not writable",
                self.path
            )));
        }

        let mut keyfile = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // cleanup if rewrite
            .open(&self._path)
            .map_err(|e| KeyFileError::FileOpen(format!("Failed to open file: {}.", e)))?;

        // write data
        keyfile
            .write_all(keyfile_data)
            .map_err(|e| KeyFileError::FileWrite(format!("Failed to write to file: {}.", e)))?;

        // set permissions
        let mut permissions = fs::metadata(&self._path)
            .map_err(|e| {
                KeyFileError::MetadataError(format!("Failed to get metadata for file: {}.", e))
            })?
            .permissions();
        permissions.set_mode(0o600); // just for owner
        fs::set_permissions(&self._path, permissions).map_err(|e| {
            KeyFileError::PermissionError(format!("Failed to set permissions: {}.", e))
        })?;
        Ok(())
    }

    /// Saves the key's password to the associated local environment variable.
    ///
    ///     Arguments:
    ///         password (Option<String>): The password to save. If ``None``, asks for user input.
    ///     Returns:
    ///         encrypted_password_base64 (str): The base64-encoded encrypted password.
    pub fn save_password_to_env(&self, password: Option<String>) -> Result<String, KeyFileError> {
        // checking the password
        let password = match password {
            Some(pwd) => pwd,
            None => match ask_password(true) {
                Ok(pwd) => pwd,
                Err(e) => {
                    utils::print(format!("Error asking password: {:?}.\n", e));
                    return Ok("".to_string());
                }
            },
        };
        // saving password
        let env_var_name = self.env_var_name()?;
        // encrypt password
        let encrypted_password = encrypt_password(&env_var_name, &password);
        let encrypted_password_base64 = general_purpose::STANDARD.encode(&encrypted_password);
        // store encrypted password
        env::set_var(&env_var_name, &encrypted_password_base64);
        Ok(encrypted_password_base64)
    }

    /// Removes the password associated with the Keyfile from the local environment.
    pub fn remove_password_from_env(&self) -> Result<bool, KeyFileError> {
        let env_var_name = self.env_var_name()?;

        if env::var(&env_var_name).is_ok() {
            env::remove_var(&env_var_name);
            let message = format!("Environment variable '{}' removed.\n", env_var_name);
            utils::print(message);
            Ok(true)
        } else {
            let message = format!("Environment variable '{}' does not exist.\n", env_var_name);
            utils::print(message);
            Ok(false)
        }
    }
}
