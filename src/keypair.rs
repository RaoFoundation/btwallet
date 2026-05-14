use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use schnorrkel::{PublicKey, SecretKey};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, ByteArray, Pair};
use std::fmt;

const PKCS8_HEADER: &[u8] = &[48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const PKCS8_DIVIDER: &[u8] = &[161, 35, 3, 33, 0];
const SEC_LENGTH: usize = 64;
const PUB_LENGTH: usize = 32;

#[derive(Serialize, Deserialize, Debug)]
struct Encoding {
    content: Vec<String>,
    #[serde(rename = "type")]
    enc_type: Vec<String>,
    version: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Meta {
    #[serde(rename = "genesisHash")]
    genesis_hash: Option<String>,
    name: String,
    #[serde(rename = "whenCreated")]
    when_created: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonStructure {
    encoded: String,
    encoding: Encoding,
    address: String,
    meta: Meta,
}

#[derive(Clone)]
pub struct Keypair {
    ss58_address: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
    ss58_format: u8,
    seed_hex: Option<Vec<u8>>,
    crypto_type: u8,
    mnemonic: Option<String>,
    pair: Option<sr25519::Pair>,
}

impl Keypair {
    /// Creates a new Keypair instance.
    ///
    ///     Arguments:
    ///         ss58_address (Option<String>): Optional SS58-formatted address.
    ///         public_key (Option<String>): Optional public key as hex string.
    ///         private_key (Option<String>): Optional private key as hex string.
    ///         ss58_format (u8): The SS58 format number for address encoding.
    ///         seed_hex (Option<Vec<u8>>): Optional seed bytes.
    ///         crypto_type (u8): The cryptographic algorithm type (1 for SR25519).
    ///     Returns:
    ///         keypair (Keypair): A new Keypair instance.
    pub fn new(
        ss58_address: Option<String>,
        public_key: Option<String>,
        private_key: Option<String>,
        ss58_format: u8,
        seed_hex: Option<Vec<u8>>,
        crypto_type: u8,
    ) -> Result<Self, String> {
        if crypto_type != 1 {
            return Err(format!("Unsupported crypto type: {}.", crypto_type));
        }

        let mut ss58_address_res = ss58_address.clone();
        let mut public_key_res = public_key;

        if let Some(private_key_str) = &private_key {
            let private_key_bytes =
                hex::decode(private_key_str.trim_start_matches("0x")).expect("");

            if private_key_bytes.len() != 64 {
                return Err("Secret key should be 64 bytes long.".to_string());
            }

            // TODO: add logic creation pair from private key
        }

        // if public_key is passed
        if let Some(public_key_str) = &public_key_res {
            let public_key_vec = hex::decode(public_key_str.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid `public_key` string: {}", e))?;

            let public_key_array: [u8; 32] = public_key_vec
                .try_into()
                .map_err(|_| "Public key must be 32 bytes long.")?;

            let public_key = sr25519::Public::from_raw(public_key_array);

            ss58_address_res = Option::from(public_key.to_ss58check());
        }

        // If ss58_address is passed, decode the public key
        if let Some(ss58_address_str) = ss58_address.clone() {
            let public_key = sr25519::Public::from_ss58check(&ss58_address_str)
                .map_err(|e| format!("Invalid SS58 address: {}", e))?;

            public_key_res = Some(hex::encode(public_key.to_raw()));
        }

        let kp = Keypair {
            ss58_address: ss58_address_res,
            public_key: public_key_res,
            private_key,
            ss58_format,
            seed_hex,
            crypto_type,
            mnemonic: None,
            pair: None,
        };

        // If public_key is missing (ss58_address wasn't created), return an error
        if kp.public_key.is_none() {
            return Err("No SS58 formatted address or public key provided.".to_string());
        }
        Ok(kp)
    }

    fn __str__(&self) -> Result<String, String> {
        match self.ss58_address() {
            Some(address) => Ok(format!("<Keypair (address={})>", address)),
            None => Ok("<Keypair (address=None)>".to_string()),
        }
    }

    fn __repr__(&self) -> Result<String, String> {
        self.__str__()
    }

    /// Generates a new mnemonic phrase.
    ///
    ///     Arguments:
    ///         n_words (usize): The number of words in the mnemonic (e.g., 12, 15, 18, 21, 24).
    ///     Returns:
    ///         mnemonic (String): The generated mnemonic phrase.
    pub fn generate_mnemonic(n_words: usize) -> Result<String, String> {
        let mnemonic = Mnemonic::generate(n_words).map_err(|e| e.to_string())?;
        Ok(mnemonic.to_string())
    }

    /// Creates a Keypair from a mnemonic phrase.
    ///
    ///     Arguments:
    ///         mnemonic (str): The mnemonic phrase to create the keypair from.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the mnemonic.
    pub fn create_from_mnemonic(mnemonic: &str) -> Result<Self, String> {
        let (pair, seed_vec) =
            sr25519::Pair::from_phrase(mnemonic, None).map_err(|e| e.to_string())?;

        let kp = Keypair {
            mnemonic: Some(mnemonic.to_string()),
            seed_hex: Some(seed_vec.to_vec()),
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates a Keypair from a seed.
    ///
    ///     Arguments:
    ///         seed (Vec<u8>): The seed bytes to create the keypair from.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the seed.
    pub fn create_from_seed(seed: Vec<u8>) -> Result<Self, String> {
        let pair = sr25519::Pair::from_seed_slice(&seed)
            .map_err(|e| format!("Failed to create pair from seed: {}", e))?;

        let kp = Keypair {
            seed_hex: Some(seed.to_vec()),
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates a Keypair from a private key.
    ///
    ///     Arguments:
    ///         private_key (str): The private key as hex string to create the keypair from.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the private key.
    pub fn create_from_private_key(private_key: &str) -> Result<Self, String> {
        let private_key_vec = hex::decode(private_key.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid `private_key` string: {}", e))?;

        let pair = sr25519::Pair::from_seed_slice(&private_key_vec)
            .map_err(|e| format!("Failed to create pair from private key: {}", e))?;

        let kp = Keypair {
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates a Keypair from encrypted JSON data.
    ///
    ///     Arguments:
    ///         json_data (str): The encrypted JSON data containing the keypair.
    ///         passphrase (str): The passphrase to decrypt the JSON data.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the encrypted JSON.
    pub fn create_from_encrypted_json(
        json_data: &str,
        passphrase: &str,
    ) -> Result<Keypair, String> {
        /// rust version of python .rjust
        fn pad_right(mut data: Vec<u8>, total_len: usize, pad_byte: u8) -> Vec<u8> {
            if data.len() < total_len {
                let pad_len = total_len - data.len();
                data.extend(vec![pad_byte; pad_len]);
            }
            data
        }

        pub fn pair_from_ed25519_secret_key(secret: &[u8], pubkey: &[u8]) -> ([u8; 64], [u8; 32]) {
            match (
                SecretKey::from_ed25519_bytes(secret),
                PublicKey::from_bytes(pubkey),
            ) {
                (Ok(s), Ok(k)) => (s.to_bytes(), k.to_bytes()),
                _ => panic!("Invalid secret or pubkey provided."),
            }
        }

        /// Decodes a PKCS8-encoded key pair from the provided byte slice.
        /// Returns a tuple containing the private key and public key as vectors of bytes.
        fn decode_pkcs8(
            ciphertext: &[u8],
        ) -> Result<([u8; SEC_LENGTH], [u8; PUB_LENGTH]), &'static str> {
            let mut current_offset = 0;
            let header = &ciphertext[current_offset..current_offset + PKCS8_HEADER.len()];
            if header != PKCS8_HEADER {
                return Err("Invalid Pkcs8 header found in body");
            }
            current_offset += PKCS8_HEADER.len();
            let secret_key = &ciphertext[current_offset..current_offset + SEC_LENGTH];
            let mut secret_key_array = [0u8; SEC_LENGTH];
            secret_key_array.copy_from_slice(secret_key);
            current_offset += SEC_LENGTH;
            let divider = &ciphertext[current_offset..current_offset + PKCS8_DIVIDER.len()];
            if divider != PKCS8_DIVIDER {
                return Err("Invalid Pkcs8 divider found in body");
            }
            current_offset += PKCS8_DIVIDER.len();
            let public_key = &ciphertext[current_offset..current_offset + PUB_LENGTH];
            let mut public_key_array = [0u8; PUB_LENGTH];
            public_key_array.copy_from_slice(public_key);
            Ok((secret_key_array, public_key_array))
        }

        let json_data: JsonStructure = serde_json::from_str(json_data).unwrap();

        if json_data.encoding.version != "3" {
            return Err("Unsupported JSON format".to_string());
        }

        let mut encrypted = general_purpose::STANDARD
            .decode(json_data.encoded)
            .map_err(|e| e.to_string())?;

        let password = if json_data.encoding.enc_type.contains(&"scrypt".to_string()) {
            let salt = &encrypted[0..32];
            let n = u32::from_le_bytes(encrypted[32..36].try_into().unwrap());
            let p = u32::from_le_bytes(encrypted[36..40].try_into().unwrap());
            let r = u32::from_le_bytes(encrypted[40..44].try_into().unwrap());
            let log_n: u8 = n.ilog2() as u8;

            let params = ScryptParams::new(log_n, r, p, 32).map_err(|e| e.to_string())?;
            let mut derived_key = vec![0u8; 32];
            scrypt(passphrase.as_bytes(), salt, &params, &mut derived_key)
                .map_err(|e| e.to_string())?;
            encrypted = encrypted[44..].to_vec();
            derived_key
        } else {
            let mut derived_key = passphrase.as_bytes().to_vec();
            derived_key = pad_right(derived_key, 32, 0x00);
            derived_key
        };

        let nonce_bytes = &encrypted[0..24];
        let nonce = Nonce::from_slice(nonce_bytes)
            .ok_or("Invalid nonce length")
            .map_err(|e| e.to_string())?;
        let message = &encrypted[24..];

        let key = Key::from_slice(&password).ok_or("Invalid key length")?;
        let decrypted_data = secretbox::open(message, &nonce, &key)
            .map_err(|_| "Failed to decrypt data".to_string())?;
        let (private_key, public_key) =
            decode_pkcs8(&decrypted_data).map_err(|_| "Failed to decode PKCS8 data".to_string())?;

        let (secret, converted_public_key) =
            pair_from_ed25519_secret_key(&private_key[..], &public_key[..]);

        let keypair = match json_data.encoding.content.iter().any(|c| c == "sr25519") {
            true => {
                assert_eq!(public_key, converted_public_key);
                Keypair::create_from_private_key(&hex::encode(secret))
            }
            _ => return Err("Unsupported keypair type.".to_string()),
        };

        keypair
    }

    /// Creates a Keypair from a URI string.
    ///
    ///     Arguments:
    ///         uri (str): The URI string to create the keypair from.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the URI.
    pub fn create_from_uri(uri: &str) -> Result<Self, String> {
        let pair = Pair::from_string(uri, None).map_err(|e| e.to_string())?;

        let kp = Keypair {
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Signs data with the keypair's private key.
    ///
    ///     Arguments:
    ///         data (Vec<u8>): The data to sign as bytes.
    ///     Returns:
    ///         signature (Vec<u8>): The signature as bytes.
    pub fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, String> {
        // Check if private key exists
        let pair = self
            .pair
            .as_ref()
            .ok_or_else(|| "No private key set to create signatures".to_string())?;

        // Generate a signature depending on the type of cryptographic key
        let signature = match self.crypto_type {
            1 => {
                // SR25519
                pair.sign(&data)
            }
            _ => {
                return Err("Crypto type not supported.".to_string());
            }
        };

        Ok(signature.to_vec())
    }

    /// Verifies a signature against data using the keypair's public key.
    ///
    ///     Arguments:
    ///         data (Vec<u8>): The data that was signed as bytes.
    ///         signature (Vec<u8>): The signature to verify as bytes.
    ///     Returns:
    ///         verified (bool): ``True`` if the signature is valid, ``False`` otherwise.
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
        // Check if public key exists
        let public_key = if let Some(public_key_str) = &self.public_key {
            hex::decode(public_key_str.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid `public_key` string: {:?}", e))?
        } else if let Some(pair) = &self.pair {
            pair.public().to_vec()
        } else {
            return Err("No public key or pair available.".to_string());
        };

        let public = sr25519::Public::from_raw(
            <[u8; 32]>::try_from(public_key)
                .map_err(|e| format!("Invalid public key length: {:?}", e))?,
        );

        // Convert signature bytes to the type expected by the verify function
        let signature = sr25519::Signature::from_slice(&signature)
            .map_err(|_| "Invalid signature".to_string())?;

        // Verify signature depending on the type of crypto key
        let verified = match self.crypto_type {
            1 => {
                // SR25519
                sr25519::Pair::verify(&signature, &data, &public)
            }
            _ => {
                return Err("Crypto type not supported".to_string());
            }
        };

        // If not verified, try to verify with data wrapper
        if !verified {
            let wrapped_data = [b"<Bytes>", data.as_slice(), b"</Bytes>"].concat();
            let verified_wrapped = match self.crypto_type {
                1 => {
                    // SR25519
                    sr25519::Pair::verify(&signature, wrapped_data, &public)
                }
                _ => {
                    return Err("Crypto type not supported".to_string());
                }
            };

            Ok(verified_wrapped)
        } else {
            Ok(verified)
        }
    }

    /// Returns the SS58 address of the keypair.
    pub fn ss58_address(&self) -> Option<String> {
        match &self.pair {
            Some(pair) => {
                let ss58_address = pair.public().to_ss58check();
                Some(ss58_address)
            }
            None => self.ss58_address.clone(),
        }
    }

    /// Returns the public key of the keypair as bytes.
    pub fn public_key(&self) -> Result<Option<Vec<u8>>, String> {
        if let Some(pair) = &self.pair {
            let public_key_vec = pair.public().to_vec();
            Ok(Some(public_key_vec))
        } else if let Some(public_key) = &self.public_key {
            let public_key_vec = hex::decode(public_key.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid `public_key` string: {}", e))?;
            Ok(Some(public_key_vec))
        } else {
            Ok(None)
        }
    }

    /// Returns the SS58 format number.
    pub fn ss58_format(&self) -> u8 {
        self.ss58_format
    }

    pub fn seed_hex(&self) -> Option<Vec<u8>> {
        self.seed_hex.clone()
    }

    /// Returns the cryptographic algorithm type.
    pub fn crypto_type(&self) -> u8 {
        self.crypto_type
    }

    /// Sets the cryptographic algorithm type.
    ///
    ///     Arguments:
    ///         crypto_type (u8): The cryptographic algorithm type (1 for SR25519).
    pub fn set_crypto_type(&mut self, crypto_type: u8) {
        self.crypto_type = crypto_type;
    }

    /// Returns the mnemonic phrase of the keypair.
    pub fn mnemonic(&self) -> Option<String> {
        self.mnemonic.clone()
    }

    /// Returns the private key of the keypair as bytes.
    pub fn private_key(&self) -> Result<Option<Vec<u8>>, String> {
        match &self.pair {
            Some(pair) => {
                let seed = pair.to_raw_vec();
                Ok(Some(seed))
            }
            None => {
                if let Some(private_key) = &self.private_key {
                    Ok(Some(private_key.as_bytes().to_vec()))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

// Default values for Keypair
impl Default for Keypair {
    fn default() -> Self {
        Keypair {
            ss58_address: None,
            public_key: None,
            private_key: None,
            ss58_format: 42,
            seed_hex: None,
            crypto_type: 1,
            mnemonic: None,
            pair: None,
        }
    }
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = self.ss58_address();
        match address {
            Some(addr) => write!(f, "<Keypair (address={})>", addr),
            None => write!(f, "<Keypair (address=None)>"),
        }
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = self.ss58_address();
        match address {
            Some(addr) => write!(f, "<Keypair (address={})>", addr),
            None => write!(f, "<Keypair (address=None)>"),
        }
    }
}
