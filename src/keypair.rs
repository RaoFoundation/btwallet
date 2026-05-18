use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use schnorrkel::{PublicKey, SecretKey};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::{ed25519, sr25519, ByteArray, Pair};
use std::fmt;

use crate::constants::{CRYPTO_ED25519, CRYPTO_SR25519};

const PKCS8_HEADER: &[u8] = &[48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const PKCS8_DIVIDER: &[u8] = &[161, 35, 3, 33, 0];
const SEC_LENGTH: usize = 64;
const PUB_LENGTH: usize = 32;

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PairInner {
    Sr25519(sr25519::Pair),
    Ed25519(ed25519::Pair),
}

impl PairInner {
    pub fn public_bytes(&self) -> [u8; 32] {
        match self {
            Self::Sr25519(p) => p.public().0,
            Self::Ed25519(p) => p.public().0,
        }
    }

    pub fn ss58_address(&self) -> String {
        AccountId32::from(self.public_bytes()).to_ss58check()
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sr25519(p) => p.sign(data).0.to_vec(),
            Self::Ed25519(p) => p.sign(data).0.to_vec(),
        }
    }

    pub fn to_raw_vec(&self) -> Vec<u8> {
        match self {
            Self::Sr25519(p) => p.to_raw_vec(),
            Self::Ed25519(p) => p.to_raw_vec(),
        }
    }

    pub fn crypto_type(&self) -> u8 {
        match self {
            Self::Sr25519(_) => CRYPTO_SR25519,
            Self::Ed25519(_) => CRYPTO_ED25519,
        }
    }
}

fn verify_signature(
    crypto_type: u8,
    public_key_bytes: &[u8; 32],
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    match crypto_type {
        CRYPTO_SR25519 => {
            let public = sr25519::Public::from_raw(*public_key_bytes);
            let signature = sr25519::Signature::from_slice(signature_bytes)
                .map_err(|_| "Invalid SR25519 signature.".to_string())?;
            Ok(sr25519::Pair::verify(&signature, data, &public))
        }
        CRYPTO_ED25519 => {
            let public = ed25519::Public::from_raw(*public_key_bytes);
            let signature = ed25519::Signature::from_slice(signature_bytes)
                .map_err(|_| "Invalid ED25519 signature.".to_string())?;
            Ok(ed25519::Pair::verify(&signature, data, &public))
        }
        _ => Err(format!("Unsupported crypto type: {}.", crypto_type)),
    }
}

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
    pair: Option<PairInner>,
}

impl Keypair {
    /// Returns whether this keypair has an active key pair.
    pub fn pair_is_some(&self) -> bool {
        self.pair.is_some()
    }

    /// Used by the Python binding setter (`keypair.crypto_type = ...`) for pub-only keypairs.
    #[allow(dead_code)]
    pub(crate) fn set_crypto_type_field(&mut self, crypto_type: u8) {
        self.crypto_type = crypto_type;
    }

    /// Creates a new Keypair instance.
    ///
    /// ```text
    ///     Arguments:
    ///         ss58_address (Option<String>): Optional SS58-formatted address.
    ///         public_key (Option<String>): Optional public key as hex string.
    ///         private_key (Option<String>): Optional private key as hex string.
    ///         ss58_format (u8): The SS58 format number for address encoding.
    ///         seed_hex (Option<Vec<u8>>): Optional seed bytes.
    ///         crypto_type (u8): The cryptographic algorithm type. 0 for ED25519, 1 for SR25519.
    ///     Returns:
    ///         keypair (Keypair): A new Keypair instance.
    /// ```
    pub fn new(
        ss58_address: Option<String>,
        public_key: Option<String>,
        private_key: Option<String>,
        ss58_format: u8,
        seed_hex: Option<Vec<u8>>,
        crypto_type: u8,
    ) -> Result<Self, String> {
        match crypto_type {
            CRYPTO_SR25519 | CRYPTO_ED25519 => {}
            _ => return Err(format!("Unsupported crypto type: {}.", crypto_type)),
        }

        let mut ss58_address_res = ss58_address.clone();
        let mut public_key_res = public_key;

        if let Some(private_key_str) = &private_key {
            let private_key_bytes =
                hex::decode(private_key_str.trim_start_matches("0x")).expect("");

            let expected_len = match crypto_type {
                CRYPTO_SR25519 => 64,
                CRYPTO_ED25519 => 32,
                _ => unreachable!(),
            };
            if private_key_bytes.len() != expected_len {
                return Err(format!("Secret key should be {} bytes long.", expected_len));
            }
        }

        if let Some(public_key_str) = &public_key_res {
            let public_key_vec = hex::decode(public_key_str.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid `public_key` string: {}", e))?;

            let public_key_array: [u8; 32] = public_key_vec
                .try_into()
                .map_err(|_| "Public key must be 32 bytes long.")?;

            let account_id = AccountId32::from(public_key_array);
            ss58_address_res = Some(account_id.to_ss58check());
        }

        if let Some(ss58_address_str) = ss58_address.clone() {
            let (account_id, _) = AccountId32::from_ss58check_with_version(&ss58_address_str)
                .map_err(|e| format!("Invalid SS58 address: {:?}", e))?;
            public_key_res = Some(hex::encode(<AccountId32 as AsRef<[u8; 32]>>::as_ref(
                &account_id,
            )));
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
    /// ```text
    ///     Arguments:
    ///         n_words (usize): The number of words in the mnemonic (e.g., 12, 15, 18, 21, 24).
    ///     Returns:
    ///         mnemonic (String): The generated mnemonic phrase.
    /// ```
    pub fn generate_mnemonic(n_words: usize) -> Result<String, String> {
        let mnemonic = Mnemonic::generate(n_words).map_err(|e| e.to_string())?;
        Ok(mnemonic.to_string())
    }

    /// Creates a Keypair from a mnemonic phrase.
    ///
    /// ```text
    ///     Arguments:
    ///         mnemonic (str): The mnemonic phrase to create the keypair from.
    ///         crypto_type (u8): The cryptographic algorithm type. 0 for ED25519, 1 for SR25519.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the mnemonic.
    /// ```
    pub fn create_from_mnemonic(mnemonic: &str, crypto_type: u8) -> Result<Self, String> {
        let (pair_inner, seed_vec) = match crypto_type {
            CRYPTO_SR25519 => {
                let (pair, seed) =
                    sr25519::Pair::from_phrase(mnemonic, None).map_err(|e| e.to_string())?;
                (PairInner::Sr25519(pair), seed.to_vec())
            }
            CRYPTO_ED25519 => {
                let (pair, seed) =
                    ed25519::Pair::from_phrase(mnemonic, None).map_err(|e| e.to_string())?;
                (PairInner::Ed25519(pair), seed.to_vec())
            }
            _ => return Err(format!("Unsupported crypto type: {}.", crypto_type)),
        };

        Ok(Keypair {
            mnemonic: Some(mnemonic.to_string()),
            seed_hex: Some(seed_vec),
            pair: Some(pair_inner),
            crypto_type,
            ..Default::default()
        })
    }

    /// Creates a Keypair from a seed.
    ///
    /// ```text
    ///     Arguments:
    ///         seed (Vec<u8>): The seed bytes to create the keypair from.
    ///         crypto_type (u8): The cryptographic algorithm type. 0 for ED25519, 1 for SR25519.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the seed.
    /// ```
    pub fn create_from_seed(seed: Vec<u8>, crypto_type: u8) -> Result<Self, String> {
        let pair_inner = match crypto_type {
            CRYPTO_SR25519 => {
                let pair = sr25519::Pair::from_seed_slice(&seed)
                    .map_err(|e| format!("Failed to create SR25519 pair from seed: {}", e))?;
                PairInner::Sr25519(pair)
            }
            CRYPTO_ED25519 => {
                let pair = ed25519::Pair::from_seed_slice(&seed)
                    .map_err(|e| format!("Failed to create ED25519 pair from seed: {}", e))?;
                PairInner::Ed25519(pair)
            }
            _ => return Err(format!("Unsupported crypto type: {}.", crypto_type)),
        };

        Ok(Keypair {
            seed_hex: Some(seed),
            pair: Some(pair_inner),
            crypto_type,
            ..Default::default()
        })
    }

    /// Creates a Keypair from a private key.
    ///
    /// ```text
    ///     Arguments:
    ///         private_key (str): The private key as hex string to create the keypair from.
    ///         crypto_type (u8): The cryptographic algorithm type. 0 for ED25519, 1 for SR25519.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the private key.
    /// ```
    pub fn create_from_private_key(private_key: &str, crypto_type: u8) -> Result<Self, String> {
        let private_key_vec = hex::decode(private_key.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid `private_key` string: {}", e))?;

        let pair_inner = match crypto_type {
            CRYPTO_SR25519 => {
                let pair = sr25519::Pair::from_seed_slice(&private_key_vec).map_err(|e| {
                    format!("Failed to create SR25519 pair from private key: {}", e)
                })?;
                PairInner::Sr25519(pair)
            }
            CRYPTO_ED25519 => {
                let pair = ed25519::Pair::from_seed_slice(&private_key_vec).map_err(|e| {
                    format!("Failed to create ED25519 pair from private key: {}", e)
                })?;
                PairInner::Ed25519(pair)
            }
            _ => return Err(format!("Unsupported crypto type: {}.", crypto_type)),
        };

        Ok(Keypair {
            pair: Some(pair_inner),
            crypto_type,
            ..Default::default()
        })
    }

    /// Creates a Keypair from encrypted JSON data.
    ///
    /// ```text
    ///     Arguments:
    ///         json_data (str): The encrypted JSON data containing the keypair.
    ///         passphrase (str): The passphrase to decrypt the JSON data.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the encrypted JSON.
    /// ```
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

        if json_data.encoding.content.iter().any(|c| c == "sr25519") {
            assert_eq!(public_key, converted_public_key);
            Keypair::create_from_private_key(&hex::encode(secret), CRYPTO_SR25519)
        } else if json_data.encoding.content.iter().any(|c| c == "ed25519") {
            let seed = &private_key[..32];
            let pair = ed25519::Pair::from_seed_slice(seed)
                .map_err(|e| format!("Failed to create ED25519 pair: {}", e))?;
            if pair.public().0 != public_key {
                return Err("ED25519 public key mismatch in JSON.".to_string());
            }
            Ok(Keypair {
                pair: Some(PairInner::Ed25519(pair)),
                crypto_type: CRYPTO_ED25519,
                ..Default::default()
            })
        } else {
            Err("Unsupported keypair type.".to_string())
        }
    }

    /// Creates a Keypair from a URI string.
    ///
    /// ```text
    ///     Arguments:
    ///         uri (str): The URI string to create the keypair from.
    ///         crypto_type (u8): The cryptographic algorithm type. 0 for ED25519, 1 for SR25519.
    ///     Returns:
    ///         keypair (Keypair): The Keypair created from the URI.
    /// ```
    pub fn create_from_uri(uri: &str, crypto_type: u8) -> Result<Self, String> {
        let pair_inner = match crypto_type {
            CRYPTO_SR25519 => {
                let pair = sr25519::Pair::from_string(uri, None).map_err(|e| e.to_string())?;
                PairInner::Sr25519(pair)
            }
            CRYPTO_ED25519 => {
                let pair = ed25519::Pair::from_string(uri, None).map_err(|e| e.to_string())?;
                PairInner::Ed25519(pair)
            }
            _ => return Err(format!("Unsupported crypto type: {}.", crypto_type)),
        };

        Ok(Keypair {
            pair: Some(pair_inner),
            crypto_type,
            ..Default::default()
        })
    }

    /// Signs data with the keypair's private key.
    ///
    /// ```text
    ///     Arguments:
    ///         data (Vec<u8>): The data to sign as bytes.
    ///     Returns:
    ///         signature (Vec<u8>): The signature as bytes.
    /// ```
    pub fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let pair = self
            .pair
            .as_ref()
            .ok_or_else(|| "No private key set to create signatures.".to_string())?;

        Ok(pair.sign(&data))
    }

    /// Verifies a signature against data using the keypair's public key.
    ///
    /// ```text
    ///     Arguments:
    ///         data (Vec<u8>): The data that was signed as bytes.
    ///         signature (Vec<u8>): The signature to verify as bytes.
    ///     Returns:
    ///         verified (bool): ``True`` if the signature is valid, ``False`` otherwise.
    /// ```
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
        let public_key_bytes = self.public_key_bytes()?;
        let ct = self.crypto_type();

        let verified = verify_signature(ct, &public_key_bytes, &data, &signature)?;
        if verified {
            return Ok(true);
        }

        let wrapped_data = [b"<Bytes>", data.as_slice(), b"</Bytes>"].concat();
        verify_signature(ct, &public_key_bytes, &wrapped_data, &signature)
    }

    fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        if let Some(pair) = &self.pair {
            Ok(pair.public_bytes())
        } else if let Some(public_key_str) = &self.public_key {
            let bytes = hex::decode(public_key_str.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid `public_key` string: {:?}", e))?;
            <[u8; 32]>::try_from(bytes).map_err(|_| "Public key must be 32 bytes.".to_string())
        } else {
            Err("No public key or pair available.".to_string())
        }
    }

    /// Returns the SS58 address of the keypair.
    pub fn ss58_address(&self) -> Option<String> {
        match &self.pair {
            Some(pair) => Some(pair.ss58_address()),
            None => self.ss58_address.clone(),
        }
    }

    /// Returns the public key of the keypair as bytes.
    pub fn public_key(&self) -> Result<Option<Vec<u8>>, String> {
        if let Some(pair) = &self.pair {
            Ok(Some(pair.public_bytes().to_vec()))
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
    /// Derives from the inner pair if present; falls back to the stored field for pub-only keypairs.
    pub fn crypto_type(&self) -> u8 {
        match &self.pair {
            Some(pair) => pair.crypto_type(),
            None => self.crypto_type,
        }
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

impl Default for Keypair {
    fn default() -> Self {
        Keypair {
            ss58_address: None,
            public_key: None,
            private_key: None,
            ss58_format: 42,
            seed_hex: None,
            crypto_type: CRYPTO_SR25519,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mnemonic() -> String {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .to_string()
    }

    // --- Creation tests ---

    #[test]
    fn test_sr25519_from_mnemonic_produces_valid_keypair() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        assert_eq!(kp.crypto_type(), CRYPTO_SR25519);
        let pk = kp.public_key().unwrap().unwrap();
        assert_eq!(pk.len(), 32);
        assert!(kp.ss58_address().is_some());
        assert!(kp.ss58_address().unwrap().starts_with('5'));
    }

    #[test]
    fn test_ed25519_from_mnemonic_produces_valid_keypair() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        assert_eq!(kp.crypto_type(), CRYPTO_ED25519);
        let pk = kp.public_key().unwrap().unwrap();
        assert_eq!(pk.len(), 32);
        let priv_key = kp.private_key().unwrap().unwrap();
        assert_eq!(priv_key.len(), 32);
        assert!(kp.ss58_address().is_some());
        assert!(kp.ss58_address().unwrap().starts_with('5'));
    }

    #[test]
    fn test_same_mnemonic_different_crypto_produces_different_addresses() {
        let sr = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        let ed = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        assert_ne!(sr.ss58_address(), ed.ss58_address());
        assert_ne!(
            sr.public_key().unwrap().unwrap(),
            ed.public_key().unwrap().unwrap()
        );
    }

    #[test]
    fn test_ed25519_from_seed_accepts_32_bytes() {
        let result = Keypair::create_from_seed([1u8; 32].to_vec(), CRYPTO_ED25519);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_from_seed_rejects_64_bytes() {
        let result = Keypair::create_from_seed([1u8; 64].to_vec(), CRYPTO_ED25519);
        assert!(result.is_err());
    }

    #[test]
    fn test_sr25519_from_seed_accepts_32_and_64_bytes() {
        assert!(Keypair::create_from_seed([1u8; 32].to_vec(), CRYPTO_SR25519).is_ok());
        assert!(Keypair::create_from_seed([1u8; 64].to_vec(), CRYPTO_SR25519).is_ok());
    }

    #[test]
    fn test_ed25519_from_uri_hard_derivation() {
        let kp = Keypair::create_from_uri("//Alice", CRYPTO_ED25519).unwrap();
        assert!(kp.ss58_address().is_some());
        assert_eq!(kp.crypto_type(), CRYPTO_ED25519);
    }

    #[test]
    fn test_invalid_crypto_type_rejected() {
        assert!(Keypair::create_from_mnemonic(&test_mnemonic(), 2).is_err());
        assert!(Keypair::create_from_mnemonic(&test_mnemonic(), 255).is_err());
        assert!(Keypair::new(
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string()),
            None,
            None,
            42,
            None,
            5
        )
        .is_err());
    }

    #[test]
    fn test_sr25519_alice_known_address() {
        let kp = Keypair::create_from_uri("//Alice", CRYPTO_SR25519).unwrap();
        assert_eq!(
            kp.ss58_address().unwrap(),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
    }

    // --- Sign/Verify tests ---

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let sig = kp.sign(b"hello".to_vec()).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(kp.verify(b"hello".to_vec(), sig).unwrap());
    }

    #[test]
    fn test_ed25519_verify_wrong_data() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let sig = kp.sign(b"hello".to_vec()).unwrap();
        assert!(!kp.verify(b"world".to_vec(), sig).unwrap());
    }

    #[test]
    fn test_ed25519_verify_bytes_wrapping() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let sig = kp.sign(b"<Bytes>hello</Bytes>".to_vec()).unwrap();
        assert!(kp.verify(b"hello".to_vec(), sig).unwrap());
    }

    #[test]
    fn test_sr25519_sign_verify_unchanged() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        let sig = kp.sign(b"hello".to_vec()).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(kp.verify(b"hello".to_vec(), sig).unwrap());
    }

    #[test]
    fn test_cross_type_verification_fails() {
        let sr = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        let ed = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let sig = sr.sign(b"hello".to_vec()).unwrap();
        assert!(!ed.verify(b"hello".to_vec(), sig).unwrap());
    }

    // --- Keypair::new() pub-only tests ---

    #[test]
    fn test_new_ed25519_pubonly_from_ss58() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let addr = kp.ss58_address().unwrap();

        let pub_kp =
            Keypair::new(Some(addr.clone()), None, None, 42, None, CRYPTO_ED25519).unwrap();
        assert_eq!(pub_kp.ss58_address().unwrap(), addr);
        assert_eq!(pub_kp.crypto_type(), CRYPTO_ED25519);
    }

    #[test]
    fn test_pair_is_some() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        assert!(kp.pair_is_some());

        let pub_kp = Keypair::new(
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string()),
            None,
            None,
            42,
            None,
            CRYPTO_SR25519,
        )
        .unwrap();
        assert!(!pub_kp.pair_is_some());
    }

    // --- crypto_type getter tests ---

    #[test]
    fn test_crypto_type_derived_from_pair() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        assert_eq!(kp.crypto_type(), CRYPTO_ED25519);

        let kp2 = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        assert_eq!(kp2.crypto_type(), CRYPTO_SR25519);
    }

    #[test]
    fn test_crypto_type_from_field_for_pubonly() {
        let pub_kp = Keypair::new(
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string()),
            None,
            None,
            42,
            None,
            CRYPTO_ED25519,
        )
        .unwrap();
        assert_eq!(pub_kp.crypto_type(), CRYPTO_ED25519);
    }

    // --- Private key creation tests ---

    #[test]
    fn test_ed25519_from_private_key_32_bytes() {
        let hex_key = hex::encode([1u8; 32]);
        let kp = Keypair::create_from_private_key(&hex_key, CRYPTO_ED25519).unwrap();
        assert_eq!(kp.crypto_type(), CRYPTO_ED25519);
        assert!(kp.ss58_address().is_some());
    }

    #[test]
    fn test_ed25519_from_private_key_64_bytes_rejected() {
        let hex_key = hex::encode([1u8; 64]);
        let result = Keypair::create_from_private_key(&hex_key, CRYPTO_ED25519);
        assert!(result.is_err());
    }

    #[test]
    fn test_sr25519_from_private_key_64_bytes() {
        let hex_key = hex::encode([1u8; 64]);
        let kp = Keypair::create_from_private_key(&hex_key, CRYPTO_SR25519).unwrap();
        assert_eq!(kp.crypto_type(), CRYPTO_SR25519);
        assert!(kp.ss58_address().is_some());
    }

    // --- Determinism ---

    #[test]
    fn test_ed25519_mnemonic_determinism() {
        let kp1 = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let kp2 = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        assert_eq!(kp1.ss58_address(), kp2.ss58_address());
        assert_eq!(
            kp1.public_key().unwrap().unwrap(),
            kp2.public_key().unwrap().unwrap()
        );
    }

    // --- Pub-only verification ---

    #[test]
    fn test_ed25519_pubonly_can_verify() {
        let full = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_ED25519).unwrap();
        let sig = full.sign(b"test-message".to_vec()).unwrap();
        let addr = full.ss58_address().unwrap();

        let pub_only = Keypair::new(Some(addr), None, None, 42, None, CRYPTO_ED25519).unwrap();
        assert!(pub_only.verify(b"test-message".to_vec(), sig).unwrap());
    }

    // --- SR25519 Bytes wrapping (mirror of ED25519 test) ---

    #[test]
    fn test_sr25519_verify_bytes_wrapping() {
        let kp = Keypair::create_from_mnemonic(&test_mnemonic(), CRYPTO_SR25519).unwrap();
        let sig = kp.sign(b"<Bytes>hello</Bytes>".to_vec()).unwrap();
        assert!(kp.verify(b"hello".to_vec(), sig).unwrap());
    }

    // --- Default ---

    #[test]
    fn test_default_crypto_type_is_sr25519() {
        let kp = Keypair::default();
        assert_eq!(kp.crypto_type(), CRYPTO_SR25519);
    }
}
