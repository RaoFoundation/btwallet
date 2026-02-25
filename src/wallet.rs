use colored::Colorize;
use std::path::PathBuf;
use std::{env, fmt};

use crate::config::Config;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::errors::*;
use crate::keyfile::Keyfile;
use crate::keypair::Keypair;
use crate::utils::{self, is_valid_bittensor_address_or_public_key};

/// Display the mnemonic and a warning message to keep the mnemonic safe.
///
///     Arguments:
///         mnemonic (str): The mnemonic phrase to display.
///         key_type (str): The type of key e.g. "coldkey" or "hotkey".
pub fn display_mnemonic_msg(mnemonic: String, key_type: &str) {
    utils::print(format!("{}", "\nIMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.\n".red()));

    utils::print(format!(
        "\nThe mnemonic to the new {} is: {}",
        key_type.blue(),
        mnemonic.green()
    ));
    utils::print(format!(
        "\nYou can use the mnemonic to recreate the key with `{}` in case it gets lost.\n",
        "btcli".green()
    ));
}

#[derive(Clone)]
pub struct Wallet {
    pub name: String,
    pub path: String,
    pub hotkey: String,

    _path: PathBuf,

    _coldkey: Option<Keypair>,
    _coldkeypub: Option<Keypair>,
    _hotkey: Option<Keypair>,
    _hotkeypub: Option<Keypair>,
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wallet (Name: '{:}', Hotkey: '{:}', Path: '{:}')",
            self.name, self.hotkey, self.path
        )
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name: '{:?}', hotkey: '{:?}', path: '{:?}'",
            self.name, self.hotkey, self.path
        )
    }
}

impl Wallet {
    /// Initialize the bittensor wallet object containing a hot and coldkey.
    ///
    ///     Arguments:
    ///         name (Optional[str]): The name of the wallet. Defaults to "default".
    ///         hotkey (Optional[str]): The name of hotkey. Defaults to "default".
    ///         path (Optional[str]): The path to wallets. Defaults to "~/.bittensor/wallets/".
    ///         config (Optional[Config]): Optional configuration.
    ///
    ///     Returns:
    ///         `Wallet` - A new Wallet instance.
    pub fn new(
        name: Option<String>,
        hotkey: Option<String>,
        path: Option<String>,
        config: Option<Config>,
    ) -> Self {
        let final_name = name
            .or(config.as_ref().map(|conf| conf.name()))
            .unwrap_or(BT_WALLET_NAME.to_string());

        let final_hotkey = hotkey
            .or(config.as_ref().map(|conf| conf.hotkey()))
            .unwrap_or(BT_WALLET_HOTKEY.to_string());

        let final_path = path
            .or(config.as_ref().map(|conf| conf.path()))
            .unwrap_or(BT_WALLET_PATH.to_string());

        let expanded_path = PathBuf::from(shellexpand::tilde(&final_path).to_string());

        Wallet {
            name: final_name,
            hotkey: final_hotkey,
            path: final_path,
            _path: expanded_path,
            _coldkey: None,
            _coldkeypub: None,
            _hotkey: None,
            _hotkeypub: None,
        }
    }

    /// Get default config
    pub fn config() -> Config {
        Config::new(None, None, None)
    }

    /// Print help information
    pub fn help() -> Config {
        unimplemented!()
    }

    // TODO: What are the prefixes for ?
    pub fn add_args(parser: clap::Command, _prefix: Option<&str>) -> clap::Command {
        let default_name =
            env::var("BT_WALLET_NAME").unwrap_or_else(|_| BT_WALLET_NAME.to_string());
        let default_name_static: &'static str = Box::leak(default_name.into_boxed_str());

        let parser = parser.arg(
            clap::Arg::new("wallet.name")
                .long("wallet.name")
                .default_value(default_name_static)
                .help("The name of the wallet to unlock for running Bittensor"),
        );

        let default_hotkey =
            env::var("BT_WALLET_HOTKEY").unwrap_or_else(|_| BT_WALLET_HOTKEY.to_string());
        let default_hotkey_static: &'static str = Box::leak(default_hotkey.into_boxed_str());

        let parser = parser.arg(
            clap::Arg::new("wallet.hotkey")
                .long("wallet.hotkey")
                .default_value(default_hotkey_static)
                .help("The name of the wallet's hotkey"),
        );

        let default_path =
            env::var("BT_WALLET_PATH").unwrap_or_else(|_| BT_WALLET_PATH.to_string());
        let default_path_static: &'static str = Box::leak(default_path.into_boxed_str());

        parser.arg(
            clap::Arg::new("wallet.path")
                .long("wallet.path")
                .default_value(default_path_static)
                .help("The path to your Bittensor wallets"),
        )
    }

    /// Checks for existing coldkeypub, hotkeypub, hotkeys, and creates them if non-existent.
    ///
    ///     Arguments:
    ///         coldkey_use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         hotkey_use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save a coldkey password to local env. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save a hotkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``. If `coldkey_password` is passed, then `coldkey_use_password` is automatically ``True``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``. If `hotkey_password` is passed, then `hotkey_use_password` is automatically ``True``.
    ///         overwrite (bool): Whether to overwrite an existing keys. Defaults to ``False``.
    ///         suppress (bool): If ``True``, suppresses the display of the keys mnemonic message. Defaults to ``False``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created keys.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    #[allow(clippy::too_many_arguments)]
    pub fn create_if_non_existent(
        &mut self,
        coldkey_use_password: bool,
        hotkey_use_password: bool,
        save_coldkey_to_env: bool,
        save_hotkey_to_env: bool,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: bool,
        suppress: bool,
    ) -> Result<Self, WalletError> {
        self.create(
            coldkey_use_password,
            hotkey_use_password,
            save_coldkey_to_env,
            save_hotkey_to_env,
            coldkey_password,
            hotkey_password,
            overwrite,
            suppress,
        )
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    ///
    ///     Arguments:
    ///         coldkey_use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         hotkey_use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save a coldkey password to local env. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save a hotkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``. If `coldkey_password` is passed, then `coldkey_use_password` is automatically ``True``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``. If `hotkey_password` is passed, then `hotkey_use_password` is automatically ``True``.
    ///         overwrite (bool): Whether to overwrite an existing keys. Defaults to ``False``.
    ///         suppress (bool): If ``True``, suppresses the display of the keys mnemonic message. Defaults to ``False``.
    ///
    ///     Returns:
    ///         Wallet instance with created keys.
    ///
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    #[allow(clippy::bool_comparison, clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        coldkey_use_password: bool,
        hotkey_use_password: bool,
        save_coldkey_to_env: bool,
        save_hotkey_to_env: bool,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: bool,
        suppress: bool,
    ) -> Result<Self, WalletError> {
        if overwrite
            || (!self.coldkey_file()?.exists_on_device()?
                && !self.coldkeypub_file()?.exists_on_device()?)
        {
            self.create_new_coldkey(
                12,
                coldkey_use_password,
                overwrite,
                suppress,
                save_coldkey_to_env,
                coldkey_password,
            )?;
        } else {
            println!("ColdKey for the wallet '{}' already exists.", self.name);
        }

        if overwrite
            || !self.hotkey_file()?.exists_on_device()?
                && !self.hotkeypub_file()?.exists_on_device()?
        {
            self.create_new_hotkey(
                12,
                hotkey_use_password,
                overwrite,
                suppress,
                save_hotkey_to_env,
                hotkey_password,
            )?;
        } else {
            println!("HotKey for the wallet '{}' already exists.", self.name);
        }

        Ok(self.clone())
    }

    /// Checks for existing coldkeypub and hotkeys, and recreates them if non-existent.
    ///
    ///     Arguments:
    ///         coldkey_use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         hotkey_use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save a coldkey password to local env. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save a hotkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``. If `coldkey_password` is passed, then `coldkey_use_password` is automatically ``True``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``. If `hotkey_password` is passed, then `hotkey_use_password` is automatically ``True``.
    ///         overwrite (bool): Whether to overwrite an existing keys. Defaults to ``False``.
    ///         suppress (bool): If ``True``, suppresses the display of the keys mnemonic message. Defaults to ``False``.
    ///
    ///     Returns:
    ///         Wallet instance with created keys.
    ///
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    #[allow(clippy::too_many_arguments)]
    pub fn recreate(
        &mut self,
        coldkey_use_password: bool,
        hotkey_use_password: bool,
        save_coldkey_to_env: bool,
        save_hotkey_to_env: bool,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: bool,
        suppress: bool,
    ) -> Result<Self, WalletError> {
        self.create_new_coldkey(
            12,
            coldkey_use_password,
            overwrite,
            suppress,
            save_coldkey_to_env,
            coldkey_password,
        )?;
        self.create_new_hotkey(
            12,
            hotkey_use_password,
            overwrite,
            suppress,
            save_hotkey_to_env,
            hotkey_password,
        )?;

        Ok(self.clone())
    }

    /// Returns the hotkey file.
    pub fn hotkey_file(&self) -> Result<Keyfile, KeyFileError> {
        self.create_hotkey_file(false)
    }

    /// Creates a new hotkey file for the keypair.
    ///
    ///     Arguments:
    ///         save_hotkey_to_env (bool): Whether to save hotkey password to local env. Defaults to ``False``.
    ///
    ///     Returns:
    ///         `Keyfile` - The created hotkey file.
    ///     Raises:
    ///         KeyFileError: If file creation fails.
    pub fn create_hotkey_file(&self, save_hotkey_to_env: bool) -> Result<Keyfile, KeyFileError> {
        // concatenate wallet path
        let wallet_path = self._path.join(&self.name);

        // concatenate hotkey path
        let hotkey_path = wallet_path.join("hotkeys").join(&self.hotkey);

        Keyfile::new(
            hotkey_path.to_string_lossy().into_owned(),
            Some(self.hotkey.clone()),
            save_hotkey_to_env,
        )
    }

    /// Returns the coldkey file.
    pub fn coldkey_file(&self) -> Result<Keyfile, KeyFileError> {
        self.create_coldkey_file(false)
    }

    /// Creates a new coldkey file for the keypair.
    ///
    ///     Arguments:
    ///         save_coldkey_to_env (bool): Whether to save coldkey password to local env. Defaults to ``False``.
    ///
    ///     Returns:
    ///         `Keyfile` - The created coldkey file.
    ///     Raises:
    ///         KeyFileError: If file creation fails.
    pub fn create_coldkey_file(&self, save_coldkey_to_env: bool) -> Result<Keyfile, KeyFileError> {
        // concatenate wallet path
        let wallet_path = PathBuf::from(&self._path).join(&self.name);

        // concatenate coldkey path
        let coldkey_path = wallet_path.join("coldkey");
        Keyfile::new(
            coldkey_path.to_string_lossy().into_owned(),
            Some("coldkey".to_string()),
            save_coldkey_to_env,
        )
    }

    /// Returns the hotkeypub file.
    pub fn hotkeypub_file(&self) -> Result<Keyfile, KeyFileError> {
        // concatenate wallet path
        let wallet_path = self._path.join(&self.name);
        let hotkeypub_name = format!("{}pub.txt", self.hotkey);
        // concatenate hotkeypub path
        let hotkeypub_path = wallet_path.join("hotkeys").join(&hotkeypub_name);

        Keyfile::new(
            hotkeypub_path.to_string_lossy().into_owned(),
            Some(hotkeypub_name),
            false,
        )
    }

    /// Returns the coldkeypub file.
    pub fn coldkeypub_file(&self) -> Result<Keyfile, KeyFileError> {
        // concatenate wallet path
        let wallet_path = self._path.join(&self.name);

        // concatenate hotkey path
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");

        Keyfile::new(
            coldkeypub_path.to_string_lossy().into_owned(),
            Some("coldkeypub.txt".to_string()),
            false,
        )
    }

    /// Returns the coldkey from wallet.path/wallet.name/coldkey or raises an error.
    pub fn coldkey_property(&self) -> Result<Keypair, KeyFileError> {
        if let Some(coldkey) = &self._coldkey {
            Ok(coldkey.clone())
        } else {
            let coldkey_file = self.coldkey_file()?;
            coldkey_file.get_keypair(None)
        }
    }

    /// Returns the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    pub fn coldkeypub_property(&self) -> Result<Keypair, KeyFileError> {
        let coldkeypub_file = self.coldkeypub_file()?;
        coldkeypub_file.get_keypair(None)
    }

    /// Returns the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.
    pub fn hotkey_property(&self) -> Result<Keypair, KeyFileError> {
        if let Some(hotkey) = &self._hotkey {
            Ok(hotkey.clone())
        } else {
            let hotkey_file = self.hotkey_file()?;
            hotkey_file.get_keypair(None)
        }
    }

    /// Returns the hotkeypub from wallet.path/wallet.name/hotkeypub.txt or raises an error.
    pub fn hotkeypub_property(&self) -> Result<Keypair, KeyFileError> {
        let hotkeypub_file = self.hotkeypub_file()?;
        hotkeypub_file.get_keypair(None)
    }

    /// Returns the name of the wallet
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    /// Returns the path of the wallet
    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    /// Returns the hotkey name
    pub fn get_hotkey_str(&self) -> String {
        self.hotkey.clone()
    }

    /// Sets the coldkey for the wallet.
    ///
    ///     Arguments:
    ///         keypair (Keypair): The keypair to set as coldkey.
    ///         encrypt (bool): Whether to encrypt the key. Defaults to ``True``.
    ///         overwrite (bool): Whether to overwrite if key exists. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save coldkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``.
    ///
    ///     Raises:
    ///         KeyFileError: If file operations fail.
    pub fn set_coldkey(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<(), KeyFileError> {
        self._coldkey = Some(keypair.clone());
        match self.create_coldkey_file(save_coldkey_to_env) {
            Ok(keyfile) => keyfile
                .set_keypair(keypair, encrypt, overwrite, coldkey_password)
                .map_err(|e| KeyFileError::Generic(e.to_string())),
            Err(e) => Err(KeyFileError::Generic(e.to_string())),
        }
    }

    /// Sets the coldkeypub for the wallet.
    ///
    ///     Arguments:
    ///         keypair (Keypair): The keypair to set as coldkeypub.
    ///         encrypt (bool): Whether to encrypt the key. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite if key exists. Defaults to ``False``.
    ///
    ///     Raises:
    ///         KeyFileError: If file operations fail.
    pub fn set_coldkeypub(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
    ) -> Result<(), KeyFileError> {
        let ss58_address = keypair
            .ss58_address()
            .ok_or_else(|| KeyFileError::Generic("Failed to get ss58_address".to_string()))?;
        let coldkeypub_keypair = Keypair::new(Some(ss58_address), None, None, 42, None, 1)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        self._coldkeypub = Some(coldkeypub_keypair.clone());
        self.coldkeypub_file()
            .map_err(|e| KeyFileError::Generic(e.to_string()))?
            .set_keypair(coldkeypub_keypair, encrypt, overwrite, None)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;
        Ok(())
    }

    /// Sets the hotkey for the wallet.
    ///
    ///     Arguments:
    ///         keypair (Keypair): The keypair to set as hotkey.
    ///         encrypt (bool): Whether to encrypt the key. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite if key exists. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save hotkey password to local env. Defaults to ``False``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``.
    ///
    ///     Raises:
    ///         KeyFileError: If file operations fail.
    pub fn set_hotkey(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<(), KeyFileError> {
        self._hotkey = Some(keypair.clone());
        self.create_hotkey_file(save_hotkey_to_env)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?
            .set_keypair(keypair, encrypt, overwrite, hotkey_password)
    }

    /// Sets the hotkeypub for the wallet.
    ///
    ///     Arguments:
    ///         keypair (Keypair): The keypair to set as hotkeypub.
    ///         encrypt (bool): Whether to encrypt the key. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite if key exists. Defaults to ``False``.
    ///
    ///     Raises:
    ///         KeyFileError: If file operations fail.
    pub fn set_hotkeypub(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
    ) -> Result<(), KeyFileError> {
        let ss58_address = keypair
            .ss58_address()
            .ok_or_else(|| KeyFileError::Generic("Failed to get ss58_address".to_string()))?;
        let hotkeypub_keypair = Keypair::new(Some(ss58_address), None, None, 42, None, 1)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        self._hotkeypub = Some(hotkeypub_keypair.clone());
        self.hotkeypub_file()
            .map_err(|e| KeyFileError::Generic(e.to_string()))?
            .set_keypair(hotkeypub_keypair, encrypt, overwrite, None)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;
        Ok(())
    }

    /// Gets the coldkey from the wallet.
    ///
    ///     Arguments:
    ///         password (Optional[str]): Password for decryption. Defaults to ``None``. If not provided, asks for user input.
    ///
    ///     Returns:
    ///         `Keypair` - The coldkey keypair.
    ///     Raises:
    ///         KeyFileError: If the coldkey file doesn't exist or decryption fails.
    pub fn get_coldkey(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.coldkey_file()?.get_keypair(password)
    }

    /// Gets the coldkeypub from the wallet.
    ///
    ///     Arguments:
    ///         password (Optional[str]): Password for decryption. Defaults to ``None``. If not provided, asks for user input.
    ///
    ///     Returns:
    ///         `Keypair` - The coldkeypub keypair.
    ///     Raises:
    ///         KeyFileError: If the coldkeypub file doesn't exist or decryption fails.
    pub fn get_coldkeypub(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.coldkeypub_file()?.get_keypair(password)
    }

    /// Gets the hotkey from the wallet.
    ///
    ///     Arguments:
    ///         password (Optional[str]): Password for decryption. Defaults to ``None``. If not provided, asks for user input.
    ///
    ///     Returns:
    ///         `Keypair` - The hotkey keypair.
    ///     Raises:
    ///         KeyFileError: If the hotkey file doesn't exist or decryption fails.
    pub fn get_hotkey(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.hotkey_file()?.get_keypair(password)
    }

    /// Gets the hotkeypub from the wallet.
    ///
    ///     Arguments:
    ///         password (Optional[str]): Password for decryption. Defaults to ``None``. If not provided, asks for user input.
    ///
    ///     Returns:
    ///         `Keypair` - The hotkeypub keypair.
    ///     Raises:
    ///         KeyFileError: If the hotkeypub file doesn't exist or decryption fails.
    pub fn get_hotkeypub(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.hotkeypub_file()?.get_keypair(password)
    }

    /// Creates coldkey from uri string, optionally encrypts it with the user-provided password.
    ///
    ///     Arguments:
    ///         uri (str): The URI string to create the coldkey from.
    ///         use_password (bool): Whether to use a password for coldkey. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``True``.
    ///         save_coldkey_to_env (bool): Whether to save coldkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created coldkey.
    ///     Raises:
    ///         KeyFileError: If key creation or file operations fail.
    pub fn create_coldkey_from_uri(
        &mut self,
        uri: String,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Wallet, KeyFileError> {
        let keypair = Keypair::create_from_uri(uri.as_str())
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        if !suppress {
            if let Some(m) = keypair.mnemonic() {
                display_mnemonic_msg(m, "coldkey");
            }
        }

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
        )?;
        self.set_coldkeypub(keypair, false, overwrite)?;
        Ok(self.clone())
    }

    /// Creates hotkey from uri string, optionally encrypts it with the user-provided password.
    ///
    ///     Arguments:
    ///         uri (str): The URI string to create the hotkey from.
    ///         use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``True``.
    ///         save_hotkey_to_env (bool): Whether to save hotkey password to local env. Defaults to ``False``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created hotkey.
    ///     Raises:
    ///         KeyFileError: If key creation or file operations fail.
    pub fn create_hotkey_from_uri(
        &mut self,
        uri: String,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Wallet, KeyFileError> {
        let keypair = Keypair::create_from_uri(uri.as_str())
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        if !suppress {
            if let Some(m) = keypair.mnemonic() {
                display_mnemonic_msg(m, "hotkey");
            }
        }

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
        )?;
        self.set_hotkeypub(keypair, false, overwrite)?;
        Ok(self.clone())
    }

    /// Unlocks the coldkey.
    pub fn unlock_coldkey(&mut self) -> Result<Keypair, KeyFileError> {
        if self._coldkey.is_none() {
            let coldkey_file = self.coldkey_file()?;
            self._coldkey = Some(coldkey_file.get_keypair(None)?);
        }
        let _coldkey = self
            ._coldkey
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Coldkey file doesn't exist.".to_string()))?;
        Ok(_coldkey)
    }

    /// Unlocks the coldkeypub.
    pub fn unlock_coldkeypub(&mut self) -> Result<Keypair, KeyFileError> {
        if self._coldkeypub.is_none() {
            let coldkeypub_file = self.coldkeypub_file()?;
            self._coldkeypub = Some(coldkeypub_file.get_keypair(None)?);
        }
        let _coldkeypub = self
            ._coldkeypub
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Coldkey file doesn't exist.".to_string()))?;
        Ok(_coldkeypub)
    }

    /// Unlocks the hotkey.
    pub fn unlock_hotkey(&mut self) -> Result<Keypair, KeyFileError> {
        if self._hotkey.is_none() {
            let hotkey_file = self.hotkey_file()?;
            self._hotkey = Some(hotkey_file.get_keypair(None)?);
        }
        let _hotkey = self
            ._hotkey
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Hotkey doesn't exist.".to_string()))?;
        Ok(_hotkey)
    }

    /// Unlocks the hotkeypub.
    pub fn unlock_hotkeypub(&mut self) -> Result<Keypair, KeyFileError> {
        if self._hotkeypub.is_none() {
            let hotkeypub_file = self.hotkeypub_file()?;
            self._hotkeypub = Some(hotkeypub_file.get_keypair(None)?);
        }
        let _hotkeypub = self
            ._hotkeypub
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Hotkeypub file doesn't exist.".to_string()))?;
        Ok(_hotkeypub)
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    ///
    ///     Arguments:
    ///         n_words (int): The number of words in the mnemonic. Defaults to 12.
    ///         use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save coldkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``. If `coldkey_password` is passed, then `use_password` is automatically ``True``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created coldkey.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    pub fn new_coldkey(
        &mut self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Wallet, WalletError> {
        self.create_new_coldkey(
            n_words,
            use_password,
            overwrite,
            suppress,
            save_coldkey_to_env,
            coldkey_password,
        )
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    ///
    ///     Arguments:
    ///         n_words (int): The number of words in the mnemonic. Defaults to 12.
    ///         use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save coldkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``. If `coldkey_password` is passed, then `use_password` is automatically ``True``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created coldkey.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    fn create_new_coldkey(
        &mut self,
        n_words: usize,
        mut use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Self, WalletError> {
        let mnemonic = Keypair::generate_mnemonic(n_words)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        let keypair = Keypair::create_from_mnemonic(&mnemonic)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "coldkey");
        }

        // If password is provided, force password usage
        if coldkey_password.is_some() {
            use_password = true;
        }

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
        )?;

        self.set_coldkeypub(keypair.clone(), false, overwrite)?;

        Ok(self.clone())
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    ///
    ///     Arguments:
    ///         n_words (int): The number of words in the mnemonic. Defaults to 12.
    ///         use_password (bool): Whether to use a password for hotkey. Defaults to ``True``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save hotkey password to local env. Defaults to ``False``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``. If `hotkey_password` is passed, then `use_password` is automatically ``True``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created hotkey.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    pub fn new_hotkey(
        &mut self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Self, WalletError> {
        self.create_new_hotkey(
            n_words,
            use_password,
            overwrite,
            suppress,
            save_hotkey_to_env,
            hotkey_password,
        )
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    ///
    ///     Arguments:
    ///         n_words (int): The number of words in the mnemonic. Defaults to 12.
    ///         use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save hotkey password to local env. Defaults to ``False``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``. If `hotkey_password` is passed, then `use_password` is automatically ``True``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with created hotkey.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    pub fn create_new_hotkey(
        &mut self,
        n_words: usize,
        mut use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Wallet, WalletError> {
        let mnemonic = Keypair::generate_mnemonic(n_words)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "hotkey");
        }

        // if hotkey_password is passed then hotkey_use_password always is true
        use_password = hotkey_password.is_some() || use_password;

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
        )?;

        self.set_hotkeypub(keypair.clone(), false, overwrite)?;

        Ok(self.clone())
    }

    /// Regenerates the coldkey from the passed mnemonic or seed, or JSON encrypts it with the user's password and saves the file.
    ///
    ///     Arguments:
    ///         mnemonic (Optional[str]): Mnemonic phrase to regenerate the coldkey from. Defaults to ``None``.
    ///         seed (Optional[str]): Seed hex to regenerate the coldkey from. Defaults to ``None``.
    ///         json (Optional[tuple]): Tuple of (JSON data, passphrase) to regenerate the coldkey from. Defaults to ``None``.
    ///         use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save coldkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with regenerated coldkey.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    #[allow(clippy::too_many_arguments)]
    pub fn regenerate_coldkey(
        &mut self,
        mnemonic: Option<String>,
        seed: Option<String>,
        json: Option<(String, String)>,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Self, WalletError> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)
                .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "coldkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            Keypair::create_from_seed(hex::decode(seed.trim_start_matches("0x")).unwrap())
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else {
            return Err(WalletError::InvalidInput(
                "Must pass either mnemonic, seed, or json.".to_string(),
            ));
        };

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
        )?;
        self.set_coldkeypub(keypair.clone(), false, overwrite)?;
        Ok(self.clone())
    }

    /// Regenerates the coldkeypub from the passed ss58_address or public_key and saves the file.
    /// Requires either ss58_address or public_key to be passed.
    ///
    ///     Arguments:
    ///         ss58_address (Optional[str]): SS58 address to regenerate the coldkeypub from. Defaults to ``None``.
    ///         public_key (Optional[str]): Public key hex to regenerate the coldkeypub from. Defaults to ``None``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with regenerated coldkeypub.
    ///     Raises:
    ///         WalletError: If key generation or file operations fail.
    pub fn regenerate_coldkeypub(
        &mut self,
        ss58_address: Option<String>,
        public_key: Option<String>,
        overwrite: bool,
    ) -> Result<Self, WalletError> {
        if ss58_address.is_none() && public_key.is_none() {
            return Err(WalletError::InvalidInput(
                "Either ss58_address or public_key must be passed.".to_string(),
            ));
        }

        let address_to_string = ss58_address
            .as_ref()
            .or(public_key.as_ref())
            .ok_or_else(|| WalletError::InvalidInput("No address provided".to_string()))?;

        if !is_valid_bittensor_address_or_public_key(address_to_string) {
            return Err(WalletError::InvalidInput(format!(
                "Invalid {}.",
                if ss58_address.is_some() {
                    "ss58_address"
                } else {
                    "public_key"
                }
            )));
        }

        let keypair = Keypair::new(ss58_address, public_key, None, 42, None, 1)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        self.set_coldkeypub(keypair, false, overwrite)?;
        Ok(self.clone())
    }

    /// Regenerates the hotkey from passed mnemonic or seed, encrypts it with the user's password and saves the file.
    ///
    ///     Arguments:
    ///         mnemonic (Optional[str]): Mnemonic phrase to regenerate the hotkey from. Defaults to ``None``.
    ///         seed (Optional[str]): Seed hex to regenerate the hotkey from. Defaults to ``None``.
    ///         json (Optional[tuple]): Tuple of (JSON data, passphrase) to regenerate the hotkey from. Defaults to ``None``.
    ///         use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         overwrite (bool): Whether to overwrite existing keys. Defaults to ``False``.
    ///         suppress (bool): Whether to suppress mnemonic display. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save hotkey password to local env. Defaults to ``False``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``.
    ///
    ///     Returns:
    ///         `Wallet` - The wallet instance with regenerated hotkey.
    ///     Raises:
    ///         KeyFileError: If key generation or file operations fail.
    #[allow(clippy::too_many_arguments)]
    pub fn regenerate_hotkey(
        &mut self,
        mnemonic: Option<String>,
        seed: Option<String>,
        json: Option<(String, String)>,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Self, KeyFileError> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)
                .map_err(|e| KeyFileError::Generic(e.to_string()))?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "hotkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            Keypair::create_from_seed(hex::decode(seed.trim_start_matches("0x")).unwrap())
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else {
            return Err(KeyFileError::Generic(
                "Must pass either mnemonic, seed, or json.".to_string(),
            ));
        };

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
        )?;
        self.set_hotkeypub(keypair.clone(), false, overwrite)?;
        Ok(self.clone())
    }

    /// Regenerates the hotkeypub from the passed `ss58_address` or `public_key` and saves the file.
    /// Requires either `ss58_address` or `public_key` to be passed.
    pub fn regenerate_hotkeypub(
        &mut self,
        ss58_address: Option<String>,
        public_key: Option<String>,
        overwrite: bool,
    ) -> Result<Self, WalletError> {
        if ss58_address.is_none() && public_key.is_none() {
            return Err(WalletError::InvalidInput(
                "Either ss58_address or public_key must be passed.".to_string(),
            ));
        }

        let address_to_string = ss58_address
            .as_ref()
            .or(public_key.as_ref())
            .ok_or_else(|| WalletError::InvalidInput("No address provided".to_string()))?;

        if !is_valid_bittensor_address_or_public_key(address_to_string) {
            return Err(WalletError::InvalidInput(format!(
                "Invalid {}.",
                if ss58_address.is_some() {
                    "ss58_address"
                } else {
                    "public_key"
                }
            )));
        }

        let keypair = Keypair::new(ss58_address, public_key, None, 42, None, 1)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        self.set_hotkeypub(keypair, false, overwrite)?;
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_wallet() -> Wallet {
        Wallet::new(None, None, None, None)
    }

    fn custom_wallet(name: &str, hotkey: &str, path: &str) -> Wallet {
        Wallet::new(
            Some(name.to_string()),
            Some(hotkey.to_string()),
            Some(path.to_string()),
            None,
        )
    }

    #[test]
    fn test_wallet_default_values() {
        let wallet = default_wallet();
        assert_eq!(wallet.name, BT_WALLET_NAME);
        assert_eq!(wallet.hotkey, BT_WALLET_HOTKEY);
        assert_eq!(wallet.path, BT_WALLET_PATH);
    }

    #[test]
    fn test_wallet_custom_values() {
        let wallet = custom_wallet("my_wallet", "my_hotkey", "/tmp/wallets/");
        assert_eq!(wallet.name, "my_wallet");
        assert_eq!(wallet.hotkey, "my_hotkey");
        assert_eq!(wallet.path, "/tmp/wallets/");
    }

    #[test]
    fn test_wallet_with_config() {
        let config = Config::new(
            Some("config_name".to_string()),
            Some("config_hotkey".to_string()),
            Some("/config/path/".to_string()),
        );
        let wallet = Wallet::new(None, None, None, Some(config));
        assert_eq!(wallet.name, "config_name");
        assert_eq!(wallet.hotkey, "config_hotkey");
        assert_eq!(wallet.path, "/config/path/");
    }

    #[test]
    fn test_wallet_explicit_overrides_config() {
        let config = Config::new(
            Some("config_name".to_string()),
            Some("config_hotkey".to_string()),
            None,
        );
        let wallet = Wallet::new(Some("explicit_name".to_string()), None, None, Some(config));
        assert_eq!(wallet.name, "explicit_name");
    }

    #[test]
    fn test_wallet_display() {
        let wallet = custom_wallet("test", "hk", "/p/");
        let display = format!("{}", wallet);
        assert!(display.contains("test"));
        assert!(display.contains("hk"));
        assert!(display.contains("/p/"));
    }

    #[test]
    fn test_wallet_debug() {
        let wallet = default_wallet();
        let debug = format!("{:?}", wallet);
        assert!(debug.contains(BT_WALLET_NAME));
    }

    #[test]
    fn test_wallet_get_name() {
        let wallet = custom_wallet("named", "hk", "/p/");
        assert_eq!(wallet.get_name(), "named");
    }

    #[test]
    fn test_wallet_get_path() {
        let wallet = custom_wallet("w", "hk", "/custom/path/");
        assert_eq!(wallet.get_path(), "/custom/path/");
    }

    #[test]
    fn test_wallet_get_hotkey_str() {
        let wallet = custom_wallet("w", "special_hotkey", "/p/");
        assert_eq!(wallet.get_hotkey_str(), "special_hotkey");
    }

    #[test]
    fn test_wallet_clone() {
        let wallet = custom_wallet("original", "hk", "/path/");
        let cloned = wallet.clone();
        assert_eq!(wallet.name, cloned.name);
        assert_eq!(wallet.hotkey, cloned.hotkey);
        assert_eq!(wallet.path, cloned.path);
    }

    #[test]
    fn test_coldkey_file_path() {
        let wallet = custom_wallet("test_wallet", "hk", "/tmp/test_wallets/");
        let keyfile = wallet.coldkey_file().expect("Failed to get coldkey file");
        assert!(keyfile.path.contains("test_wallet"));
        assert!(keyfile.path.contains("coldkey"));
    }

    #[test]
    fn test_hotkey_file_path() {
        let wallet = custom_wallet("test_wallet", "my_hotkey", "/tmp/test_wallets/");
        let keyfile = wallet.hotkey_file().expect("Failed to get hotkey file");
        assert!(keyfile.path.contains("test_wallet"));
        assert!(keyfile.path.contains("hotkeys"));
        assert!(keyfile.path.contains("my_hotkey"));
    }

    #[test]
    fn test_coldkeypub_file_path() {
        let wallet = custom_wallet("test_wallet", "hk", "/tmp/test_wallets/");
        let keyfile = wallet
            .coldkeypub_file()
            .expect("Failed to get coldkeypub file");
        assert!(keyfile.path.contains("test_wallet"));
        assert!(keyfile.path.contains("coldkeypub.txt"));
    }

    #[test]
    fn test_hotkeypub_file_path() {
        let wallet = custom_wallet("test_wallet", "my_hotkey", "/tmp/test_wallets/");
        let keyfile = wallet
            .hotkeypub_file()
            .expect("Failed to get hotkeypub file");
        assert!(keyfile.path.contains("test_wallet"));
        assert!(keyfile.path.contains("hotkeys"));
        assert!(keyfile.path.contains("my_hotkeypub.txt"));
    }

    #[test]
    fn test_wallet_config_default() {
        let config = Wallet::config();
        assert_eq!(config.name(), BT_WALLET_NAME);
        assert_eq!(config.hotkey(), BT_WALLET_HOTKEY);
        assert_eq!(config.path(), BT_WALLET_PATH);
    }

    #[test]
    fn test_regenerate_coldkeypub_requires_address() {
        let mut wallet = default_wallet();
        let result = wallet.regenerate_coldkeypub(None, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_regenerate_hotkeypub_requires_address() {
        let mut wallet = default_wallet();
        let result = wallet.regenerate_hotkeypub(None, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_regenerate_coldkeypub_invalid_address() {
        let mut wallet = default_wallet();
        let result = wallet.regenerate_coldkeypub(Some("invalid_address".to_string()), None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_regenerate_hotkeypub_invalid_address() {
        let mut wallet = default_wallet();
        let result = wallet.regenerate_hotkeypub(Some("invalid_address".to_string()), None, false);
        assert!(result.is_err());
    }
}
