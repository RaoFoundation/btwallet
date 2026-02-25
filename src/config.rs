use std::fmt::Display;

use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};

#[derive(Clone)]
pub struct WalletConfig {
    pub name: String,
    pub path: String,
    pub hotkey: String,
}

impl WalletConfig {
    /// Creates a new WalletConfig instance.
    ///
    ///     Arguments:
    ///         name (Option<String>): Optional wallet name. Defaults to "default" if not provided.
    ///         hotkey (Option<String>): Optional hotkey name. Defaults to "default" if not provided.
    ///         path (Option<String>): Optional wallet path. Defaults to "~/.bittensor/wallets/" if not provided.
    ///     Returns:
    ///         wallet_config (WalletConfig): A new WalletConfig instance.
    pub fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>) -> Self {
        WalletConfig {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            hotkey: hotkey.unwrap_or_else(|| BT_WALLET_HOTKEY.to_string()),
            path: path.unwrap_or_else(|| BT_WALLET_PATH.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub wallet: WalletConfig,
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Config(name: '{}', path: '{}', hotkey: '{}'",
            self.wallet.name, self.wallet.path, self.wallet.hotkey
        )
    }
}

impl Config {
    /// Creates a new Config instance.
    ///
    ///     Arguments:
    ///         name (Option<String>): Optional wallet name. Defaults to "default" if not provided.
    ///         hotkey (Option<String>): Optional hotkey name. Defaults to "default" if not provided.
    ///         path (Option<String>): Optional wallet path. Defaults to "~/.bittensor/wallets/" if not provided.
    ///     Returns:
    ///         config (Config): A new Config instance.
    pub fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>) -> Config {
        Config {
            wallet: WalletConfig::new(name, hotkey, path),
        }
    }

    /// Returns the wallet name.
    pub fn name(&self) -> String {
        self.wallet.name.clone()
    }

    /// Returns the wallet path.
    pub fn path(&self) -> String {
        self.wallet.path.clone()
    }

    /// Returns the hotkey name.
    pub fn hotkey(&self) -> String {
        self.wallet.hotkey.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_config_defaults() {
        let config = WalletConfig::new(None, None, None);
        assert_eq!(config.name, BT_WALLET_NAME);
        assert_eq!(config.hotkey, BT_WALLET_HOTKEY);
        assert_eq!(config.path, BT_WALLET_PATH);
    }

    #[test]
    fn test_wallet_config_custom_values() {
        let config = WalletConfig::new(
            Some("my_wallet".to_string()),
            Some("my_hotkey".to_string()),
            Some("/custom/path/".to_string()),
        );
        assert_eq!(config.name, "my_wallet");
        assert_eq!(config.hotkey, "my_hotkey");
        assert_eq!(config.path, "/custom/path/");
    }

    #[test]
    fn test_wallet_config_partial_overrides() {
        let config = WalletConfig::new(Some("custom_name".to_string()), None, None);
        assert_eq!(config.name, "custom_name");
        assert_eq!(config.hotkey, BT_WALLET_HOTKEY);
        assert_eq!(config.path, BT_WALLET_PATH);
    }

    #[test]
    fn test_config_delegates_to_wallet_config() {
        let config = Config::new(
            Some("test_wallet".to_string()),
            Some("test_hotkey".to_string()),
            Some("/test/path/".to_string()),
        );
        assert_eq!(config.name(), "test_wallet");
        assert_eq!(config.hotkey(), "test_hotkey");
        assert_eq!(config.path(), "/test/path/");
    }

    #[test]
    fn test_config_display_format() {
        let config = Config::new(None, None, None);
        let display = format!("{}", config);
        assert!(display.contains(BT_WALLET_NAME));
        assert!(display.contains(BT_WALLET_PATH));
        assert!(display.contains(BT_WALLET_HOTKEY));
    }

    #[test]
    fn test_config_clone() {
        let config = Config::new(Some("cloned".to_string()), Some("hotkey".to_string()), None);
        let cloned = config.clone();
        assert_eq!(config.name(), cloned.name());
        assert_eq!(config.hotkey(), cloned.hotkey());
        assert_eq!(config.path(), cloned.path());
    }
}
