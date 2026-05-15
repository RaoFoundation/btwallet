from typing import Any, Optional

from ..keyfile import Keyfile
from ..keypair import Keypair

class Wallet:
    def __init__(
        self,
        name: Optional[str] = None,
        hotkey: Optional[str] = None,
        path: Optional[str] = None,
        config: Optional[Any] = None,
    ) -> None: ...
    def __str__(self) -> str: ...
    @classmethod
    def add_args(cls, parser: Any, prefix: Optional[str] = None) -> Any: ...
    def to_string(self) -> str: ...
    def debug_string(self) -> str: ...
    def create_if_non_existent(
        self,
        coldkey_use_password: Optional[bool] = True,
        hotkey_use_password: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        hotkey_password: Optional[str] = None,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        coldkey_crypto_type: Optional[int] = 1,
        hotkey_crypto_type: Optional[int] = 1,
    ) -> "Wallet": ...
    def create(
        self,
        coldkey_use_password: Optional[bool] = True,
        hotkey_use_password: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        hotkey_password: Optional[str] = None,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        coldkey_crypto_type: int = 1,
        hotkey_crypto_type: int = 1,
    ) -> "Wallet": ...
    def recreate(
        self,
        coldkey_use_password: Optional[bool] = True,
        hotkey_use_password: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        hotkey_password: Optional[str] = None,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        coldkey_crypto_type: Optional[int] = 1,
        hotkey_crypto_type: Optional[int] = 1,
    ) -> "Wallet": ...
    def get_coldkey(self, password: Optional[str] = None) -> "Keypair": ...
    def get_coldkeypub(self, password: Optional[str] = None) -> "Keypair": ...
    def get_hotkey(self, password: Optional[str] = None) -> "Keypair": ...
    def get_hotkeypub(self, password: Optional[str] = None) -> "Keypair": ...
    def set_coldkey(
        self,
        keypair: "Keypair",
        encrypt: bool = True,
        overwrite: bool = False,
        save_coldkey_to_env: bool = False,
        coldkey_password: Optional[str] = None,
    ) -> None: ...
    def set_coldkeypub(
        self,
        keypair: "Keypair",
        encrypt: bool = False,
        overwrite: bool = False,
    ) -> None: ...
    def set_hotkey(
        self,
        keypair: "Keypair",
        encrypt: bool = False,
        overwrite: bool = False,
        save_hotkey_to_env: bool = False,
        hotkey_password: Optional[str] = None,
    ) -> None: ...
    def set_hotkeypub(
        self,
        keypair: "Keypair",
        encrypt: bool = False,
        overwrite: bool = False,
    ) -> None: ...
    @property
    def coldkey(self) -> "Keypair": ...
    @property
    def coldkeypub(self) -> "Keypair": ...
    @property
    def hotkey(self) -> "Keypair": ...
    @property
    def hotkeypub(self) -> "Keypair": ...
    @property
    def coldkey_file(self) -> "Keyfile": ...
    @property
    def coldkeypub_file(self) -> "Keyfile": ...
    @property
    def hotkey_file(self) -> "Keyfile": ...
    @property
    def hotkeypub_file(self) -> "Keyfile": ...
    @property
    def name(self) -> str: ...
    @property
    def path(self) -> str: ...
    @property
    def hotkey_str(self) -> str: ...
    def create_coldkey_from_uri(
        self,
        uri: str,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        crypto_type: int = 1,
    ) -> None: ...
    def create_hotkey_from_uri(
        self,
        uri: str,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        hotkey_password: Optional[str] = None,
        crypto_type: int = 1,
    ) -> None: ...
    def unlock_coldkey(self) -> "Keypair": ...
    def unlock_coldkeypub(self) -> "Keypair": ...
    def unlock_hotkey(self) -> "Keypair": ...
    def unlock_hotkeypub(self) -> "Keypair": ...
    def new_coldkey(
        self,
        n_words: Optional[int] = 12,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        crypto_type: Optional[int] = 1,
    ) -> "Wallet": ...
    def create_new_coldkey(
        self,
        n_words: Optional[int] = 12,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        crypto_type: Optional[int] = 1,
    ) -> "Wallet": ...
    def new_hotkey(
        self,
        n_words: Optional[int] = 12,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        hotkey_password: Optional[str] = None,
        crypto_type: Optional[int] = 1,
    ) -> "Wallet": ...
    def create_new_hotkey(
        self,
        n_words: Optional[int] = 12,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        hotkey_password: Optional[str] = None,
        crypto_type: Optional[int] = 1,
    ) -> "Wallet": ...
    def regenerate_coldkey(
        self,
        mnemonic: Optional[str] = None,
        seed: Optional[bytes] = None,
        json: Optional[str] = None,
        use_password: Optional[bool] = True,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_coldkey_to_env: Optional[bool] = False,
        coldkey_password: Optional[str] = None,
        crypto_type: int = 1,
    ) -> "Wallet": ...
    def regenerate_coldkeypub(
        self,
        ss58_address: Optional[str] = None,
        public_key: Optional[bytes] = None,
        overwrite: Optional[bool] = False,
        crypto_type: int = 1,
    ) -> "Wallet": ...
    def regenerate_hotkey(
        self,
        mnemonic: Optional[str] = None,
        seed: Optional[bytes] = None,
        json: Optional[str] = None,
        use_password: Optional[bool] = False,
        overwrite: Optional[bool] = False,
        suppress: Optional[bool] = False,
        save_hotkey_to_env: Optional[bool] = False,
        hotkey_password: Optional[str] = None,
        crypto_type: int = 1,
    ) -> "Wallet": ...
    def regenerate_hotkeypub(
        self,
        ss58_address: Optional[str] = None,
        public_key: Optional[bytes] = None,
        overwrite: Optional[bool] = False,
        crypto_type: int = 1,
    ) -> "Wallet": ...
