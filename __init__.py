# The MIT License (MIT)
# Copyright © 2021 Yuma Rao
# Copyright © 2022 Opentensor Foundation
# Copyright © 2023 Opentensor Technologies Inc

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

__ss58_format__ = 42  # Bittensor ss58 format


from typing import Optional, Union, Tuple, Dict, overload, Any, TypedDict

import argparse
import copy
import os
from substrateinterface import Keypair
from termcolor import colored

import bittensor

from ._keyfile import (
    Keyfile as Keyfile,
    KeyFileError as KeyFileError,
    serialized_keypair_to_keyfile_data as serialized_keypair_to_keyfile_data,
    validate_password as validate_password,
    ask_password_to_encrypt as ask_password_to_encrypt,
    decrypt_keyfile_data as decrypt_keyfile_data,
)

from .keypair_impl import Keypair as Keypair
from . import utils as utils


def display_mnemonic_msg(keypair: Keypair, key_type: str):
    """Displaying the mnemonic and warning message to keep mnemonic safe"""
    mnemonic = keypair.mnemonic
    mnemonic_green = colored(mnemonic, "green")
    print(
        colored(
            "\nIMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone "
            "who has possesion of this mnemonic can use it to regenerate the key and access your tokens. \n",
            "red",
        )
    )
    print("The mnemonic to the new {} is:\n\n{}\n".format(key_type, mnemonic_green))
    print(
        "You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:"
    )
    print("btcli regen_{} --mnemonic {}".format(key_type, mnemonic))
    print("")


class WalletConfigDefault(TypedDict):
    name: str
    hotkey: str
    path: str


class WalletConfig(bittensor.DefaultConfig):
    name: str
    hotkey: str
    path: str

    defaults: WalletConfigDefault = {
        "name": "default",
        "hotkey": "default",
        "path": "~/.bittensor/wallets/",
    }

    def __init__(
        self, name: str = None, hotkey: str = None, path: str = None, **kwargs
    ):
        super().__init__(default=None)

        self.name = name or self.defaults["name"]
        self.hotkey = hotkey or self.defaults["hotkey"]
        self.path = path or self.defaults["path"]
        self.update(kwargs)

    @classmethod
    def default(cls) -> "WalletConfig":
        wallet_config = cls()
        wallet_config.update_with_kwargs(cls.defaults)

        return wallet_config


class wallet:
    """Create and init wallet that stores hot and coldkey"""

    defaults: WalletConfig = WalletConfig.default()

    def __init__(
        self,
        name: Optional[str] = None,
        path: Optional[str] = None,
        hotkey: Optional[str] = None,
        config: Optional[Union[bittensor.config, WalletConfig]] = None,
    ):
        r"""Init bittensor wallet object containing a hot and coldkey.
        Args:
            name (required=True, default='default):
                The name of the wallet to unlock for running bittensor
            hotkey (required=True, default='default):
                The name of hotkey used to running the miner.
            path (required=True, default='~/.bittensor/wallets/'):
                The path to your bittensor wallets
            config (required=False, default=None):
                bittensor.config or wallet config object.
        """
        # Fill config from passed args using command line defaults.
        if config == None:
            config = wallet.defaults

        if hasattr(config, "wallet") and config.wallet != None:
            config = config.wallet

        self.config = copy.deepcopy(config)
        self.config.name = name or config.get("name", wallet.defaults.name)
        self.config.hotkey = hotkey or config.get("hotkey", wallet.defaults.hotkey)
        self.config.path = path or config.get("path", wallet.defaults.path)

        self.name = self.config.name
        self.path = self.config.path
        self.hotkey_str = self.config.hotkey

        self._hotkey = None
        self._coldkey = None
        self._coldkeypub = None

    def __str__(self):
        return "wallet ({}, {}, {})".format(self.name, self.hotkey_str, self.path)

    def __repr__(self):
        return self.__str__()

    @classmethod
    def config(cls) -> "bittensor.config":
        """Get config from the argument parser
        Return: bittensor.config object
        """
        parser = argparse.ArgumentParser()
        wallet.add_args(parser)
        return bittensor.config(parser)

    @classmethod
    def help(cls):
        """Print help to stdout"""
        parser = argparse.ArgumentParser()
        cls.add_args(parser)
        print(cls.__new__.__doc__)
        parser.print_help()

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser, prefix: str = None):
        """Accept specific arguments from parser"""
        prefix_str = "" if prefix == None else prefix + "."
        try:
            parser.add_argument(
                "--" + prefix_str + "wallet.name",
                required=False,
                default=cls.defaults.name,
                help="""The name of the wallet to unlock for running bittensor (name mock is reserved for mocking this wallet)""",
            )
            parser.add_argument(
                "--" + prefix_str + "wallet.hotkey",
                required=False,
                default=cls.defaults.hotkey,
                help="""The name of wallet's hotkey.""",
            )
            parser.add_argument(
                "--" + prefix_str + "wallet.path",
                required=False,
                default=cls.defaults.path,
                help="""The path to your bittensor wallets""",
            )

        except argparse.ArgumentError as e:
            pass

    @classmethod
    def add_defaults(cls, defaults: bittensor.config, prefix: str = "wallet") -> None:
        """Adds parser defaults to object, optionally using enviroment variables."""
        default_config = WalletConfig()
        default_config.name = (
            os.getenv("BT_WALLET_NAME")
            if os.getenv("BT_WALLET_NAME") != None
            else cls.defaults.name
        )
        default_config.hotkey = (
            os.getenv("BT_WALLET_HOTKEY")
            if os.getenv("BT_WALLET_HOTKEY") != None
            else cls.defaults.hotkey
        )
        default_config.path = (
            os.getenv("BT_WALLET_PATH")
            if os.getenv("BT_WALLET_PATH") != None
            else cls.defaults.path
        )

        setattr(defaults, prefix, default_config)

    @classmethod
    def check_config(cls, config: "bittensor.config"):
        """Check config for wallet name/hotkey/path/hotkeys/sort_by"""
        assert "wallet" in config
        assert isinstance(config.wallet.name, str)
        assert (
            isinstance(config.wallet.hotkey, str) or config.wallet.hotkey == None
        )  # Optional
        assert isinstance(config.wallet.path, str)

    def create_if_non_existent(
        self, coldkey_use_password: bool = True, hotkey_use_password: bool = False
    ) -> "wallet":
        """Checks for existing coldkeypub and hotkeys and creates them if non-existent."""
        return self.create(coldkey_use_password, hotkey_use_password)

    def create(
        self, coldkey_use_password: bool = True, hotkey_use_password: bool = False
    ) -> "wallet":
        """Checks for existing coldkeypub and hotkeys and creates them if non-existent."""
        # ---- Setup wallet. ----
        if (
            not self.coldkey_file.exists_on_device()
            and not self.coldkeypub_file.exists_on_device()
        ):
            self.create_new_coldkey(n_words=12, use_password=coldkey_use_password)
        if not self.hotkey_file.exists_on_device():
            self.create_new_hotkey(n_words=12, use_password=hotkey_use_password)
        return self

    def recreate(
        self, coldkey_use_password: bool = True, hotkey_use_password: bool = False
    ) -> "wallet":
        """Checks for existing coldkeypub and hotkeys and creates them if non-existent."""
        # ---- Setup wallet. ----
        self.create_new_coldkey(n_words=12, use_password=coldkey_use_password)
        self.create_new_hotkey(n_words=12, use_password=hotkey_use_password)
        return self

    @property
    def hotkey_file(self) -> "Keyfile":
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        hotkey_path = os.path.join(wallet_path, "hotkeys", self.hotkey_str)
        return Keyfile(path=hotkey_path)

    @property
    def coldkey_file(self) -> "Keyfile":
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        coldkey_path = os.path.join(wallet_path, "coldkey")
        return Keyfile(path=coldkey_path)

    @property
    def coldkeypub_file(self) -> "Keyfile":
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        coldkeypub_path = os.path.join(wallet_path, "coldkeypub.txt")
        return Keyfile(path=coldkeypub_path)

    def set_hotkey(
        self, keypair: "Keypair", encrypt: bool = False, overwrite: bool = False
    ) -> "Keyfile":
        self._hotkey = keypair
        self.hotkey_file.set_keypair(keypair, encrypt=encrypt, overwrite=overwrite)

    def set_coldkeypub(
        self, keypair: "Keypair", encrypt: bool = False, overwrite: bool = False
    ) -> "Keyfile":
        self._coldkeypub = Keypair(ss58_address=keypair.ss58_address)
        self.coldkeypub_file.set_keypair(
            self._coldkeypub, encrypt=encrypt, overwrite=overwrite
        )

    def set_coldkey(
        self, keypair: "Keypair", encrypt: bool = True, overwrite: bool = False
    ) -> "Keyfile":
        self._coldkey = keypair
        self.coldkey_file.set_keypair(
            self._coldkey, encrypt=encrypt, overwrite=overwrite
        )

    def get_coldkey(self, password: str = None) -> "Keypair":
        self.coldkey_file.get_keypair(password=password)

    def get_hotkey(self, password: str = None) -> "Keypair":
        self.hotkey_file.get_keypair(password=password)

    def get_coldkeypub(self, password: str = None) -> "Keypair":
        self.coldkeypub_file.get_keypair(password=password)

    @property
    def hotkey(self) -> "Keypair":
        r"""Loads the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.
        Returns:
            hotkey (Keypair):
                hotkey loaded from config arguments.
        Raises:
            KeyFileError: Raised if the file is corrupt of non-existent.
            CryptoKeyError: Raised if the user enters an incorrec password for an encrypted Keyfile.
        """
        if self._hotkey == None:
            self._hotkey = self.hotkey_file.keypair
        return self._hotkey

    @property
    def coldkey(self) -> "Keypair":
        r"""Loads the hotkey from wallet.path/wallet.name/coldkey or raises an error.
        Returns:
            coldkey (Keypair):
                colkey loaded from config arguments.
        Raises:
            KeyFileError: Raised if the file is corrupt of non-existent.
            CryptoKeyError: Raised if the user enters an incorrec password for an encrypted Keyfile.
        """
        if self._coldkey == None:
            self._coldkey = self.coldkey_file.keypair
        return self._coldkey

    @property
    def coldkeypub(self) -> "Keypair":
        r"""Loads the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.
        Returns:
            coldkeypub (Keypair):
                colkeypub loaded from config arguments.
        Raises:
            KeyFileError: Raised if the file is corrupt of non-existent.
            CryptoKeyError: Raised if the user enters an incorrect password for an encrypted Keyfile.
        """
        if self._coldkeypub == None:
            self._coldkeypub = self.coldkeypub_file.keypair
        return self._coldkeypub

    def create_coldkey_from_uri(
        self,
        uri: str,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        """Creates coldkey from suri string, optionally encrypts it with the user's inputed password.
        Args:
            uri: (str, required):
                URI string to use i.e. /Alice or /Bob
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created coldkey.
        """
        keypair = Keypair.create_from_uri(uri)
        if not suppress:
            display_mnemonic_msg(keypair, "coldkey")
        self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    def create_hotkey_from_uri(
        self,
        uri: str,
        use_password: bool = False,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        """Creates hotkey from suri string, optionally encrypts it with the user's inputed password.
        Args:
            uri: (str, required):
                URI string to use i.e. /Alice or /Bob
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created hotkey.
        """
        keypair = Keypair.create_from_uri(uri)
        if not suppress:
            display_mnemonic_msg(keypair, "hotkey")
        self.set_hotkey(keypair, encrypt=use_password, overwrite=overwrite)
        return self

    def new_coldkey(
        self,
        n_words: int = 12,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        """Creates a new coldkey, optionally encrypts it with the user's inputed password and saves to disk.
        Args:
            n_words: (int, optional):
                Number of mnemonic words to use.
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created coldkey.
        """
        self.create_new_coldkey(
            n_words=n_words,
            use_password=use_password,
            overwrite=overwrite,
            suppress=suppress,
        )

    def create_new_coldkey(
        self,
        n_words: int = 12,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        """Creates a new coldkey, optionally encrypts it with the user's inputed password and saves to disk.
        Args:
            n_words: (int, optional):
                Number of mnemonic words to use.
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created coldkey.
        """
        mnemonic = Keypair.generate_mnemonic(n_words)
        keypair = Keypair.create_from_mnemonic(mnemonic)
        if not suppress:
            display_mnemonic_msg(keypair, "coldkey")
        self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    def new_hotkey(
        self,
        n_words: int = 12,
        use_password: bool = False,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        """Creates a new hotkey, optionally encrypts it with the user's inputed password and saves to disk.
        Args:
            n_words: (int, optional):
                Number of mnemonic words to use.
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created hotkey.
        """
        self.create_new_hotkey(
            n_words=n_words,
            use_password=use_password,
            overwrite=overwrite,
            suppress=suppress,
        )

    def create_new_hotkey(
        self,
        n_words: int = 12,
        use_password: bool = False,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        """Creates a new hotkey, optionally encrypts it with the user's inputed password and saves to disk.
        Args:
            n_words: (int, optional):
                Number of mnemonic words to use.
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
        Returns:
            wallet (bittensor.wallet):
                this object with newly created hotkey.
        """
        mnemonic = Keypair.generate_mnemonic(n_words)
        keypair = Keypair.create_from_mnemonic(mnemonic)
        if not suppress:
            display_mnemonic_msg(keypair, "hotkey")
        self.set_hotkey(keypair, encrypt=use_password, overwrite=overwrite)
        return self

    def regenerate_coldkeypub(
        self,
        ss58_address: Optional[str] = None,
        public_key: Optional[Union[str, bytes]] = None,
        overwrite: bool = False,
    ) -> "wallet":
        """Regenerates the coldkeypub from passed ss58_address or public_key and saves the file
           Requires either ss58_address or public_key to be passed.
        Args:
            ss58_address: (str, optional):
                Address as ss58 string.
            public_key: (str | bytes, optional):
                Public key as hex string or bytes.
            overwrite (bool, optional) (default: False):
                Will this operation overwrite the coldkeypub (if exists) under the same path <wallet path>/<wallet name>/coldkeypub
        Returns:
            wallet (bittensor.wallet):
                newly re-generated wallet with coldkeypub.

        """
        if ss58_address is None and public_key is None:
            raise ValueError("Either ss58_address or public_key must be passed")

        if not utils.is_valid_bittensor_address_or_public_key(
            ss58_address if ss58_address is not None else public_key
        ):
            raise ValueError(
                f"Invalid {'ss58_address' if ss58_address is not None else 'public_key'}"
            )

        if ss58_address is not None:
            ss58_format = utils.get_ss58_format(ss58_address)
            keypair = Keypair(
                ss58_address=ss58_address,
                public_key=public_key,
                ss58_format=ss58_format,
            )
        else:
            keypair = Keypair(
                ss58_address=ss58_address,
                public_key=public_key,
                ss58_format=__ss58_format__,
            )

        # No need to encrypt the public key
        self.set_coldkeypub(keypair, overwrite=overwrite)

        return self

    # Short name for regenerate_coldkeypub
    regen_coldkeypub = regenerate_coldkeypub

    @overload
    def regenerate_coldkey(
        self,
        mnemonic: Optional[Union[list, str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        ...

    @overload
    def regenerate_coldkey(
        self,
        seed: Optional[str] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        ...

    @overload
    def regenerate_coldkey(
        self,
        json: Optional[Tuple[Union[str, Dict], str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        ...

    def regenerate_coldkey(
        self,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
        **kwargs,
    ) -> "wallet":
        """Regenerates the coldkey from passed mnemonic, seed, or json encrypts it with the user's password and saves the file
        Args:
            mnemonic: (Union[list, str], optional):
                Key mnemonic as list of words or string space separated words.
            seed: (str, optional):
                Seed as hex string.
            json: (Tuple[Union[str, Dict], str], optional):
                Restore from encrypted JSON backup as (json_data: Union[str, Dict], passphrase: str)
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created coldkey.

        Note: uses priority order: mnemonic > seed > json
        """
        if len(kwargs) == 0:
            raise ValueError("Must pass either mnemonic, seed, or json")

        # Get from kwargs
        mnemonic = kwargs.get("mnemonic", None)
        seed = kwargs.get("seed", None)
        json = kwargs.get("json", None)

        if mnemonic is None and seed is None and json is None:
            raise ValueError("Must pass either mnemonic, seed, or json")
        if mnemonic is not None:
            if isinstance(mnemonic, str):
                mnemonic = mnemonic.split()
            if len(mnemonic) not in [12, 15, 18, 21, 24]:
                raise ValueError(
                    "Mnemonic has invalid size. This should be 12,15,18,21 or 24 words"
                )
            keypair = Keypair.create_from_mnemonic(
                " ".join(mnemonic), ss58_format=__ss58_format__
            )
            if not suppress:
                display_mnemonic_msg(keypair, "coldkey")
        elif seed is not None:
            keypair = Keypair.create_from_seed(seed, ss58_format=__ss58_format__)
        else:
            # json is not None
            if (
                not isinstance(json, tuple)
                or len(json) != 2
                or not isinstance(json[0], (str, dict))
                or not isinstance(json[1], str)
            ):
                raise ValueError(
                    "json must be a tuple of (json_data: str | Dict, passphrase: str)"
                )

            json_data, passphrase = json
            keypair = Keypair.create_from_encrypted_json(
                json_data, passphrase, ss58_format=__ss58_format__
            )

        self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    # Short name for regenerate_coldkey
    regen_coldkey = regenerate_coldkey

    @overload
    def regenerate_hotkey(
        self,
        mnemonic: Optional[Union[list, str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        ...

    @overload
    def regenerate_hotkey(
        self,
        seed: Optional[str] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        ...

    @overload
    def regenerate_hotkey(
        self,
        json: Optional[Tuple[Union[str, Dict], str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "wallet":
        ...

    def regenerate_hotkey(
        self,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
        **kwargs,
    ) -> "wallet":
        """Regenerates the hotkey from passed mnemonic, encrypts it with the user's password and save the file
        Args:
            mnemonic: (Union[list, str], optional):
                Key mnemonic as list of words or string space separated words.
            seed: (str, optional):
                Seed as hex string.
            json: (Tuple[Union[str, Dict], str], optional):
                Restore from encrypted JSON backup as (json_data: Union[str, Dict], passphrase: str)
            use_password (bool, optional):
                Is the created key password protected.
            overwrite (bool, optional):
                Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            suppress (bool, optional):
                Suppress the display of the mnemonic.
        Returns:
            wallet (bittensor.wallet):
                this object with newly created hotkey.
        """
        if len(kwargs) == 0:
            raise ValueError("Must pass either mnemonic, seed, or json")

        # Get from kwargs
        mnemonic = kwargs.get("mnemonic", None)
        seed = kwargs.get("seed", None)
        json = kwargs.get("json", None)

        if mnemonic is None and seed is None and json is None:
            raise ValueError("Must pass either mnemonic, seed, or json")
        if mnemonic is not None:
            if isinstance(mnemonic, str):
                mnemonic = mnemonic.split()
            if len(mnemonic) not in [12, 15, 18, 21, 24]:
                raise ValueError(
                    "Mnemonic has invalid size. This should be 12,15,18,21 or 24 words"
                )
            keypair = Keypair.create_from_mnemonic(
                " ".join(mnemonic), ss58_format=__ss58_format__
            )
            if not suppress:
                display_mnemonic_msg(keypair, "hotkey")
        elif seed is not None:
            keypair = Keypair.create_from_seed(seed, ss58_format=__ss58_format__)
        else:
            # json is not None
            if (
                not isinstance(json, tuple)
                or len(json) != 2
                or not isinstance(json[0], (str, dict))
                or not isinstance(json[1], str)
            ):
                raise ValueError(
                    "json must be a tuple of (json_data: str | Dict, passphrase: str)"
                )

            json_data, passphrase = json
            keypair = Keypair.create_from_encrypted_json(
                json_data, passphrase, ss58_format=__ss58_format__
            )

        self.set_hotkey(keypair, encrypt=use_password, overwrite=overwrite)
        return self

    # Short name for regenerate_hotkey
    regen_hotkey = regenerate_hotkey
