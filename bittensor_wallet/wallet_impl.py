""" Implementation of the wallet class, which manages balances with staking and transfer. Also manages hotkey and coldkey.
"""
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

import os
from typing import Optional, Union, Tuple, Dict, overload, Any, TypedDict
import bittensor_config

from substrateinterface import Keypair
from termcolor import colored

from . import __ss58_format__
from .utils import is_valid_bittensor_address_or_public_key, get_ss58_format
from ._keyfile import Keyfile, keyfile


def display_mnemonic_msg( keypair : Keypair, key_type : str ):
    """ Displaying the mnemonic and warning message to keep mnemonic safe
    """
    mnemonic = keypair.mnemonic
    mnemonic_green = colored(mnemonic, 'green')
    print (colored("\nIMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone " \
                "who has possesion of this mnemonic can use it to regenerate the key and access your tokens. \n", "red"))
    print ("The mnemonic to the new {} is:\n\n{}\n".format(key_type, mnemonic_green))
    print ("You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:")
    print("btcli regen_{} --mnemonic {}".format(key_type, mnemonic))
    print('')


class WalletConfigDefault(TypedDict):
    name: str
    hotkey: str
    path: str

class WalletConfig(bittensor_config.DefaultConfig):
    name: str
    hotkey: str
    path: str

    defaults: WalletConfigDefault = {
        "name": 'default',
        "hotkey": 'default',
        "path": '~/.bittensor/wallets/'
    }

    def __init__(self, name: str = None, hotkey: str = None, path: str = None, **kwargs):
        super().__init__(
            loaded_config=None,
            default = None
        )
        
        self.name = name or self.defaults['name']
        self.hotkey = hotkey or self.defaults['hotkey']
        self.path = path or self.defaults['path']
        self.update(kwargs)

    @classmethod
    def default(cls) -> 'WalletConfig':
        wallet_config = cls()
        wallet_config.update_with_kwargs(cls.defaults)

        return wallet_config

class Wallet():
    """
    Bittensor wallet maintenance class. Each wallet contains a coldkey and a hotkey.
    The coldkey is the user's primary key for holding stake in their wallet
    and is the only way that users can access Tao. Coldkeys can hold tokens and should be encrypted on your device.
    The coldkey must be used to stake and unstake funds from a running node. The hotkey, on the other hand, is only used
    for suscribing and setting weights from running code. Hotkeys are linked to coldkeys through the metagraph.
    """
    def __init__(
        self,
        name:str,
        path:str,
        hotkey:str,
        config: Optional[WalletConfig] = None,
    ):
        r""" Init bittensor wallet object containing a hot and coldkey.
            Args:
                name (required=True, default='default):
                    The name of the wallet to unlock for running bittensor
                hotkey (required=True, default='default):
                    The name of hotkey used to running the miner.
                path (required=True, default='~/.bittensor/wallets/'):
                    The path to your bittensor wallets
                config (:obj:`WalletConfig`, `optional`):
                    Wallet configuration object.
        """
        self.name = name
        self.path = path
        self.hotkey_str = hotkey
        self._hotkey = None
        self._coldkey = None
        self._coldkeypub = None
        self.config = config

    def __str__(self):
        return "Wallet ({}, {}, {})".format(self.name, self.hotkey_str, self.path)

    def __repr__(self):
        return self.__str__()

    def create_if_non_existent( self, coldkey_use_password:bool = True, hotkey_use_password:bool = False) -> 'Wallet':
        """ Checks for existing coldkeypub and hotkeys and creates them if non-existent.
        """
        return self.create(coldkey_use_password, hotkey_use_password)

    def create (self, coldkey_use_password:bool = True, hotkey_use_password:bool = False ) -> 'Wallet':
        """ Checks for existing coldkeypub and hotkeys and creates them if non-existent.
        """
        # ---- Setup Wallet. ----
        if not self.coldkey_file.exists_on_device() and not self.coldkeypub_file.exists_on_device():
            self.create_new_coldkey( n_words = 12, use_password = coldkey_use_password )
        if not self.hotkey_file.exists_on_device():
            self.create_new_hotkey( n_words = 12, use_password = hotkey_use_password )
        return self

    def recreate (self, coldkey_use_password:bool = True, hotkey_use_password:bool = False ) -> 'Wallet':
        """ Checks for existing coldkeypub and hotkeys and creates them if non-existent.
        """
        # ---- Setup Wallet. ----
        self.create_new_coldkey( n_words = 12, use_password = coldkey_use_password )
        self.create_new_hotkey( n_words = 12, use_password = hotkey_use_password )
        return self

    @property
    def hotkey_file(self) -> 'Keyfile':

        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        hotkey_path = os.path.join(wallet_path, "hotkeys", self.hotkey_str)
        return keyfile( path = hotkey_path )

    @property
    def coldkey_file(self) -> 'Keyfile':
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        coldkey_path = os.path.join(wallet_path, "coldkey")
        return keyfile( path = coldkey_path )

    @property
    def coldkeypub_file(self) -> 'Keyfile':
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        coldkeypub_path = os.path.join(wallet_path, "coldkeypub.txt")
        return Keyfile( path = coldkeypub_path )

    def set_hotkey(self, keypair: 'Keypair', encrypt: bool = False, overwrite: bool = False) -> 'Keyfile':
        self._hotkey = keypair
        self.hotkey_file.set_keypair( keypair, encrypt = encrypt, overwrite = overwrite )

    def set_coldkeypub(self, keypair: 'Keypair', encrypt: bool = False, overwrite: bool = False) -> 'Keyfile':
        self._coldkeypub = Keypair(ss58_address=keypair.ss58_address)
        self.coldkeypub_file.set_keypair( self._coldkeypub, encrypt = encrypt, overwrite = overwrite  )

    def set_coldkey(self, keypair: 'Keypair', encrypt: bool = True, overwrite: bool = False) -> 'Keyfile':
        self._coldkey = keypair
        self.coldkey_file.set_keypair( self._coldkey, encrypt = encrypt, overwrite = overwrite )

    def get_coldkey(self, password: str = None ) -> 'Keypair':
        self.coldkey_file.get_keypair( password = password )

    def get_hotkey(self, password: str = None ) -> 'Keypair':
        self.hotkey_file.get_keypair( password = password )

    def get_coldkeypub(self, password: str = None ) -> 'Keypair':
        self.coldkeypub_file.get_keypair( password = password )

    @property
    def hotkey(self) -> 'Keypair':
        r""" Loads the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.
            Returns:
                hotkey (Keypair):
                    hotkey loaded from config arguments.
            Raises:
                KeyFileError: Raised if the file is corrupt of non-existent.
                CryptoKeyError: Raised if the user enters an incorrec password for an encrypted keyfile.
        """
        if self._hotkey == None:
            self._hotkey = self.hotkey_file.keypair
        return self._hotkey

    @property
    def coldkey(self) -> 'Keypair':
        r""" Loads the hotkey from wallet.path/wallet.name/coldkey or raises an error.
            Returns:
                coldkey (Keypair):
                    colkey loaded from config arguments.
            Raises:
                KeyFileError: Raised if the file is corrupt of non-existent.
                CryptoKeyError: Raised if the user enters an incorrec password for an encrypted keyfile.
        """
        if self._coldkey == None:
            self._coldkey = self.coldkey_file.keypair
        return self._coldkey

    @property
    def coldkeypub(self) -> 'Keypair':
        r""" Loads the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.
            Returns:
                coldkeypub (Keypair):
                    colkeypub loaded from config arguments.
            Raises:
                KeyFileError: Raised if the file is corrupt of non-existent.
                CryptoKeyError: Raised if the user enters an incorrect password for an encrypted keyfile.
        """
        if self._coldkeypub == None:
            self._coldkeypub = self.coldkeypub_file.keypair
        return self._coldkeypub

    def create_coldkey_from_uri(self, uri:str, use_password: bool = True, overwrite:bool = False) -> 'Wallet':
        """ Creates coldkey from suri string, optionally encrypts it with the user's inputed password.
            Args:
                uri: (str, required):
                    URI string to use i.e. /Alice or /Bob
                use_password (bool, optional):
                    Is the created key password protected.
                overwrite (bool, optional):
                    Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created coldkey.
        """
        keypair = Keypair.create_from_uri( uri )
        display_mnemonic_msg( keypair, "coldkey" )
        self.set_coldkey( keypair, encrypt = use_password, overwrite = overwrite)
        self.set_coldkeypub( keypair, overwrite = overwrite)
        return self

    def create_hotkey_from_uri( self, uri:str, use_password: bool = False, overwrite:bool = False) -> 'Wallet':
        """ Creates hotkey from suri string, optionally encrypts it with the user's inputed password.
            Args:
                uri: (str, required):
                    URI string to use i.e. /Alice or /Bob
                use_password (bool, optional):
                    Is the created key password protected.
                overwrite (bool, optional):
                    Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created hotkey.
        """
        keypair = Keypair.create_from_uri( uri )
        display_mnemonic_msg( keypair, "hotkey" )
        self.set_hotkey( keypair, encrypt=use_password, overwrite = overwrite)
        return self

    def new_coldkey( self, n_words:int = 12, use_password: bool = True, overwrite:bool = False) -> 'Wallet':
        """ Creates a new coldkey, optionally encrypts it with the user's inputed password and saves to disk.
            Args:
                n_words: (int, optional):
                    Number of mnemonic words to use.
                use_password (bool, optional):
                    Is the created key password protected.
                overwrite (bool, optional):
                    Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created coldkey.
        """
        self.create_new_coldkey( n_words, use_password, overwrite )

    def create_new_coldkey( self, n_words:int = 12, use_password: bool = True, overwrite:bool = False) -> 'Wallet':
        """ Creates a new coldkey, optionally encrypts it with the user's inputed password and saves to disk.
            Args:
                n_words: (int, optional):
                    Number of mnemonic words to use.
                use_password (bool, optional):
                    Is the created key password protected.
                overwrite (bool, optional):
                    Will this operation overwrite the coldkey under the same path <wallet path>/<wallet name>/coldkey
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created coldkey.
        """
        mnemonic = Keypair.generate_mnemonic( n_words)
        keypair = Keypair.create_from_mnemonic(mnemonic)
        display_mnemonic_msg( keypair, "coldkey" )
        self.set_coldkey( keypair, encrypt = use_password, overwrite = overwrite)
        self.set_coldkeypub( keypair, overwrite = overwrite)
        return self

    def new_hotkey( self, n_words:int = 12, use_password: bool = False, overwrite:bool = False) -> 'Wallet':
        """ Creates a new hotkey, optionally encrypts it with the user's inputed password and saves to disk.
            Args:
                n_words: (int, optional):
                    Number of mnemonic words to use.
                use_password (bool, optional):
                    Is the created key password protected.
                overwrite (bool, optional):
                    Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created hotkey.
        """
        self.create_new_hotkey( n_words, use_password, overwrite )

    def create_new_hotkey( self, n_words:int = 12, use_password: bool = False, overwrite:bool = False) -> 'Wallet':
        """ Creates a new hotkey, optionally encrypts it with the user's inputed password and saves to disk.
            Args:
                n_words: (int, optional):
                    Number of mnemonic words to use.
                use_password (bool, optional):
                    Is the created key password protected.
                overwrite (bool, optional):
                    Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created hotkey.
        """
        mnemonic = Keypair.generate_mnemonic( n_words)
        keypair = Keypair.create_from_mnemonic(mnemonic)
        display_mnemonic_msg( keypair, "hotkey" )
        self.set_hotkey( keypair, encrypt=use_password, overwrite = overwrite)
        return self

    def regenerate_coldkeypub( self, ss58_address: Optional[str] = None, public_key: Optional[Union[str, bytes]] = None, overwrite: bool = False ) -> 'Wallet':
        """ Regenerates the coldkeypub from passed ss58_address or public_key and saves the file
               Requires either ss58_address or public_key to be passed.
            Args:
                ss58_address: (str, optional):
                    Address as ss58 string.
                public_key: (str | bytes, optional):
                    Public key as hex string or bytes.
                overwrite (bool, optional) (default: False):
                    Will this operation overwrite the coldkeypub (if exists) under the same path <wallet path>/<wallet name>/coldkeypub
            Returns:
                wallet (bittensor.Wallet):
                    newly re-generated Wallet with coldkeypub.

        """
        if ss58_address is None and public_key is None:
            raise ValueError("Either ss58_address or public_key must be passed")

        if not is_valid_bittensor_address_or_public_key( ss58_address if ss58_address is not None else public_key ):
            raise ValueError(f"Invalid {'ss58_address' if ss58_address is not None else 'public_key'}")

        if ss58_address is not None:
            ss58_format = get_ss58_format( ss58_address )
            keypair = Keypair(ss58_address=ss58_address, public_key=public_key, ss58_format=ss58_format)
        else:
            keypair = Keypair(ss58_address=ss58_address, public_key=public_key, ss58_format=__ss58_format__)

        # No need to encrypt the public key
        self.set_coldkeypub( keypair, overwrite = overwrite)

        return self

    # Short name for regenerate_coldkeypub
    regen_coldkeypub = regenerate_coldkeypub

    @overload
    def regenerate_coldkey(
            self,
            mnemonic: Optional[Union[list, str]] = None,
            use_password: bool = True,
            overwrite: bool = False
        ) -> 'Wallet':
        ...

    @overload
    def regenerate_coldkey(
            self,
            seed: Optional[str] = None,
            use_password: bool = True,
            overwrite: bool = False
        ) -> 'Wallet':
        ...

    @overload
    def regenerate_coldkey(
            self,
            json: Optional[Tuple[Union[str, Dict], str]] = None,
            use_password: bool = True,
            overwrite: bool = False
        ) -> 'Wallet':
        ...


    def regenerate_coldkey(
            self,
            use_password: bool = True,
            overwrite: bool = False,
            **kwargs
        ) -> 'Wallet':
        """ Regenerates the coldkey from passed mnemonic, seed, or json encrypts it with the user's password and saves the file
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
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created coldkey.

            Note: uses priority order: mnemonic > seed > json
        """
        if len(kwargs) == 0:
            raise ValueError("Must pass either mnemonic, seed, or json")

        # Get from kwargs
        mnemonic = kwargs.get('mnemonic', None)
        seed = kwargs.get('seed', None)
        json = kwargs.get('json', None)

        if mnemonic is None and seed is None and json is None:
            raise ValueError("Must pass either mnemonic, seed, or json")
        if mnemonic is not None:
            if isinstance( mnemonic, str): mnemonic = mnemonic.split()
            if len(mnemonic) not in [12,15,18,21,24]:
                raise ValueError("Mnemonic has invalid size. This should be 12,15,18,21 or 24 words")
            keypair = Keypair.create_from_mnemonic(" ".join(mnemonic), ss58_format=__ss58_format__ )
            display_mnemonic_msg( keypair, "coldkey" )
        elif seed is not None:
            keypair = Keypair.create_from_seed(seed, ss58_format=__ss58_format__ )
        else:
            # json is not None
            if not isinstance(json, tuple) or len(json) != 2 or not isinstance(json[0], (str, dict)) or not isinstance(json[1], str):
                raise ValueError("json must be a tuple of (json_data: str | Dict, passphrase: str)")

            json_data, passphrase = json
            keypair = Keypair.create_from_encrypted_json( json_data, passphrase, ss58_format=__ss58_format__ )

        self.set_coldkey( keypair, encrypt = use_password, overwrite = overwrite)
        self.set_coldkeypub( keypair, overwrite = overwrite)
        return self

    # Short name for regenerate_coldkey
    regen_coldkey = regenerate_coldkey

    @overload
    def regenerate_hotkey(
            self,
            mnemonic: Optional[Union[list, str]] = None,
            use_password: bool = True,
            overwrite: bool = False
        ) -> 'Wallet':
        ...

    @overload
    def regenerate_hotkey(
            self,
            seed: Optional[str] = None,
            use_password: bool = True,
            overwrite: bool = False
        ) -> 'Wallet':
        ...

    @overload
    def regenerate_hotkey(
            self,
            json: Optional[Tuple[Union[str, Dict], str]] = None,
            use_password: bool = True,
            overwrite: bool = False
        ) -> 'Wallet':
        ...

    def regenerate_hotkey(
            self,
            use_password: bool = True,
            overwrite: bool = False,
            **kwargs
        ) -> 'Wallet':
        """ Regenerates the hotkey from passed mnemonic, encrypts it with the user's password and save the file
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
            Returns:
                wallet (bittensor.Wallet):
                    this object with newly created hotkey.
        """
        if len(kwargs) == 0:
            raise ValueError("Must pass either mnemonic, seed, or json")

        # Get from kwargs
        mnemonic = kwargs.get('mnemonic', None)
        seed = kwargs.get('seed', None)
        json = kwargs.get('json', None)

        if mnemonic is None and seed is None and json is None:
            raise ValueError("Must pass either mnemonic, seed, or json")
        if mnemonic is not None:
            if isinstance( mnemonic, str): mnemonic = mnemonic.split()
            if len(mnemonic) not in [12,15,18,21,24]:
                raise ValueError("Mnemonic has invalid size. This should be 12,15,18,21 or 24 words")
            keypair = Keypair.create_from_mnemonic(" ".join(mnemonic), ss58_format=__ss58_format__ )
            display_mnemonic_msg( keypair, "hotkey" )
        elif seed is not None:
            keypair = Keypair.create_from_seed(seed, ss58_format=__ss58_format__ )
        else:
            # json is not None
            if not isinstance(json, tuple) or len(json) != 2 or not isinstance(json[0], (str, dict)) or not isinstance(json[1], str):
                raise ValueError("json must be a tuple of (json_data: str | Dict, passphrase: str)")

            json_data, passphrase = json
            keypair = Keypair.create_from_encrypted_json( json_data, passphrase, ss58_format=__ss58_format__ )


        self.set_hotkey( keypair, encrypt=use_password, overwrite = overwrite)
        return self

    # Short name for regenerate_hotkey
    regen_hotkey = regenerate_hotkey
