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

__version__ = "0.0.4"
__ss58_format__ = 42 # Bittensor ss58 format

import argparse
import copy
import os
from typing import Optional

import bittensor_config

from .wallet_impl import Wallet as Wallet, WalletConfig as WalletConfig
from ._keyfile import Keyfile as Keyfile, KeyFileError as KeyFileError, keyfile as keyfile, serialized_keypair_to_keyfile_data as serialized_keypair_to_keyfile_data
from .keypair_impl import Keypair as Keypair
from . import utils as utils


class wallet:
    """ Create and init wallet that stores hot and coldkey
    """    
    defaults: WalletConfig = WalletConfig.default()

    def __new__(
            cls,
            config: Optional[WalletConfig] = None,
            name: str = None,
            hotkey: str = None,
            path: str = None,
        ) -> 'wallet_impl.Wallet':
        r""" Init bittensor wallet object containing a hot and coldkey.

            Args:
                config (:obj:`bittensor_config.Config`, `optional`):
                    bittensor_wallet.wallet.config()
                name (required=False, default='default'):
                    The name of the wallet to unlock for running bittensor
                hotkey (required=False, default='default'):
                    The name of hotkey used to running the miner.
                path (required=False, default='~/.bittensor/wallets/'):
                    The path to your bittensor wallets
        """
        if config == None:
            config = wallet.config()
        config = copy.deepcopy( config )
        config.wallet.name = name if name != None else config.wallet.name
        config.wallet.hotkey = hotkey if hotkey != None else config.wallet.hotkey
        config.wallet.path = path if path != None else config.wallet.path
        wallet.check_config( config )

        return wallet_impl.Wallet(
            name = config.wallet.get('name', cls.defaults.name),
            hotkey = config.wallet.get('hotkey', cls.defaults.hotkey),
            path = config.wallet.path,
            config = config
        )

    @classmethod
    def config(cls) -> 'bittensor_config.Config':
        """ Get config from the argument parser
        Return: bittensor_config.config object
        """
        parser = argparse.ArgumentParser()
        wallet.add_args( parser )
        return bittensor_config.config( parser )

    @classmethod
    def help(cls):
        """ Print help to stdout
        """
        parser = argparse.ArgumentParser()
        cls.add_args( parser )
        print (cls.__new__.__doc__)
        parser.print_help()

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser, prefix: str = None ):
        """ Accept specific arguments from parser
        """
        prefix_str = '' if prefix == None else prefix + '.'
        try:
            parser.add_argument('--' + prefix_str + 'wallet.name', required=False, default=cls.defaults.name, help='''The name of the wallet to unlock for running bittensor (name mock is reserved for mocking this wallet)''')
            parser.add_argument('--' + prefix_str + 'wallet.hotkey', required=False, default=cls.defaults.hotkey, help='''The name of wallet's hotkey.''')
            parser.add_argument('--' + prefix_str + 'wallet.path', required=False, default=cls.defaults.path, help='''The path to your bittensor wallets''')
        
        except argparse.ArgumentError as e:
            pass


    @classmethod
    def add_defaults(cls, defaults: bittensor_config.Config, prefix: str = 'wallet' ) -> None:
        """ Adds parser defaults to object, optionally using enviroment variables.
        """
        default_config = WalletConfig()
        default_config.name = os.getenv('BT_WALLET_NAME') if os.getenv('BT_WALLET_NAME') != None else cls.defaults.name
        default_config.hotkey = os.getenv('BT_WALLET_HOTKEY') if os.getenv('BT_WALLET_HOTKEY') != None else cls.defaults.hotkey
        default_config.path = os.getenv('BT_WALLET_PATH') if os.getenv('BT_WALLET_PATH') != None else cls.defaults.path

        setattr( defaults, prefix, default_config )

    @classmethod
    def check_config(cls, config: 'bittensor_config.Config' ):
        """ Check config for wallet name/hotkey/path/hotkeys/sort_by
        """
        assert 'wallet' in config
        assert isinstance(config.wallet.name, str)
        assert isinstance(config.wallet.hotkey, str ) or config.wallet.hotkey == None # Optional
        assert isinstance(config.wallet.path, str)
