# The MIT License (MIT)
# Copyright © 2021 Yuma Rao
# Copyright © 2021-2022 Opentensor Foundation
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
import pytest
import shutil
import time
import unittest
from unittest.mock import patch

from bittensor_wallet.keypair_impl import Keypair
from bittensor_wallet.wallet_impl import Wallet
from bittensor_wallet._keyfile import Keyfile, keyfile
from bittensor_wallet._keyfile.keyfile_impl import validate_password, ask_password_to_encrypt, decrypt_keyfile_data, KeyFileError
from bittensor_wallet.mock import MockKeyfile, MockWallet

class TestWallet(unittest.TestCase):

    def test_regen_coldkeypub_from_ss58_addr(self):
        ss58_address = "5DD26kC2kxajmwfbbZmVmxhrY9VeeyR1Gpzy9i8wxLUg6zxm"
        mock_wallet = MockWallet( name=f"mock", hotkey="mock_hk", path=f"/tmp/mock-wallet-{self.id()}" )
        with patch.object(mock_wallet, 'set_coldkeypub') as mock_set_coldkeypub:
            mock_wallet.regenerate_coldkeypub( ss58_address=ss58_address )

            mock_set_coldkeypub.assert_called_once()
            keypair: Keypair = mock_set_coldkeypub.call_args_list[0][0][0]
            self.assertEqual(keypair.ss58_address, ss58_address)

        ss58_address_bad = "5DD26kC2kxajmwfbbZmVmxhrY9VeeyR1Gpzy9i8wxLUg6zx" # 1 character short
        with pytest.raises(ValueError):
            mock_wallet.regenerate_coldkeypub(ss58_address=ss58_address_bad)

    def test_regen_coldkeypub_from_hex_pubkey_str(self):
        pubkey_str = "0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512f"

        mock_wallet = MockWallet( name=f"mock", hotkey="mock_hk", path=f"/tmp/mock-wallet-{self.id()}" )
        with patch.object(mock_wallet, 'set_coldkeypub') as mock_set_coldkeypub:
            mock_wallet.regenerate_coldkeypub(public_key=pubkey_str)

            mock_set_coldkeypub.assert_called_once()
            keypair: Keypair = mock_set_coldkeypub.call_args_list[0][0][0]
            self.assertEqual('0x' + keypair.public_key.hex(), pubkey_str)

        pubkey_str_bad = "0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512" # 1 character short
        with pytest.raises(ValueError):
            mock_wallet.regenerate_coldkeypub(ss58_address=pubkey_str_bad)

    def test_regen_coldkeypub_from_hex_pubkey_bytes(self):
        pubkey_str = "0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512f"
        pubkey_bytes = bytes.fromhex(pubkey_str[2:]) # Remove 0x from beginning

        mock_wallet = MockWallet( name=f"mock", hotkey="mock_hk", path=f"/tmp/mock-wallet-{self.id()}" )
        with patch.object(mock_wallet, 'set_coldkeypub') as mock_set_coldkeypub:
            mock_wallet.regenerate_coldkeypub(public_key=pubkey_bytes)

            mock_set_coldkeypub.assert_called_once()
            keypair: Keypair = mock_set_coldkeypub.call_args_list[0][0][0]
            self.assertEqual(keypair.public_key, pubkey_bytes)

    def test_regen_coldkeypub_no_pubkey(self):
        mock_wallet = MockWallet( name=f"mock", hotkey="mock_hk", path=f"/tmp/mock-wallet-{self.id()}" )

        with pytest.raises(ValueError):
            # Must provide either public_key or ss58_address
            mock_wallet.regenerate_coldkeypub(ss58_address=None, public_key=None)

    def test_regen_coldkey_from_hex_seed_str(self):
        ss58_addr = "5D5cwd8DX6ij7nouVcoxDuWtJfiR1BnzCkiBVTt7DU8ft5Ta"
        seed_str = "0x659c024d5be809000d0d93fe378cfde020846150b01c49a201fc2a02041f7636"

        mock_wallet = MockWallet( name=f"mock", hotkey="mock_hk", path=f"/tmp/mock-wallet-{self.id()}" )
        with patch.object(mock_wallet, 'set_coldkey') as mock_set_coldkey:
            mock_wallet.regenerate_coldkey(seed=seed_str)

            mock_set_coldkey.assert_called_once()
            keypair: Keypair = mock_set_coldkey.call_args_list[0][0][0]
            self.assertRegex(keypair.seed_hex if isinstance(keypair.seed_hex, str) else keypair.seed_hex.hex(), rf'(0x|){seed_str[2:]}')
            self.assertEqual(keypair.ss58_address, ss58_addr) # Check that the ss58 address is correct

        seed_str_bad = "0x659c024d5be809000d0d93fe378cfde020846150b01c49a201fc2a02041f763" # 1 character short
        with pytest.raises(ValueError):
            mock_wallet.regenerate_coldkey(seed=seed_str_bad)

    def test_regen_hotkey_from_hex_seed_str(self):
        ss58_addr = "5D5cwd8DX6ij7nouVcoxDuWtJfiR1BnzCkiBVTt7DU8ft5Ta"
        seed_str = "0x659c024d5be809000d0d93fe378cfde020846150b01c49a201fc2a02041f7636"

        mock_wallet = MockWallet( name=f"mock", hotkey="mock_hk", path=f"/tmp/mock-wallet-{self.id()}" )
        with patch.object(mock_wallet, 'set_hotkey') as mock_set_hotkey:
            mock_wallet.regenerate_hotkey(seed=seed_str)

            mock_set_hotkey.assert_called_once()
            keypair: Keypair = mock_set_hotkey.call_args_list[0][0][0]
            self.assertRegex(keypair.seed_hex if isinstance(keypair.seed_hex, str) else keypair.seed_hex.hex(), rf'(0x|){seed_str[2:]}')
            self.assertEqual(keypair.ss58_address, ss58_addr) # Check that the ss58 address is correct

        seed_str_bad = "0x659c024d5be809000d0d93fe378cfde020846150b01c49a201fc2a02041f763" # 1 character short
        with pytest.raises(ValueError):
            mock_wallet.regenerate_hotkey(seed=seed_str_bad)


class TestKeyFiles(unittest.TestCase):

    def setUp(self) -> None:
        self.root_path = f"/tmp/pytest{time.time()}"
        os.makedirs(self.root_path)

        self.create_keyfile()

    def tearDown(self) -> None:
        shutil.rmtree(self.root_path)

    def create_keyfile(self):
        _keyfile = keyfile(path=os.path.join(self.root_path, "keyfile"))

        mnemonic = Keypair.generate_mnemonic(12)
        alice = Keypair.create_from_mnemonic(mnemonic)
        _keyfile.set_keypair(alice, encrypt=True, overwrite=True, password='thisisafakepassword')

        bob = Keypair.create_from_uri('/Bob')
        _keyfile.set_keypair(bob, encrypt=True, overwrite=True, password='thisisafakepassword')

        return keyfile

    def test_create(self):
        _keyfile = keyfile(path=os.path.join(self.root_path, "keyfile"))

        mnemonic = Keypair.generate_mnemonic( 12 )
        alice = Keypair.create_from_mnemonic(mnemonic)
        _keyfile.set_keypair(alice, encrypt=True, overwrite=True, password = 'thisisafakepassword')
        assert _keyfile.is_readable()
        assert _keyfile.is_writable()
        assert _keyfile.is_encrypted()
        _keyfile.decrypt( password = 'thisisafakepassword' )
        assert not _keyfile.is_encrypted()
        _keyfile.encrypt( password = 'thisisafakepassword' )
        assert _keyfile.is_encrypted()
        str(keyfile)
        _keyfile.decrypt( password = 'thisisafakepassword' )
        assert not _keyfile.is_encrypted()
        str(keyfile)

        assert _keyfile.get_keypair( password = 'thisisafakepassword' ).ss58_address == alice.ss58_address
        assert _keyfile.get_keypair( password = 'thisisafakepassword' ).private_key == alice.private_key
        assert _keyfile.get_keypair( password = 'thisisafakepassword' ).public_key == alice.public_key

        bob = Keypair.create_from_uri ('/Bob')
        _keyfile.set_keypair(bob, encrypt=True, overwrite=True, password = 'thisisafakepassword')
        assert _keyfile.get_keypair( password = 'thisisafakepassword' ).ss58_address == bob.ss58_address
        assert _keyfile.get_keypair( password = 'thisisafakepassword' ).public_key == bob.public_key

        repr(keyfile)

    def test_legacy_coldkey(self):
        legacy_filename = os.path.join(self.root_path, "coldlegacy_keyfile")
        _keyfile = keyfile (path = legacy_filename)
        _keyfile.make_dirs()
        keyfile_data = b'0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512f'
        with open(legacy_filename, "wb") as keyfile_obj:
            keyfile_obj.write( keyfile_data )
        assert _keyfile.keyfile_data == keyfile_data
        _keyfile.encrypt( password = 'this is the fake password' )
        _keyfile.decrypt( password = 'this is the fake password' )
        keypair_bytes = b'{"accountId": "0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512f", "publicKey": "0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512f", "secretPhrase": null, "secretSeed": null, "ss58Address": "5DD26kC2kxajmwfbbZmVmxhrY9VeeyR1Gpzy9i8wxLUg6zxm"}'
        assert _keyfile.keyfile_data == keypair_bytes
        assert _keyfile.get_keypair().ss58_address == "5DD26kC2kxajmwfbbZmVmxhrY9VeeyR1Gpzy9i8wxLUg6zxm"
        assert "0x" + _keyfile.get_keypair().public_key.hex() == "0x32939b6abc4d81f02dff04d2b8d1d01cc8e71c5e4c7492e4fa6a238cdca3512f"

    def test_validate_password(self):
        assert validate_password(None) == False
        assert validate_password('passw0rd') == False
        assert validate_password('123456789') == False
        with patch('getpass.getpass',return_value='biTTensor'):
            assert validate_password('biTTensor') == True
        with patch('getpass.getpass',return_value='biTTenso'):
            assert validate_password('biTTensor') == False

    def test_decrypt_keyfile_data_legacy(self):
        import base64

        from cryptography.fernet import Fernet
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        __SALT = b"Iguesscyborgslikemyselfhaveatendencytobeparanoidaboutourorigins"

        def __generate_key(password):
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=__SALT, length=32, iterations=10000000, backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key

        pw = 'fakepasssword238947239'
        data = b'encrypt me!'
        key = __generate_key(pw)
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data)

        decrypted_data = decrypt_keyfile_data( encrypted_data, pw)
        assert decrypted_data == data

    def test_user_interface(self):
        with patch('getpass.getpass', side_effect = ['pass', 'password', 'asdury3294y', 'asdury3294y']):
            assert ask_password_to_encrypt() == 'asdury3294y'

    def test_overwriting(self):
        _keyfile = keyfile (path = os.path.join(self.root_path, "keyfile"))
        alice = Keypair.create_from_uri ('/Alice')
        _keyfile.set_keypair(alice, encrypt=True, overwrite=True, password = 'thisisafakepassword')
        bob = Keypair.create_from_uri ('/Bob')

        with pytest.raises(KeyFileError) as pytest_wrapped_e:
            with patch('builtins.input', return_value = 'n'):
                _keyfile.set_keypair(bob, encrypt=True, overwrite=False, password = 'thisisafakepassword')

    def test_keyfile_mock(self):
        with patch('bittensor_wallet._keyfile.keyfile.__new__', return_value=MockKeyfile(path='/tmp/test-wallet/keyfile')):
            file = keyfile( )
            assert file.exists_on_device()
            assert not file.is_encrypted()
            assert file.is_readable()
            assert file.data
            assert file.keypair
            file.set_keypair( keypair = Keypair.create_from_mnemonic( mnemonic = Keypair.generate_mnemonic() ))
