from typing import Optional

from Crypto.Hash import keccak


from bittensor_wallet import __ss58_format__

from .. import MockWallet
from ...keypair_impl import Keypair


def get_mock_wallet(coldkey: "Keypair" = None, hotkey: "Keypair" = None):
    wallet = MockWallet(
        name = 'mock_wallet',
        hotkey = 'mock',
        path = '/tmp/mock_wallet',
    )

    if not coldkey:
        coldkey = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    if not hotkey:
        hotkey = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())

    wallet.set_coldkey(coldkey, encrypt=False, overwrite=True)
    wallet.set_coldkeypub(coldkey, encrypt=False, overwrite=True)
    wallet.set_hotkey(hotkey, encrypt=False, overwrite=True)

    return wallet

def get_mock_keypair( uid: int, test_name: Optional[str] = None ) -> Keypair:
    """
    Returns a mock keypair from a uid and optional test_name.
    If test_name is not provided, the uid is the only seed.
    If test_name is provided, the uid is hashed with the test_name to create a unique seed for the test.
    """
    if test_name is not None:
        hashed_test_name: bytes = keccak.new(digest_bits=256, data=test_name.encode('utf-8')).digest()
        hashed_test_name_as_int: int = int.from_bytes(hashed_test_name, byteorder='big', signed=False)
        uid = uid + hashed_test_name_as_int

    return Keypair.create_from_seed( seed_hex = int.to_bytes(uid, 32, 'big', signed=False), ss58_format = __ss58_format__)

def get_mock_hotkey( uid: int ) -> str:
    return get_mock_keypair(uid).ss58_address

def get_mock_coldkey( uid: int ) -> str:
    return get_mock_keypair(uid).ss58_address
