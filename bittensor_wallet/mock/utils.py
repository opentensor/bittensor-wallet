from . import MockWallet
from ..keypair_impl import Keypair


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
