# The MIT License (MIT)
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

from .keyfile_impl import Keyfile as Keyfile, KeyFileError as KeyFileError, serialized_keypair_to_keyfile_data as serialized_keypair_to_keyfile_data

class keyfile (object):
    """ Factory for a bittensor on device keypair
    """
    def __new__( cls, path: str = None ) -> 'keyfile_impl.Keyfile':
        r""" Initialize a bittensor on device keypair interface.

            Args:
                path (required=False, default: ~/.bittensor/wallets/default/coldkey ):
                    Path where this keypair is stored.
        """
        path = '~/.bittensor/wallets/default/coldkey' if path == None else path
        return keyfile_impl.Keyfile( path = path )
