# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context

class KeyBlock:
    """Kerberos KeyBlock

    This class represents the contents of a key.

    Args:
        context: Krb5 context.
    """

    def __len__(self) -> int: ...
    @property
    def data(self) -> bytes:
        """The keyblock data."""
    @property
    def enctype(self) -> int:
        """The keyblock encryption type."""

def init_keyblock(
    context: Context,
    enctype: int,
    key: typing.Optional[bytes],
) -> KeyBlock:
    """Initialize a Key Block.

    Initalize a new keyblock and copy the key into the contents of that block.
    The key can be None or an empty byte string to represent the contents are
    not allocated.

    Args:
        context: Krb5 context.
        enctype: The encryption type of the keyblock.
        key: The data to place in the keyblock or None for an empty block.

    Returns:
        KeyBlock: The initialized keyblock.
    """
