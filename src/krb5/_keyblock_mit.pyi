# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context
from krb5._keyblock import KeyBlock

def c_string_to_key(
    context: Context,
    enctype: int,
    string: bytes,
    salt: bytes,
    s2kparams: typing.Optional[bytes] = None,
) -> KeyBlock:
    """Convert a password string to a key.

    Convert a password string and a salt value plus optional S2K parameters
    to a keyblock with a certain encryption type. For getting the salt value,
    encryption type and the S2K parameters the method :meth:`get_etype_info`
    can be used.

    Args:
        context: Krb5 context.
        enctype: The encryption type to be used.
        string: The password string.
        salt: The salt string.
        s2kparams: The S2K parameters.

    Returns:
        KeyBlock: The keyblock.
    """
