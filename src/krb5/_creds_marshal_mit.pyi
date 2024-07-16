# Copyright: (c) 2024 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from krb5._context import Context
from krb5._creds import Creds

def marshal_credentials(
    context: Context,
    creds: Creds,
) -> bytes:
    """Serialize creds.

    Serialize credentials in the format used by the FILE ccache format
    (version 4) and KCM ccache protocol.

    This is only present when compiled against MIT 1.20 or newer.

    Args:
        context: Krb5 context.
        creds: Credentials to serialize.

    Returns:
        bytes: The serialized credentials.
    """

def unmarshal_credentials(
    context: Context,
    data: bytes,
) -> Creds:
    """Deserialize creds.

    Deserialize credentials from the format used by the FILE ccache format
    (version 4) and KCM ccache protocol.

    This is only present when compiled against MIT 1.20 or newer.

    Args:
        context: Krb5 context.
        data: serialized credentials.

    Returns:
        Creds: The unserialized credentials.
    """
