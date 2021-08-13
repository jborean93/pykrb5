# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

class Context:
    """Kerberos Library Context

    This class represents a library context object.
    """

def init_context() -> Context:
    """Create a krb5 library context.

    Creates a krb5 library context.

    Returns:
        Context: The opened krb5 library context.
    """

def get_default_realm(
    context: Context,
) -> bytes:
    """Get default realm for the specified context.

    Returns the default realm of the context passed in.

    Args:
        context: Krb5 context.

    Returns:
        bytes: The default realm of the context.
    """

def set_default_realm(
    context: Context,
    realm: typing.Optional[bytes],
) -> None:
    """Override the default realm for the specified context.

    Sets the default realm of the passed in context to the value specified. Use
    ``None`` to clear out the existing explicit setting.

    Args:
        context: Krb5 context.
        realm: The realm to set as the default realm.
    """
