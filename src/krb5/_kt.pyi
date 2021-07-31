# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context

class KeyTab:
    """Kerberos KeyTab object.

    This class represents a Kerberos key table.

    Args:
        context: Krb5 context.
    """

    @property
    def addr(self) -> typing.Optional[int]:
        """The raw krb5_keytab pointer address of this credential cache."""
    @property
    def name(self) -> typing.Optional[bytes]:
        """The name/residual of the keytab."""
    @property
    def kt_type(self) -> typing.Optional[bytes]:
        """The type of the keytab."""

def kt_default(
    context: Context,
) -> KeyTab:
    """Resolve the default key table.

    Get a handle to the default keytab.

    Args:
        context: Krb5 context.

    Returns:
        KeyTab: The default keytab.
    """

def kt_default_name(
    context: Context,
) -> bytes:
    """Get the default key table name.

    Gets the name of the default key table for the context specified.

    Args:
        context: Krb5 context.

    Returns:
        bytes: The default key table name.
    """

def kt_get_name(
    context: Context,
    keytab: KeyTab,
) -> bytes:
    """Get a key table name.

    Get the name of the specified key table. See :meth:`kt_get_type()` to get
    the type of a keytab.

    Note:
        MIT Kerberos returns the full name whereas Heimdal just returns the
        name/residual. See :meth:`krb5_get_full_name` for the equivalent in
        Heimdal.

    Args:
        context: Krb5 context.
        keytab: The keytab to query.

    Returns:
        bytes: The name of the keytab.
    """

def kt_get_type(
    context: Context,
    keytab: KeyTab,
) -> bytes:
    """Get a key table type.

    Get the type of the specified key table. See :meth:`ky_get_name()` to get
    the name of a keytab.

    Args:
        context: Krb5 context.
        keytab: The keytab to query.

    Returns:
        bytes: The type of the keytab.
    """

def kt_resolve(
    context: Context,
    name: bytes,
) -> KeyTab:
    """Get a handle for a key table.

    Resolve the key table name and open a handle. The name must be of the from
    ``type:residual`` where type must be known to the library. If no type is
    specified then ``FILE`` is used as a default. The ``residual`` value is
    dependent on the type specified.

    Args:
        context: Krb5 context.
        name: The name of the keytab in the form ``type:residual``.

    Returns:
        KeyTab: The opened keytab.
    """
