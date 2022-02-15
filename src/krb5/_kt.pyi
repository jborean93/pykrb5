# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context
from krb5._keyblock import KeyBlock
from krb5._principal import Principal

class KeyTab:
    """Kerberos KeyTab object.

    This class represents a Kerberos key table.

    Args:
        context: Krb5 context.
    """

    def __iter__(self) -> typing.Iterator["KeyTabEntry"]:
        """Iterate through keytab entries.

        Enumerates through all the entries in a keytab. Will fail if the keytab
        being iterated does not exist. It may not be possible to add/remove
        entries on a keytab while it is being enumerated.
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

class KeyTabEntry:
    """Kerberos KeyTabEntry object.

    This class represents a key table entry.

    Note:
        When using a key tab entry from enumerating a :class:`KeyTab`, the
        key and principal value is tied to the lifetime of the entry. Attempting
        to use either of these after the entry is out of scope and has been
        freed will crash the process. The principal can be copied with
        `copy(entry.principal)` to ensure it outlives the entry context.
    """

    @property
    def key(self) -> KeyBlock:
        """The keytab key data block."""
    @property
    def kvno(self) -> int:
        """The key version number associated with the keytab entry."""
    @property
    def principal(self) -> Principal:
        """The principal associated with the keytab entry."""
    @property
    def timestamp(self) -> int:
        """The time creation entry of the keytab entry."""

def kt_add_entry(
    context: Context,
    keytab: KeyTab,
    principal: Principal,
    kvno: int,
    timestamp: int,
    keyblock: KeyBlock,
) -> None:
    """Add new keytab entry.

    Adds a new entry to a key table.

    Args:
        context: Krb5 context.
        keytab: Key table to add the entry to.
        principal: The principal to add in the keytab.
        kvno: The key version number to add to the keytab.
        timestamp: The seconds since EPOCH when the entry was added.
        keyblock: The key and encryption type of the entry to add.
    """

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

def kt_get_entry(
    context: Context,
    keytab: KeyTab,
    principal: Principal,
    kvno: int = 0,
    enctype: int = 0,
) -> KeyTabEntry:
    """Get an entry from a key table.

    Retrieve an entry from a key table which matches the keytab, principal,
    kvno, and enctype. If kvno is 0, retrieve the highest-numbered kvno
    matching the other fields. If enctype is 0, match any enctype.

    Args:
        context: Krb5 context.
        keytab: The keytab to search.
        principal: The principal to match.
        kvno: The kvno to match in the keytab or 0 to match the highest kvno.
        enctype: The encryption type to get in the keytab or 0 to match any.

    Returns:
        KeyTabEntry: The entry found in the keytab.
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

def kt_read_service_key(
    context: Context,
    name: typing.Optional[bytes],
    principal: Principal,
    kvno: int = 0,
    enctype: int = 0,
) -> KeyBlock:
    """Retrieve a service key from a key table.

    Args:
        context: Krb5 context.
        name: The keytable to open with :meth:`kt_resolve`, uses
            :meth:`kt_default` if None or an empty byte string.
        principal: The service principal to select in the keytab.
        kvno: The key version number or 0 for the highest available.
        enctype: The encryption type or 0 for any type.

    Returns:
        KeyBlock: The key associated with the keytab entry.
    """

def kt_remove_entry(
    context: Context,
    keytab: KeyTab,
    entry: KeyTabEntry,
) -> None:
    """Remove keytab entry.

    Removes an entry from a key table.

    Args:
        context: Krb5 context.
        keytab: Key table to remove the entry from.
        entry: The entry to be removed.
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
