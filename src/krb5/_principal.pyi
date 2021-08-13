# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing

from krb5._context import Context

class PrincipalParseFlags(enum.IntEnum):
    """Flags used to control :meth:`parse_name_flags`."""

    none = ...  #: No parse flags set
    no_realm = ...  #: Error if realm is present
    require_realm = ...  #: Error if realm is not present
    enterprise = ...  #: Create single-component enterprise principal
    ignore_realm = ...  #: Ignore realm if present

class PrincipalUnparseFlags(enum.IntEnum):
    """Flags used to control :meth:`unparse_name_flags`."""

    none = ...  #: No unparse flags set
    short = ...  #: Omit realm if it is the local realm
    no_realm = ...  #: Omit realm always
    display = ...  #: Don't escape special characters

class Principal:
    """Kerberos Principal object.

    This class represents a Kerberos principal.

    Args:
        context: Krb5 context.
    """

    @property
    def addr(self) -> typing.Optional[int]:
        """The raw krb5_principal pointer address of this credential cache."""
    @property
    def name(self) -> typing.Optional[bytes]:
        """The name of the principal."""

def parse_name_flags(
    context: Context,
    name: bytes,
    flags: PrincipalParseFlags = PrincipalParseFlags.none,
) -> Principal:
    """Create a Kerberos principal.

    Convert a string principal name to a Kerberos principal object.

    Args:
        context: Krb5 context.
        name: The principal name to parse.
        flags: Optional flags to control how the string is parsed.

    Returns:
        Principal: The Kerberos principal parsed from the string.
    """

def unparse_name_flags(
    context: Context,
    principal: Principal,
    flags: PrincipalUnparseFlags = PrincipalUnparseFlags.none,
) -> bytes:
    """Get the Kerberos principal name.

    Converts a Kerberos principal to a string representation.

    args:
        context: Krb5 context.
        principal: The principal to convert from.
        flags: Optional flags to control how the string is generated.

    Returns:
        bytes: The principal as a byte string.
    """
