import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

def set_password(
    context: Context,
    creds: Creds,
    newpw: bytes,
    change_password_for: typing.Optional[Principal],
) -> bytes:
    """Set a password for a principal using specified credentials.


    This function implements the set password operation of ``RFC 3244``,
    for interoperability with Microsoft Windows implementations.
    It uses the credentials creds to set the password newpw for the
    principal change_password_for.
    If change_password_for is `None`, the password is set for the principal
    owning creds. If change_password_for is not `None`, the change is
    performed on the specified principal.

    This is only present when compiled against MIT 1.7 or newer.

    Args:
        context: Krb5 context.
        creds: Credentials for kadmin/changepw service.
        newpw: New password.
        change_password_for: `None` or the principal to set the password for.

    Returns:
        bytes: Data returned from the remote system."""

def set_password_using_ccache(
    context: Context,
    ccache: CCache,
    newpw: bytes,
    change_password_for: typing.Optional[Principal],
) -> bytes:
    """Set a password for a principal using cached credentials.


    This function implements the set password operation of ``RFC 3244``,
    for interoperability with Microsoft Windows implementations.
    It uses the cached credentials from ccache to set the password newpw for
    the principal change_password_for.
    If change_password_for is `None`, the change is performed on the default
    principal in ccache. If change_password_for is not `None`, the change is
    performed on the specified principal.

    This is only present when compiled against MIT 1.7 or newer.

    Args:
        context: Krb5 context.
        creds: Credentials to serialize.
        newpw: The new password.
        change_password_for: `None` or the principal to set the password for.

    Returns:
        bytes: Data returned from the remote system."""
