import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

class SetPasswordResult(typing.NamedTuple):
    """The result returned by :meth:`set_password()` and
    :meth:`set_password_using_ccache()`.

    The `result_code` and `result_code_string` is the library response:\n
    KRB5_KPASSWD_SUCCESS   (0) - Success\n
    KRB5_KPASSWD_MALFORMED (1) - Malformed request error\n
    KRB5_KPASSWD_HARDERROR (2) - Server error\n
    KRB5_KPASSWD_AUTHERROR (3) - Authentication error\n
    KRB5_KPASSWD_SOFTERROR (4) - Password change rejected\n

    The `result_string` is a server protocol response that may contain useful
    information about password policy violations or other errors.
    """

    result_code: int
    """The library result code of the password change operation."""
    result_code_string: bytes
    """The byte string representation of the result code."""
    result_string: bytes
    """Server response string"""

def set_password(
    context: Context,
    creds: Creds,
    newpw: bytes,
    change_password_for: typing.Optional[Principal] = None,
) -> SetPasswordResult:
    """Set a password for a principal using specified credentials.


    This function implements the set password operation of ``RFC 3244``,
    for interoperability with Microsoft Windows implementations.
    It uses the credentials `creds` to set the password `newpw` for the
    principal `change_password_for`.
    If `change_password_for` is `None`, the password is set for the principal
    owning creds. If `change_password_for` is not `None`, the change is
    performed on the specified principal, assuming enough privileges.

    Note: the `creds` can be obtained using `get_init_creds_password()` with
    `in_tkt_service` set to ``kadmin/changepw``.

    Args:
        context: Krb5 context.
        creds: Credentials for kadmin/changepw service.
        newpw: New password.
        change_password_for: `None` or the principal to set the password for.

    Returns:
        SetPasswordResult: See `SetPasswordResult` for more information about
        the return result.
    """

def set_password_using_ccache(
    context: Context,
    ccache: CCache,
    newpw: bytes,
    change_password_for: typing.Optional[Principal] = None,
) -> SetPasswordResult:
    """Set a password for a principal using cached credentials.


    This function implements the set password operation of ``RFC 3244``,
    for interoperability with Microsoft Windows implementations.
    It uses the cached credentials from `ccache` to set the password `newpw` for
    the principal `change_password_for`.
    If `change_password_for` is `None`, the change is performed on the default
    principal in ccache. If `change_password_for` is not `None`, the change is
    performed on the specified principal.

    Note: the credentials can be obtained using `get_init_creds_password()` with
    `in_tkt_service` set to ``kadmin/changepw`` and stored to `ccache`.

    Args:
        context: Krb5 context.
        ccache: Credential cache.
        newpw: The new password.
        change_password_for: `None` or the principal to set the password for.

    Returns:
        SetPasswordResult: See `SetPasswordResult` for more information about
        the return result.
    """
