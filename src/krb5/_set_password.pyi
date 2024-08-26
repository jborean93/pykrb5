import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

class SetPasswordResult(typing.NamedTuple):
    result_code: int
    result_code_string: bytes
    result_string: str

def set_password(
    context: Context,
    creds: Creds,
    newpw: bytes,
    change_password_for: typing.Optional[Principal],
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
        A named tuple containing the `result_code`, `result_code_string`, and an
        optional `result_string`.
        The non-zero `result_code` means error with a corresponding readable
        representation in `result_code_string`. It is a `bytes` object.
        The `result_string` is a server response that may contain useful
        information about password policy violations or other errors. It is
        decoded as a `string` according to ``RFC 3244``.

    The possible values of the output `result_code` are:

    `KRB5_KPASSWD_SUCCESS`   (0) - Success
    `KRB5_KPASSWD_MALFORMED` (1) - Malformed request error
    `KRB5_KPASSWD_HARDERROR` (2) - Server error
    `KRB5_KPASSWD_AUTHERROR` (3) - Authentication error
    `KRB5_KPASSWD_SOFTERROR` (4) - Password change rejected
    """

def set_password_using_ccache(
    context: Context,
    ccache: CCache,
    newpw: bytes,
    change_password_for: typing.Optional[Principal],
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
        A named tuple containing the `result_code`, `result_code_string`, and an
        optional `result_string`.
        The non-zero `result_code` means error with a corresponding readable
        representation in `result_code_string`. It is a `bytes` object.
        The `result_string` is a server response that may contain useful
        information about password policy violations or other errors. It is
        decoded as a `string` according to ``RFC 3244``.

    The possible values of the output `result_code` are:

    `KRB5_KPASSWD_SUCCESS`   (0) - Success
    `KRB5_KPASSWD_MALFORMED` (1) - Malformed request error
    `KRB5_KPASSWD_HARDERROR` (2) - Server error
    `KRB5_KPASSWD_AUTHERROR` (3) - Authentication error
    `KRB5_KPASSWD_SOFTERROR` (4) - Password change rejected
    """
