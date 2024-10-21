# Copyright: (c) 2024 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

class SetPasswordResultCode(enum.IntEnum):
    """Password change result constants returned by :meth:`set_password()`
    Follow RFC 3244 with additional Microsoft extensions.
    """

    SUCCESS = ...  # Success
    MALFORMED = ...  # Malformed request
    HARDERROR = ...  # Server error
    AUTHERROR = ...  # Authentication error
    SOFTERROR = ...  # Password change rejected
    ACCESSDENIED = ...  # Microsoft extension: Not authorized
    BAD_VERSION = ...  # Microsoft extension: Unknown RPC version
    INITIAL_FLAG_NEEDED = ...  # Microsoft extension:
    # The presented credentials were not obtained using a password directly

class SetPasswordResult(typing.NamedTuple):
    """The result returned by :meth:`set_password()` and
    :meth:`set_password_using_ccache()`.

    The `result_code` and `result_code_string` are the pure library responses.
    See `SetPasswordResultCode` for more information.

    The `server_response` is a server protocol message that may contain useful
    information about password policy violations or other errors.
    Despite RFC 3244, the server response is not standardized and may vary.
    Depending on `kpasswd` implementation, it may be returned as:\n
    - 30-byte binary Active Directory Policy Information
    - UTF-8 byte string (MIT KDC, potentially Heimdal KDC)
    - raw bytes (unknown or custom implementation)

    The trick is that Active Directory Policy Information always starts with
    `0x0000` signature to distinguish from UTF-8.
    So the client may try decoding the server response with either
    :meth:`ADPolicyInfo.from_bytes()` or :meth:`bytes.decode()`.
    And if the decoding fails with corresponding `ValueError` or
    `UnicodeDecodeError`, the raw bytes should be analyzed.

    See `ADPolicyInfo` for more information.
    """

    result_code: SetPasswordResultCode
    """The library result code of the password change operation."""
    result_code_string: bytes
    """The byte string representation of the result code."""
    server_response: bytes
    """Implementation-specific server response."""

def set_password(
    context: Context,
    creds: Creds,
    newpw: bytes,
    change_password_for: Principal | None = None,
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
        SetPasswordResult: See `SetPasswordResult` for more information.
    """

def set_password_using_ccache(
    context: Context,
    ccache: CCache,
    newpw: bytes,
    change_password_for: Principal | None = None,
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
        SetPasswordResult: See `SetPasswordResult` for more information.
    """
