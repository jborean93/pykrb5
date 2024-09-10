import enum
import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

class ADPolicyInfo(typing.NamedTuple):
    """The structure containing the reasons for failed password change attempt.
    Should be used to inform the end user how to meet the policy requirements.
    This is specific to Active Directory and is returned as the `result_string`
    by :meth:`set_password()` and :meth:`set_password_using_ccache()`. If the
    `result_string` is exactly 30 bytes long starting with `0x0000`, it is very
    likely to be an `ADPolicyInfo`.

    The structure contains the following fields:\n
    `properties` - Password policy flags (only `COMPLEX` has known meaning)\n
    `min_length` - Minimal password length\n
    `history`    - Number of passwords that this system remembers\n
    `max_age`    - Maximum password age in 100 nanosecond units\n
    `min_age`    - Minimum password age in 100 nanosecond units\n

    The only known property is `COMPLEX` which means that the password must meet
    certain character variety and not contain the user's name.
    To convert `max_age` and `min_age` to seconds, divide them by 10_000_000.
    """

    class Prop(enum.IntFlag):
        COMPLEX = 0x00000001
        NO_ANON_CHANGEv = 0x00000002
        NO_CLEAR_CHANGE = 0x00000004
        LOCKOUT_ADMINS = 0x00000008
        STORE_CLEARTEXT = 0x00000010
        REFUSE_CHANGE = 0x00000020

    SECONDS = 10000000
    properties: "ADPolicyInfo.Prop"
    min_length: int
    history: int
    max_age: int
    min_age: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "ADPolicyInfo":
        """Decode AD policy result from byte string

        Args:
            data: Serialized AD policy `result_string`

        Returns:
            ADPolicyInfo: Decoded AD policy result strcture

        Raises:
            ValueError: Invalid data length or signature not 0x0000
        """

    @classmethod
    def to_bytes(cls, policy: "ADPolicyInfo") -> bytes:
        """Reverses the `from_bytes` operation

        Args:
            policy: AD policy result structure

        Returns:
            bytes: Serialized AD policy result byte string
        """

class SetPasswordResult(typing.NamedTuple):
    """The result returned by :meth:`set_password()` and
    :meth:`set_password_using_ccache()`.

    The `result_code` and `result_code_string` is the library response:
    - KRB5_KPASSWD_SUCCESS   (0) - Success
    - KRB5_KPASSWD_MALFORMED (1) - Malformed request error
    - KRB5_KPASSWD_HARDERROR (2) - Server error
    - KRB5_KPASSWD_AUTHERROR (3) - Authentication error
    - KRB5_KPASSWD_SOFTERROR (4) - Password change rejected

    The `result_string` is a server protocol response that may contain useful
    information about password policy violations or other errors.
    Depending on `kpasswd` implementation, it may be returned as:\n
    - decoded UTF-8 string (MIT KDC)
    - decoded binary structure represented by `ADPolicyInfo` (Active Directory)
    - binary string (other implementations)

    The `ADPolicyInfo` may be used directly. On MIT libraty, it may be also
    converted back to bytes with :meth:`to_bytes()` and passed to
    :meth:`chpw_message()` to obtain a library decoded human readable response.

    """

    result_code: int
    """The library result code of the password change operation."""
    result_code_string: bytes
    """The byte string representation of the result code."""
    result_string: str | ADPolicyInfo | bytes
    """Server response."""

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
