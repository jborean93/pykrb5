import enum
import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

class ADPolicyInfo(typing.NamedTuple):
    """The structure containing the reasons for failed password change attempt.
    Should be used to inform the end user how to meet the policy requirements.
    This is specific to Active Directory and is returned as the
    `server_response` by :meth:`set_password()` and
    :meth:`set_password_using_ccache()`.

    When using MIT library, this structure may be encoded back to bytes and
    passed to :meth:`chpw_message()` to obtain a human readable response.
    With Heimdal, it is required to provide a custom implementation based
    on the known fields below.

    The structure contains the following fields:\n
    - `properties` - Password policy bit flags (see below)
    - `min_length` - Minimal password length
    - `history`    - Number of passwords that this system remembers
    - `max_age`    - Maximum password age in 100 nanosecond units
    - `min_age`    - Minimum password age in 100 nanosecond units

    The only known property flag is `COMPLEX` which means that the password must
    meet certain character variety and not contain the user's name.
    To convert `max_age` and `min_age` to seconds, divide them by 10,000,000.
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
            data: Serialized AD policy `server_response`

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

    The `result_code` and `result_code_string` are the pure library responses:
    - SUCCESS   (0) - Success
    - MALFORMED (1) - Malformed request error
    - HARDERROR (2) - Server error
    - AUTHERROR (3) - Authentication error
    - SOFTERROR (4) - Password change rejected

    The `server_response` is a server protocol message that may contain useful
    information about password policy violations or other errors.
    Depending on `kpasswd` implementation, it may be returned as:\n
    - decoded UTF-8 string (MIT KDC)
    - decoded `ADPolicyInfo` (Active Directory Policy Information)
    - raw bytes (if unable to decode)

    When (and only when) the server response is exactly 30 bytes long starting
    with `0x0000`, it is assumed to be `ADPolicyInfo`.
    All other cases are first decoded as UTF-8 string and even if this fails,
    the raw bytes are returned as `server_response`.

    See `ADPolicyInfo` for more information.
    """

    class Code(enum.IntEnum):
        SUCCESS = 0
        MALFORMED = 1
        HARDERROR = 2
        AUTHERROR = 3
        SOFTERROR = 4
    result_code: SetPasswordResult.Code
    """The library result code of the password change operation."""
    result_code_string: str | bytes
    """The decoded or byte string representation of the result code."""
    server_response: str | ADPolicyInfo | bytes
    """Implementation-specific server response."""

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
