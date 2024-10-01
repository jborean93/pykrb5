# Copyright: (c) 2024 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import struct
import typing

FORMAT = "!HIIIQQ"


class ADPolicyInfoProp(enum.IntFlag):
    COMPLEX = 0x00000001
    NO_ANON_CHANGEv = 0x00000002
    NO_CLEAR_CHANGE = 0x00000004
    LOCKOUT_ADMINS = 0x00000008
    STORE_CLEARTEXT = 0x00000010
    REFUSE_CHANGE = 0x00000020


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

    properties: ADPolicyInfoProp
    min_length: int
    history: int
    max_age: int
    min_age: int

    @classmethod
    def from_bytes(cls, data: bytes) -> ADPolicyInfo:
        """Decode AD policy result from byte string

        Args:
            data: Serialized AD policy `server_response`

        Returns:
            ADPolicyInfo: Decoded AD policy result strcture

        Raises:
            ValueError: Invalid data length or wrong signature
        """
        if len(data) != struct.calcsize(FORMAT):
            raise ValueError("Invalid data length")
        signature, min_length, history, flags, max_age, min_age = struct.unpack(FORMAT, data)
        if signature != 0x0000:
            raise ValueError("Invalid signature")
        return cls(
            min_length=min_length,
            history=history,
            max_age=max_age,
            min_age=min_age,
            properties=ADPolicyInfoProp(flags),
        )
