# Support for Microsoft set/change password was added in MIT 1.7

import enum
import struct
import typing

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    krb5_error_code krb5_set_password(
        krb5_context context,
        krb5_creds *creds,
        const char *newpw,
        krb5_principal change_password_for,
        int *result_code,
        krb5_data *result_code_string,
        krb5_data *result_string
    ) nogil

    krb5_error_code krb5_set_password_using_ccache(
        krb5_context context,
        krb5_ccache ccache,
        const char *newpw,
        krb5_principal change_password_for,
        int *result_code,
        krb5_data *result_code_string,
        krb5_data *result_string
    ) nogil

class ADPolicyInfo(typing.NamedTuple):
    class Prop(enum.IntFlag):
        COMPLEX = 0x00000001
        NO_ANON_CHANGEv = 0x00000002
        NO_CLEAR_CHANGE = 0x00000004
        LOCKOUT_ADMINS = 0x00000008
        STORE_CLEARTEXT = 0x00000010
        REFUSE_CHANGE = 0x00000020

    FORMAT = "!HIIIQQ"
    SECONDS = 10000000
    properties: "ADPolicyInfo.Prop"
    min_length: int
    history: int
    max_age: int
    min_age: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "ADPolicyInfo":
        if len(data) != struct.calcsize(cls.FORMAT):
            raise ValueError("Invalid data length")
        signature, min_length, history, flags, max_age, min_age = struct.unpack(cls.FORMAT, data)
        if signature != 0x0000:
            raise ValueError("Invalid signature")
        return cls(
            min_length=min_length,
            history=history,
            max_age=max_age,
            min_age=min_age,
            properties=ADPolicyInfo.Prop(flags),
        )

    @classmethod
    def to_bytes(cls, policy: "ADPolicyInfo") -> bytes:
        return struct.pack(
            cls.FORMAT,
            0x0000,
            policy.min_length,
            policy.history,
            int(policy.properties),
            policy.max_age,
            policy.min_age,
        )

class SetPasswordResult(typing.NamedTuple):
    class Code(enum.IntEnum):
        SUCCESS = 0
        MALFORMED = 1
        HARDERROR = 2
        AUTHERROR = 3
        SOFTERROR = 4
    result_code: SetPasswordResult.Code
    result_code_string: str | bytes
    server_response: str | ADPolicyInfo | bytes

def set_password(
    Context context not None,
    Creds creds not None,
    const unsigned char[:] newpw not None,
    change_password_for: typing.Optional[Principal] = None,
) -> SetPasswordResult:
    cdef krb5_error_code err = 0
    cdef int result_code
    cdef krb5_data krb5_result_code_string
    cdef krb5_data krb5_server_response
    cdef char *newpw_ptr
    cdef krb5_principal change_password_for_ptr = NULL
    cdef size_t length
    cdef char *value

    if len(newpw) > 0:
        newpw_ptr = <char *>&newpw[0]
    else:
        newpw_ptr = <char *>b""

    pykrb5_init_krb5_data(&krb5_result_code_string)
    pykrb5_init_krb5_data(&krb5_server_response)

    if change_password_for is not None:
        change_password_for_ptr = change_password_for.raw

    try:
        err = krb5_set_password(
            context.raw,
            creds.get_pointer(),
            newpw_ptr,
            change_password_for_ptr,
            &result_code,
            &krb5_result_code_string,
            &krb5_server_response
        )

        if err:
            raise Krb5Error(context, err)

        pykrb5_get_krb5_data(&krb5_result_code_string, &length, &value)

        if length == 0:
            result_code_string = ""
        else:
            result_code_bytes = <bytes>value[:length]
            try:
                result_code_string = result_code_bytes.decode("utf-8")
            except UnicodeDecodeError:
                result_code_string = result_code_bytes

        pykrb5_get_krb5_data(&krb5_server_response, &length, &value)

        if length == 0:
            server_response = ""
        else:
            server_response_bytes = <bytes>value[:length]
            try:
                server_response = server_response_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    server_response = ADPolicyInfo.from_bytes(server_response_bytes)
                except (ValueError, struct.error):
                    server_response = server_response_bytes

        return SetPasswordResult(result_code, result_code_string, server_response)

    finally:
        pykrb5_free_data_contents(context.raw, &krb5_result_code_string)
        pykrb5_free_data_contents(context.raw, &krb5_server_response)

def set_password_using_ccache(
    Context context not None,
    CCache ccache not None,
    const unsigned char[:] newpw not None,
    change_password_for: typing.Optional[Principal] = None,
) -> SetPasswordResult:
    cdef krb5_error_code err = 0
    cdef int result_code
    cdef krb5_data krb5_result_code_string
    cdef krb5_data krb5_server_response
    cdef char *newpw_ptr
    cdef krb5_principal change_password_for_ptr = NULL
    cdef size_t length
    cdef char *value

    if len(newpw) > 0:
        newpw_ptr = <char *>&newpw[0]
    else:
        newpw_ptr = <char *>b""

    pykrb5_init_krb5_data(&krb5_result_code_string)
    pykrb5_init_krb5_data(&krb5_server_response)

    if change_password_for is not None:
        change_password_for_ptr = change_password_for.raw

    try:
        err = krb5_set_password_using_ccache(
            context.raw,
            ccache.raw,
            newpw_ptr,
            change_password_for_ptr,
            &result_code,
            &krb5_result_code_string,
            &krb5_server_response
        )

        if err:
            raise Krb5Error(context, err)

        pykrb5_get_krb5_data(&krb5_result_code_string, &length, &value)

        if length == 0:
            result_code_string = ""
        else:
            result_code_bytes = <bytes>value[:length]
            try:
                result_code_string = result_code_bytes.decode("utf-8")
            except UnicodeDecodeError:
                result_code_string = result_code_bytes

        pykrb5_get_krb5_data(&krb5_server_response, &length, &value)

        if length == 0:
            server_response = ""
        else:
            server_response_bytes = <bytes>value[:length]
            try:
                server_response = server_response_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    server_response = ADPolicyInfo.from_bytes(server_response_bytes)
                except (ValueError, struct.error):
                    server_response = server_response_bytes

        return SetPasswordResult(result_code, result_code_string, server_response)

    finally:
        pykrb5_free_data_contents(context.raw, &krb5_result_code_string)
        pykrb5_free_data_contents(context.raw, &krb5_server_response)

