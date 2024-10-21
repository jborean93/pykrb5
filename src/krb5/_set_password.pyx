# Support for Microsoft set/change password was added in MIT 1.7

import enum
import typing

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    int32_t KRB5_KPASSWD_SUCCESS
    int32_t KRB5_KPASSWD_MALFORMED
    int32_t KRB5_KPASSWD_HARDERROR
    int32_t KRB5_KPASSWD_AUTHERROR
    int32_t KRB5_KPASSWD_SOFTERROR
    int32_t KRB5_KPASSWD_ACCESSDENIED
    int32_t KRB5_KPASSWD_BAD_VERSION
    int32_t KRB5_KPASSWD_INITIAL_FLAG_NEEDED

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



class SetPasswordResultCode(enum.IntEnum):
    SUCCESS = KRB5_KPASSWD_SUCCESS
    MALFORMED = KRB5_KPASSWD_MALFORMED
    HARDERROR = KRB5_KPASSWD_HARDERROR
    AUTHERROR = KRB5_KPASSWD_AUTHERROR
    SOFTERROR = KRB5_KPASSWD_SOFTERROR
    ACCESSDENIED = KRB5_KPASSWD_ACCESSDENIED
    BAD_VERSION = KRB5_KPASSWD_BAD_VERSION
    INITIAL_FLAG_NEEDED = KRB5_KPASSWD_INITIAL_FLAG_NEEDED

    @classmethod
    def _missing_(cls, value: object) -> typing.Optional[enum.Enum]:
        if not isinstance(value, int):
            return None
        value = int(value)

        new_member = int.__new__(cls, value)
        new_member._name_ = f"Unknown_SetPasswordResultCode_{str(value).replace('-', 'm')}"
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)

class SetPasswordResult(typing.NamedTuple):
    result_code: SetPasswordResultCode
    result_code_string: bytes
    server_response: bytes

def set_password(
    Context context not None,
    Creds creds not None,
    const unsigned char[:] newpw not None,
    Principal change_password_for = None,
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
            result_code_string = b""
        else:
            result_code_string = <bytes>value[:length]

        pykrb5_get_krb5_data(&krb5_server_response, &length, &value)

        if length == 0:
            server_response = b""
        else:
            server_response = <bytes>value[:length]

        return SetPasswordResult(result_code, result_code_string, server_response)

    finally:
        pykrb5_free_data_contents(context.raw, &krb5_result_code_string)
        pykrb5_free_data_contents(context.raw, &krb5_server_response)

def set_password_using_ccache(
    Context context not None,
    CCache ccache not None,
    const unsigned char[:] newpw not None,
    Principal change_password_for = None,
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
            result_code_string = b""
        else:
            result_code_string = <bytes>value[:length]

        pykrb5_get_krb5_data(&krb5_server_response, &length, &value)

        if length == 0:
            server_response = b""
        else:
            server_response = <bytes>value[:length]

        return SetPasswordResult(result_code, result_code_string, server_response)

    finally:
        pykrb5_free_data_contents(context.raw, &krb5_result_code_string)
        pykrb5_free_data_contents(context.raw, &krb5_server_response)

