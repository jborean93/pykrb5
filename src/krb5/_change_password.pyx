# Support for Microsoft set/change password was added in MIT 1.7

import collections
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

    krb5_error_code krb5_change_password(
        krb5_context context,
        krb5_creds *creds,
        const char *newpw,
        int *result_code,
        krb5_data *result_code_string,
        krb5_data *result_string
    ) nogil

def set_password(
    Context context not None,
    Creds creds not None,
    const unsigned char[:] newpw not None,
    change_password_for: typing.Optional[Principal] = None,
) -> typing.Tuple[int, bytes, bytes]:
    cdef krb5_error_code err = 0
    cdef int result_code
    cdef krb5_data result_code_string
    cdef krb5_data result_string
    cdef char *newpw_ptr
    cdef krb5_principal change_password_for_ptr = NULL
    cdef size_t length
    cdef char *value

    if len(newpw) > 0:
        newpw_ptr = <char *>&newpw[0]
    else:
        newpw_ptr = <char *>b""

    pykrb5_init_krb5_data(&result_code_string)
    pykrb5_init_krb5_data(&result_string)

    if change_password_for is not None:
        change_password_for_ptr = change_password_for.raw

    try:
        err = krb5_set_password(
            context.raw,
            creds.get_pointer(),
            newpw_ptr,
            change_password_for_ptr,
            &result_code,
            &result_code_string,
            &result_string
        )

        if err:
            raise Krb5Error(context, err)

        pykrb5_get_krb5_data(&result_code_string, &length, &value)

        if length == 0:
            result_code_bytes = b""
        else:
            result_code_bytes = value[:length]

        pykrb5_get_krb5_data(&result_string, &length, &value)

        if length == 0:
            result_string_bytes = b""
        else:
            result_string_bytes = value[:length]

        return (result_code, result_code_bytes, result_string_bytes)

    finally:
        pykrb5_free_data_contents(context.raw, &result_code_string)
        pykrb5_free_data_contents(context.raw, &result_string)

def set_password_using_ccache(
    Context context not None,
    CCache ccache not None,
    const unsigned char[:] newpw not None,
    change_password_for: typing.Optional[Principal] = None,
) -> typing.Tuple[int, bytes, bytes]:
    cdef krb5_error_code err = 0
    cdef int result_code
    cdef krb5_data result_code_string
    cdef krb5_data result_string
    cdef char *newpw_ptr
    cdef krb5_principal change_password_for_ptr = NULL
    cdef size_t length
    cdef char *value

    if len(newpw) > 0:
        newpw_ptr = <char *>&newpw[0]
    else:
        newpw_ptr = <char *>b""

    pykrb5_init_krb5_data(&result_code_string)
    pykrb5_init_krb5_data(&result_string)

    if change_password_for is not None:
        change_password_for_ptr = change_password_for.raw

    try:
        err = krb5_set_password_using_ccache(
            context.raw,
            ccache.raw,
            newpw_ptr,
            change_password_for_ptr,
            &result_code,
            &result_code_string,
            &result_string
        )

        if err:
            raise Krb5Error(context, err)

        pykrb5_get_krb5_data(&result_code_string, &length, &value)

        if length == 0:
            result_code_bytes = b""
        else:
            result_code_bytes = value[:length]

        pykrb5_get_krb5_data(&result_string, &length, &value)

        if length == 0:
            result_string_bytes = b""
        else:
            result_string_bytes = value[:length]

        return (result_code, result_code_bytes, result_string_bytes)

    finally:
        pykrb5_free_data_contents(context.raw, &result_code_string)
        pykrb5_free_data_contents(context.raw, &result_string)

def change_password(
    Context context not None,
    Creds creds not None,
    const unsigned char[:] newpw not None,
) -> typing.Tuple[int, bytes, bytes]:
    cdef krb5_error_code err = 0
    cdef int result_code
    cdef krb5_data result_code_string
    cdef krb5_data result_string
    cdef char *newpw_ptr
    cdef size_t length
    cdef char *value

    if len(newpw) > 0:
        newpw_ptr = <char *>&newpw[0]
    else:
        newpw_ptr = <char *>b""

    pykrb5_init_krb5_data(&result_code_string)
    pykrb5_init_krb5_data(&result_string)

    try:
        err = krb5_change_password(
            context.raw,
            creds.get_pointer(),
            newpw_ptr,
            &result_code,
            &result_code_string,
            &result_string
        )

        if err:
            raise Krb5Error(context, err)

        pykrb5_get_krb5_data(&result_code_string, &length, &value)

        if length == 0:
            result_code_bytes = b""
        else:
            result_code_bytes = value[:length]

        pykrb5_get_krb5_data(&result_string, &length, &value)

        if length == 0:
            result_string_bytes = b""
        else:
            result_string_bytes = value[:length]

        return (result_code, result_code_bytes, result_string_bytes)

    finally:
        pykrb5_free_data_contents(context.raw, &result_code_string)
        pykrb5_free_data_contents(context.raw, &result_string)