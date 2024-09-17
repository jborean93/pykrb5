import typing

from krb5._exceptions import Krb5Error

from libc.string cimport strlen

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_chpw_message(
        krb5_context context,
        const krb5_data *server_string,
        char **message_out
    ) nogil

    void krb5_free_string(
        krb5_context context,
        char *string
    ) nogil

def chpw_message(
    Context context not None,
    const unsigned char[:] server_string not None,
) -> bytes:
    cdef krb5_error_code err = 0
    cdef krb5_data server_string_raw
    cdef char *message_out = NULL

    try:
        if len(server_string) == 0:
            pykrb5_set_krb5_data(&server_string_raw, 0, "")
        else:
            pykrb5_set_krb5_data(&server_string_raw, len(server_string), <char *>&server_string[0])

        err = krb5_chpw_message(context.raw, &server_string_raw, &message_out)

        if err:
            raise Krb5Error(context, err)

        if message_out is NULL:
            return b""
        else:
            message_len = strlen(message_out)
            return <bytes>message_out[:message_len]

    finally:
        krb5_free_string(context.raw, message_out)