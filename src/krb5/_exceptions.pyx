# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdint cimport int32_t

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    const char *krb5_get_error_message(
        krb5_context ctx,
        krb5_error_code code,
    ) nogil

    void krb5_free_error_message(
        krb5_context ctx,
        const char *msg,
    ) nogil

    krb5_error_code KRB5_KT_NAME_TOOLONG
    # krb5_error_code KRB5_CONFIG_NOTENUFSPACE


cdef str get_error_message(
    krb5_context ctx,
    krb5_error_code err,
):
    cdef const char *err_msg = NULL

    err_msg = krb5_get_error_message(ctx, err)
    try:
        return err_msg.decode('utf-8')

    finally:
        krb5_free_error_message(ctx, err_msg)


class Krb5Error(Exception):

    def __init__(
        self,
        context: Context,
        err_code: int,
    ) -> None:
        self.err_code = err_code

        msg = get_error_message(context.raw, err_code)
        super().__init__(f"{msg} {self.err_code}")
