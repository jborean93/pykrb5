# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_cccol_cursor_free(
        krb5_context context,
        krb5_cccol_cursor *cursor
    ) nogil

    krb5_error_code krb5_cccol_cursor_new(
        krb5_context context,
        krb5_cccol_cursor *cursor,
    ) nogil

    krb5_error_code krb5_cccol_cursor_next(
        krb5_context context,
        krb5_cccol_cursor cursor,
        krb5_ccache *ccache,
    ) nogil

    krb5_error_code KRB5_CC_END


def cccol_iter(
    Context context not None,
) -> typing.Iterator[CCache]:
    cdef krb5_error_code err = 0
    cdef krb5_context ctx = context.raw
    cdef krb5_cccol_cursor cursor

    err = krb5_cccol_cursor_new(ctx, &cursor)
    if err:
        raise Krb5Error(context, err)

    try:
        while True:
            ccache = CCache(context)
            err = krb5_cccol_cursor_next(ctx, cursor, &ccache.raw)
            if err == KRB5_CC_END:  # Heimdal
                break
            elif err:
                raise Krb5Error(context, err)
            elif ccache.raw == NULL:  # MIT
                break

            yield ccache

    finally:
        err = krb5_cccol_cursor_free(ctx, &cursor)
        if err:
            raise Krb5Error(context, err)
