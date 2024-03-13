# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context cimport Context
from krb5._exceptions import Krb5Error
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_init_secure_context(
        krb5_context *context,
    ) nogil

    krb5_error_code krb5_get_time_offsets(
        krb5_context context,
        krb5_timestamp *seconds,
        int32_t *microseconds
    ) nogil


def init_secure_context() -> Context:
    context = Context()
    krb5_init_secure_context(&context.raw)

    return context


def get_time_offsets(
    Context context not None,
) -> typing.Tuple[int, int]:
    cdef krb5_error_code = 0

    cdef krb5_timestamp seconds
    cdef int32_t microseconds
    err = krb5_get_time_offsets(context.raw, &seconds, &microseconds)
    if err:
        raise Krb5Error(context, err)

    return seconds, microseconds
