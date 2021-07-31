# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_cc_dup(
        krb5_context context,
        krb5_ccache in_cc,
        krb5_ccache *out,
    ) nogil


def cc_dup(
    Context context not None,
    CCache cache not None,
) -> CCache:
    dup = CCache(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_dup(context.raw, cache.raw, &dup.raw)
    if err:
        raise Krb5Error(context, err)

    return dup
