# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._kt cimport KeyTab


cdef extern from "python_krb5.h":
    krb5_error_code krb5_kt_get_full_name(
        krb5_context context,
        krb5_keytab keytab,
        char **str,
    ) nogil

    krb5_error_code krb5_xfree(
        void *ptr,
    ) nogil

    krb5_error_code KRB5_KT_PREFIX_MAX_LEN


def kt_get_full_name(
    Context context not None,
    KeyTab keytab not None,
) -> bytes:
    cdef krb5_error_code err = 0
    cdef char *str = NULL

    err = krb5_kt_get_full_name(context.raw, keytab.raw, &str)
    if err:
        raise Krb5Error(context, err)

    try:
        return <bytes>str
    finally:
        krb5_xfree(str)
