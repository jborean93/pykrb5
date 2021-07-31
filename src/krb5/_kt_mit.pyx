# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._kt cimport KeyTab


cdef extern from "python_krb5.h":
    krb5_error_code krb5_kt_client_default(
        krb5_context context,
        krb5_keytab *keytab_out,
    ) nogil

    krb5_error_code krb5_kt_dup(
        krb5_context context,
        krb5_keytab in_kt,
        krb5_keytab *out,
    ) nogil


def kt_client_default(
    Context context not None,
) -> KeyTab:
    kt = KeyTab(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_client_default(context.raw, &kt.raw)
    if err:
        raise Krb5Error(context, err)

    return kt


def kt_dup(
    Context context not None,
    KeyTab keytab not None,
) -> KeyTab:
    out_kt = KeyTab(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_dup(context.raw, keytab.raw, &out_kt.raw)
    if err:
        raise Krb5Error(context, err)

    return out_kt
