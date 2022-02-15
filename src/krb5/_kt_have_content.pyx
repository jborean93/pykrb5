# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._kt cimport KeyTab


cdef extern from "python_krb5.h":
    # Added in MIT 1.11
    krb5_error_code krb5_kt_have_content(
        krb5_context context,
        krb5_keytab keytab,
    ) nogil


def kt_have_content(
    Context context not None,
    KeyTab keytab not None,
) -> bool:
    cdef krb5_error_code err = 0

    err = krb5_kt_have_content(context.raw, keytab.raw)

    return err == 0
