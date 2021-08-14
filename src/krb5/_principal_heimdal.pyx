# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    const char *krb5_principal_get_realm(
        krb5_context context,
		krb5_const_principal principal
    ) nogil


def principal_get_realm(
    Context context not None,
    Principal principal not None,
) -> bytes:
    return <bytes>krb5_principal_get_realm(context.raw, principal.raw)
