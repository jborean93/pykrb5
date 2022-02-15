# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # Added in MIT 1.10
    krb5_boolean krb5_cc_support_switch(
        krb5_context context,
        const char *type,
    ) nogil


def cc_support_switch(
    Context context not None,
    const unsigned char[:] cache_type not None,
) -> bool:
    cdef const char *type_ptr = NULL
    if len(cache_type):
        type_ptr = <const char*>&cache_type[0]
    else:
        raise ValueError("cache_type cannot be an empty byte string")

    return bool(krb5_cc_support_switch(context.raw, type_ptr))
