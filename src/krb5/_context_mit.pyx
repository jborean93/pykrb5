# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_init_secure_context(
        krb5_context *context,
    ) nogil


def init_secure_context() -> Context:
    context = Context()
    krb5_init_secure_context(&context.raw)

    return context
