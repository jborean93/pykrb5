# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._krb5_types cimport *


cdef extern from "krb5.h":
    void krb5_free_context(
        krb5_context context,
    ) nogil

    krb5_error_code krb5_init_context(
        krb5_context *context,
    ) nogil

    krb5_error_code krb5_init_secure_context(
        krb5_context *context,
    ) nogil


cdef class Context:
    """Kerberos Library Context

    This class represents a library context object.
    """
    # cdef krb5_context raw

    def __cinit__(Context self):
        self.raw = NULL

    def __dealloc__(Context self):
        if self.raw:
            krb5_free_context(self.raw)
            self.raw = NULL


def init_context() -> Context:
    """Create a krb5 library context.

    Creates a krb5 library context.

    Returns:
        Context: The opened krb5 library context.
    """
    context = Context()
    krb5_init_context(&context.raw)

    return context


def init_secure_context() -> Context:
    """Create a secure krb5 library context.

    Create a context structure, using only system configuration files. All
    information passed through environment variables are ignored.

    Returns:
        Context: The opened krb5 library context.
    """
    context = Context()
    krb5_init_secure_context(&context.raw)

    return context
