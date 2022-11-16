# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # krb5_free_default_realm is optionally exported in Heimdal (not at all on macOS) - use krb5_xfree instead
    """
    void krb5_free_default_realm_generic(krb5_context context, char *realm)
    {
    #if defined(HEIMDAL_XFREE)
        krb5_xfree(realm);
    #else
        krb5_free_default_realm(context, realm);
    #endif
    }
    """

    void krb5_free_context(
        krb5_context context,
    ) nogil

    krb5_error_code krb5_init_context(
        krb5_context *context,
    ) nogil

    # See inline C code
    void krb5_free_default_realm_generic(
        krb5_context context,
        char *realm,
    ) nogil

    krb5_error_code krb5_get_default_realm(
        krb5_context context,
        char **realm,
    ) nogil

    krb5_error_code krb5_set_default_realm(
        krb5_context context,
        const char *realm
    ) nogil


cdef class Context:
    # cdef krb5_context raw

    def __cinit__(Context self):
        self.raw = NULL

    def __dealloc__(Context self):
        if self.raw:
            krb5_free_context(self.raw)
            self.raw = NULL

    def __str__(Context self):
        return "Krb5Context"


def init_context() -> Context:
    context = Context()
    krb5_init_context(&context.raw)

    return context


def get_default_realm(
    Context context not None,
) -> bytes:
    cdef krb5_error_code = 0
    cdef char *realm = NULL

    err = krb5_get_default_realm(context.raw, &realm)
    if err:
        raise Krb5Error(context, err)

    try:
        return <bytes>realm
    finally:
        krb5_free_default_realm_generic(context.raw, realm)


def set_default_realm(
    Context context not None,
    const unsigned char[:] realm,
) -> None:
    cdef krb5_error_code = 0
    cdef const char *realm_ptr = NULL
    if realm is not None and len(realm):
        realm_ptr = <const char*>&realm[0]

    err = krb5_set_default_realm(context.raw, realm_ptr)
    if err:
        raise Krb5Error(context, err)
