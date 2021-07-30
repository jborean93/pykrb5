# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from libc.stdlib cimport free, malloc, realloc
from libc.string cimport strlen

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "krb5.h":
    krb5_error_code krb5_kt_close(
        krb5_context context,
        krb5_keytab keytab,
    ) nogil

    krb5_error_code krb5_kt_client_default(
        krb5_context context,
        krb5_keytab *keytab_out,
    ) nogil

    krb5_error_code krb5_kt_default(
        krb5_context context,
        krb5_keytab *id,
    ) nogil

    krb5_error_code krb5_kt_default_name(
        krb5_context context,
        char *name,
        int name_size,
    ) nogil

    krb5_error_code krb5_kt_dup(
        krb5_context context,
        krb5_keytab in_kt,
        krb5_keytab *out,
    ) nogil

    krb5_error_code krb5_kt_get_name(
        krb5_context context,
        krb5_keytab keytab,
        char *name,
        unsigned int namelen,
    ) nogil

    const char *krb5_kt_get_type(
        krb5_context context,
        krb5_keytab keytab,
    ) nogil

    krb5_error_code krb5_kt_resolve(
        krb5_context context,
        const char *name,
        krb5_keytab *ktid,
    ) nogil

    krb5_error_code KRB5_CONFIG_NOTENUFSPACE
    krb5_error_code KRB5_KT_NAME_TOOLONG


cdef class KeyTab:
    """Kerberos KeyTab object.

    This class represents a Kerberos key table.

    Args:
        context: Krb5 context.
    """
    # cdef Context ctx
    # cdef krb5_keytab raw

    def __cinit__(KeyTab self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(KeyTab self):
        if self.raw:
            krb5_kt_close(self.ctx.raw, self.raw)
            self.raw = NULL

    @property
    def name(KeyTab self) -> typing.Optional[bytes]:
        if self.raw:
            return kt_get_name(self.ctx, self)

    @property
    def kt_type(KeyTab self) -> typing.Optional[bytes]:
        if self.raw:
            return kt_get_type(self.ctx, self)


def kt_client_default(
    Context context not None,
) -> KeyTab:
    """Resolve the default client key table.

    Get a handle to the default client key tab.

    Args:
        context: Krb5 context.

    Returns:
        KeyTab: The default client keytab.
    """
    kt = KeyTab(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_client_default(context.raw, &kt.raw)
    if err:
        raise Krb5Error(context, err)

    return kt


def kt_default(
    Context context not None,
) -> KeyTab:
    """Resolve the default key table.

    Get a handle to the default keytab.

    Args:
        context: Krb5 context.

    Returns:
        KeyTab: The default keytab.
    """
    kt = KeyTab(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_default(context.raw, &kt.raw)
    if err:
        raise Krb5Error(context, err)

    return kt


def kt_default_name(
    Context context not None,
) -> bytes:
    """Get the default key table name.

    Gets the name of the default key table for the context specified.

    Args:
        context: Krb5 context.

    Returns:
        bytes: The default key table name.
    """
    cdef krb5_error_code err = KRB5_CONFIG_NOTENUFSPACE
    buffer_size = 8192
    buffer_length = buffer_size
    cdef char *buffer = <char *>malloc(buffer_length)
    if not buffer:
        raise MemoryError()

    try:
        while err == KRB5_CONFIG_NOTENUFSPACE:
            err = krb5_kt_default_name(context.raw, buffer, buffer_length)

            if err == KRB5_CONFIG_NOTENUFSPACE:
                buffer_length += buffer_size

                # Use a temp var to ensure buffer is always something valid to be freed
                new_buffer = <char *>realloc(buffer, buffer_length)
                if not new_buffer:
                    raise MemoryError()
                buffer = new_buffer

            elif err:
                raise Krb5Error(context, err)

            else:
                name_len = strlen(buffer)
                return <bytes>buffer[:name_len]

    finally:
        free(buffer)


def kt_dup(
    Context context not None,
    KeyTab keytab not None,
) -> KeyTab:
    """Duplicate keytab handle.

    Duplicates the referenced keytab. The new handle can be closed
    independently to the referenced keytab.

    Args:
        context: Krb5 context.
        keytab: The keytab to duplicate.

    Returns:
        KeyTab: The duplicated keytab.
    """
    out_kt = KeyTab(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_dup(context.raw, keytab.raw, &out_kt.raw)
    if err:
        raise Krb5Error(context, err)

    return out_kt


def kt_get_name(
    Context context not None,
    KeyTab keytab not None,
) -> bytes:
    """Get a key table name.

    Get the name of the specified key table. See :meth:`kt_get_type()` to get
    the type of a keytab.

    Args:
        context: Krb5 context.
        keytab: The keytab to query.

    Returns:
        bytes: The name of the keytab.
    """
    cdef krb5_error_code err = KRB5_KT_NAME_TOOLONG
    buffer_size = 8192
    buffer_length = buffer_size
    cdef char *buffer = <char *>malloc(buffer_length)
    if not buffer:
        raise MemoryError()

    try:
        while err == KRB5_KT_NAME_TOOLONG:
            err = krb5_kt_get_name(context.raw, keytab.raw, buffer, buffer_length)

            if err == KRB5_KT_NAME_TOOLONG:
                buffer_length += buffer_size

                # Use a temp var to ensure buffer is always something valid to be freed
                new_buffer = <char *>realloc(buffer, buffer_length)
                if not new_buffer:
                    raise MemoryError()
                buffer = new_buffer

            elif err:
                raise Krb5Error(context, err)

            else:
                name_len = strlen(buffer)
                return <bytes>buffer[:name_len]

    finally:
        free(buffer)


def kt_get_type(
    Context context not None,
    KeyTab keytab not None,
) -> bytes:
    """Get a key table type.

    Get the type of the specified key table. See :meth:`ky_get_name()` to get
    the name of a keytab.

    Args:
        context: Krb5 context.
        keytab: The keytab to query.

    Returns:
        bytes: The type of the keytab.
    """
    return <bytes>krb5_kt_get_type(context.raw, keytab.raw)


def kt_resolve(
    Context context not None,
    const unsigned char[:] name not None,
) -> KeyTab:
    """Get a handle for a key table.

    Resolve the key table name and open a handle. The name must be of the from
    ``type:residual`` where type must be known to the library. If no type is
    specified then ``FILE`` is used as a default. The ``residual`` value is
    dependent on the type specified.

    Args:
        context: Krb5 context.
        name: The name of the keytab in the form ``type:residual``.

    Returns:
        KeyTab: The opened keytab.
    """
    kt = KeyTab(context)
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("KeyTab must be set")

    err = krb5_kt_resolve(context.raw, name_ptr, &kt.raw)
    if err:
        raise Krb5Error(context, err)

    return kt
