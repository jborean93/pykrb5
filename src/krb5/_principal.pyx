# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing

from libc.stdint cimport int32_t, uintptr_t

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # krb5_free_unparsed_name is deprecated in Heimdal - use krb5_xfree instead
    """
    void krb5_free_unparsed_name_generic(krb5_context context, char *val)
    {
    #if defined(HEIMDAL_XFREE)
        krb5_xfree(val);
    #else
        krb5_free_unparsed_name(context, val);
    #endif
    }
    """

    krb5_error_code krb5_copy_principal(
        krb5_context context,
        krb5_const_principal inprinc,
        krb5_principal *outprinc,
    ) nogil

    void krb5_free_principal(
        krb5_context context,
        krb5_principal val,
    ) nogil

    # See inline C code
    void krb5_free_unparsed_name_generic(
        krb5_context context,
        char *val,
    ) nogil

    krb5_error_code krb5_parse_name_flags(
        krb5_context context,
        const char *name,
        int flags,
        krb5_principal *principal_out,
    ) nogil

    krb5_error_code krb5_unparse_name_flags(
        krb5_context context,
        krb5_const_principal principal,
        int flags,
        char **name,
    ) nogil

    int32_t KRB5_PRINCIPAL_PARSE_NO_REALM
    int32_t KRB5_PRINCIPAL_PARSE_REQUIRE_REALM
    int32_t KRB5_PRINCIPAL_PARSE_ENTERPRISE
    int32_t KRB5_PRINCIPAL_PARSE_IGNORE_REALM

    int32_t KRB5_PRINCIPAL_UNPARSE_SHORT
    int32_t KRB5_PRINCIPAL_UNPARSE_NO_REALM
    int32_t KRB5_PRINCIPAL_UNPARSE_DISPLAY


class PrincipalParseFlags(enum.IntEnum):
    none = 0
    no_realm = KRB5_PRINCIPAL_PARSE_NO_REALM
    require_realm = KRB5_PRINCIPAL_PARSE_REQUIRE_REALM
    enterprise = KRB5_PRINCIPAL_PARSE_ENTERPRISE
    ignore_realm = KRB5_PRINCIPAL_PARSE_IGNORE_REALM


class PrincipalUnparseFlags(enum.IntEnum):
    none = 0
    short = KRB5_PRINCIPAL_UNPARSE_SHORT
    no_realm = KRB5_PRINCIPAL_UNPARSE_NO_REALM
    display = KRB5_PRINCIPAL_UNPARSE_DISPLAY


cdef class Principal:
    """Kerberos Principal object.

    This class represents a Kerberos principal.

    Args:
        context: Krb5 context.
    """
    # cdef Context ctx
    # cdef krb5_principal raw
    # cdef int needs_free
    # cdef int _parse_flags

    def __cinit__(Principal self, Context context, flags, int needs_free=1):
        self.ctx = context
        self.raw = NULL
        self.needs_free = needs_free
        self._parse_flags = flags

    def __copy__(Principal self):
        return copy_principal(self.ctx, self)

    def __dealloc__(Principal self):
        if self.raw and self.needs_free:
            krb5_free_principal(self.ctx.raw, self.raw)
            self.raw = NULL

    @property
    def addr(Principal self) -> typing.Optional[int]:
        if self.raw:
            return <uintptr_t>self.raw

    @property
    def name(Principal self) -> typing.Optional[bytes]:
        if self.raw:
            # Heimdal fails to unparse a no_realm principal if the no_realm unparse flags aren't used.
            flags = PrincipalUnparseFlags.none
            if (
                self._parse_flags & PrincipalParseFlags.no_realm or
                self._parse_flags & PrincipalParseFlags.ignore_realm
            ):
                flags = PrincipalUnparseFlags.no_realm

            return unparse_name_flags(self.ctx, self, flags=flags)

    def __repr__(Principal self) -> str:
        name = self.name
        return f"Principal({name.decode('utf-8') if name else 'NULL'})"

    def __str__(Principal self) -> str:
        name = self.name
        return name.decode('utf-8') if name else 'NULL'


def copy_principal(
    Context context not None,
    Principal principal not None,
) -> Principal:
    out = Principal(context, principal._parse_flags)
    cdef krb5_error_code err = 0

    err = krb5_copy_principal(context.raw, principal.raw, &out.raw)
    if err:
        raise Krb5Error(context, err)

    return out


def parse_name_flags(
    Context context not None,
    const unsigned char[:] name not None,
    int flags=PrincipalParseFlags.none,
) -> Principal:
    principal = Principal(context, flags)
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if name is not None and len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("Principal must be set")

    err = krb5_parse_name_flags(context.raw, name_ptr, flags, &principal.raw)
    if err:
        raise Krb5Error(context, err)

    return principal


def unparse_name_flags(
    Context context not None,
    Principal principal not None,
    int flags=PrincipalUnparseFlags.none,
) -> bytes:
    cdef krb5_error_code err = 0
    cdef char *name = NULL

    err = krb5_unparse_name_flags(context.raw, principal.raw, flags, &name)
    if err:
        raise Krb5Error(context, err)

    try:
        return <bytes>name
    finally:
        krb5_free_unparsed_name_generic(context.raw, name)
