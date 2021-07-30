# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing

from libc.stdint cimport int32_t

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "krb5.h":
    void krb5_free_principal(
        krb5_context context,
        krb5_principal val,
    ) nogil

    void krb5_free_unparsed_name(
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


cdef class Principal:
    """Kerberos Principal object.

    This class represents a Kerberos principal.

    Args:
        context: Krb5 context.
    """
    # cdef Context ctx
    # cdef krb5_principal raw

    def __cinit__(Principal self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(Principal self):
        if self.raw:
            krb5_free_principal(self.ctx.raw, self.raw)
            self.raw = NULL

    @property
    def name(self) -> typing.Optional[bytes]:
        if self.raw:
            return unparse_name_flags(self.ctx, self)


class PrincipalParseFlags(enum.IntEnum):
    none = 0  #: No parse flags set
    no_realm = KRB5_PRINCIPAL_PARSE_NO_REALM  #: Error if realm is present
    require_realm = KRB5_PRINCIPAL_PARSE_REQUIRE_REALM  #: Error if realm is not present
    enterprise = KRB5_PRINCIPAL_PARSE_ENTERPRISE  #: Create single-component enterprise principal
    ignore_realm = KRB5_PRINCIPAL_PARSE_IGNORE_REALM  #: Ignore realm if present


class PrincipalUnparseFlags(enum.IntEnum):
    none = 0  #: No unparse flags set
    short = KRB5_PRINCIPAL_UNPARSE_SHORT  #: Omit realm if it is the local realm
    no_realm = KRB5_PRINCIPAL_UNPARSE_NO_REALM  #: Omit realm always
    display = KRB5_PRINCIPAL_UNPARSE_DISPLAY  #: Don't escape special characters


def parse_name_flags(
    Context context not None,
    const unsigned char[:] name not None,
    flags: PrincipalParseFlags = PrincipalParseFlags.none,
) -> Principal:
    """Create a Kerberos principal.

    Convert a string principal name to a Kerberos principal object.

    Args:
        context: Krb5 context.
        name: The principal name to parse.
        flags: Optional flags to control how the string is parsed.

    Returns:
        Principal: The Kerberos principal parsed from the string.
    """
    principal = Principal(context)
    cdef int raw_flags = flags.value
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if name is not None and len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("Principal must be set")

    with nogil:
        err = krb5_parse_name_flags(context.raw, name_ptr, raw_flags, &principal.raw)

    if err:
        raise Krb5Error(context, err)

    return principal


def unparse_name_flags(
    Context context not None,
    Principal principal not None,
    flags: PrincipalUnparseFlags = PrincipalUnparseFlags.none,
) -> bytes:
    """Get the Kerberos principal name.

    Converts a Kerberos principal to a string representation.

    args:
        context: Krb5 context.
        principal: The principal to convert from.
        flags: Optional flags to control how the string is generated.

    Returns:
        bytes: The principal as a byte string.
    """
    cdef krb5_error_code err = 0
    cdef int raw_flags = flags.value
    cdef char *name = NULL

    err = krb5_unparse_name_flags(context.raw, principal.raw, raw_flags, &name)
    if err:
        raise Krb5Error(context, err)

    try:
        return <bytes>name
    finally:
        krb5_free_unparsed_name(context.raw, name)
