# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing

from cpython cimport array
from libc.stdint cimport int32_t, uintptr_t

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # krb5_free_unparsed_name is deprecated in Heimdal - use krb5_xfree instead
    """
    #if defined(HEIMDAL_XFREE)
    #include "krb5_asn1.h"
    #endif

    void krb5_free_unparsed_name_generic(krb5_context context, char *val)
    {
    #if defined(HEIMDAL_XFREE)
        krb5_xfree(val);
    #else
        krb5_free_unparsed_name(context, val);
    #endif
    }

    void pykrb5_principal_get(
        krb5_principal principal,
        size_t *realm_name_length,
        char **realm_name,
        size_t *component_count,
        int32_t *type
    )
    {
    #if defined(HEIMDAL_XFREE)
        if (realm_name_length != NULL) *realm_name_length = strlen(principal->realm);
        if (realm_name != NULL) *realm_name = principal->realm;
        if (component_count != NULL) *component_count = principal->name.name_string.len;
        if (type != NULL) *type = principal->name.name_type;
    #else
        if (realm_name_length != NULL) *realm_name_length = principal->realm.length;
        if (realm_name != NULL) *realm_name = principal->realm.data;
        if (component_count != NULL) *component_count = principal->length;
        if (type != NULL) *type = principal->type;
    #endif
    }

    int pykrb5_principal_set(
        krb5_principal principal,
        size_t realm_name_length,
        const char *realm_name,
        size_t component_count
    )
    {
        memset(principal, 0, sizeof(*principal));

    #if defined(HEIMDAL_XFREE)
        principal->realm = (char *)realm_name;
        principal->name.name_type = 0;
        principal->name.name_string.len = component_count;

        principal->name.name_string.val = malloc(component_count * sizeof(krb5_data));
        if (!principal->name.name_string.val)
            return 0;
    #else
        principal->realm.length = realm_name_length;
        principal->realm.data = (char *)realm_name;
        principal->length = component_count;
        principal->type = 0;

        principal->data = malloc(component_count * sizeof(krb5_data));
        if (!principal->data)
            return 0;
    #endif

        return 1;
    }

    void pykrb5_principal_set_type(
        krb5_principal principal,
        int32_t type
    )
    {
    #if defined(HEIMDAL_XFREE)
        principal->name.name_type = type;
    #else
        principal->type = type;
    #endif
    }

    void pykrb5_principal_get_component(
        krb5_principal principal,
        size_t pos,
        size_t *component_length,
        char **component
    )
    {
    #if defined(HEIMDAL_XFREE)
        if (component_length != NULL) *component_length = strlen(principal->name.name_string.val[pos]);
        if (component != NULL) *component = principal->name.name_string.val[pos];
    #else
        if (component_length != NULL) *component_length = principal->data[pos].length;
        if (component != NULL) *component = principal->data[pos].data;
    #endif
    }

    void pykrb5_principal_set_component(
        krb5_principal principal,
        size_t pos,
        size_t component_length,
        const char *component
    )
    {
    #if defined(HEIMDAL_XFREE)
        principal->name.name_string.val[pos] = (char *)component;
    #else
        principal->data[pos].length = component_length;
        principal->data[pos].data = (char *)component;
    #endif
    }

    void pykrb5_principal_set_free(
        krb5_principal principal
    )
    {
    #if defined(HEIMDAL_XFREE)
        free(principal->name.name_string.val);
    #else
        free(principal->data);
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

    void pykrb5_principal_get(
        krb5_principal principal,
        size_t *realm_name_length,
        const char **realm_name,
        size_t *component_count,
        int32_t *type
    ) nogil

    int pykrb5_principal_set(
        krb5_principal principal,
        size_t realm_name_length,
        const char *realm_name,
        size_t component_count,
    ) nogil

    void pykrb5_principal_set_type(
        krb5_principal principal,
        int32_t type
    ) nogil

    void pykrb5_principal_get_component(
        krb5_principal principal,
        size_t pos,
        size_t *component_length,
        const char **component
    ) nogil

    void pykrb5_principal_set_component(
        krb5_principal principal,
        size_t pos,
        size_t component_length,
        const char *component,
    )

    void pykrb5_principal_set_free(
        krb5_principal principal,
    )


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


class NameType(enum.IntEnum):
    # See also https://github.com/krb5/krb5-assignments/blob/master/name-type

    # https://www.rfc-editor.org/rfc/rfc4120.html#section-7.5.8
    unknown = 0
    principal = 1
    srv_inst = 2
    srv_hst = 3
    srv_xhst = 4
    uid = 5
    x500_principal = 6
    smtp_name = 7
    enterprise_principal = 10
    # https://www.rfc-editor.org/rfc/rfc6111.html#section-3.1
    wellknown = 11
    # Not standardized, supported by MIT and Heimdal
    ms_principal = -128
    ms_principal_and_id = -129
    ent_principal_and_id = -130

    @classmethod
    def _missing_(cls, value: object) -> typing.Optional[enum.Enum]:
        if not isinstance(value, int):
            return None
        value = int(value)

        new_member = int.__new__(cls, value)
        new_member._name_ = f"Unknown_NameType_{str(value).replace('-', 'm')}"
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)


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

    @property
    def realm(Principal self) -> bytes:
        cdef size_t length
        cdef char *value

        if not self.raw:
            raise ValueError("Attempting to access property of NULL principal")

        pykrb5_principal_get(self.raw, &length, &value, NULL, NULL)

        if length == 0:
            return b""
        else:
            return value[:length]

    @property
    def components(Principal self) -> typing.List[bytes]:
        cdef size_t component_count

        cdef size_t length
        cdef char *value

        if not self.raw:
            raise ValueError("Attempting to access property of NULL principal")

        pykrb5_principal_get(self.raw, NULL, NULL, &component_count, NULL)

        components = []
        for pos in range(component_count):
            pykrb5_principal_get_component(self.raw, pos, &length, &value)

            if length == 0:
                component = b""
            else:
                component = value[:length]

            components.append(component)

        return components

    @property
    def type(Principal self) -> NameType:
        cdef int32_t type

        if not self.raw:
            raise ValueError("Attempting to access property of NULL principal")

        pykrb5_principal_get(self.raw, NULL, NULL, NULL, &type)
        return NameType(type)

    @type.setter
    def type(Principal self, int32_t value):
        if not self.raw:
            raise ValueError("Attempting to access property of NULL principal")

        pykrb5_principal_set_type(self.raw, value)


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


# Note: build_principal() does not actually call krb5_build_principal() because
# this would require passing vararg parameters and because
# krb5_build_principal() cannot handle NUL bytes in the strings.
# Instead, the principal is built manually, and then duplicated with
# copy_principal().
def build_principal(
    Context context not None,
    const unsigned char[:] realm not None,
    components: typing.Iterable[bytes],
) -> Principal:
    component_list = list(components)
    component_count = len(component_list)

    # Guess the component count, similar to the MIT implementation starting with 1.12
    if component_count == 2 and component_list[0] == b'krbtgt':
        inferred_principal_type = NameType.srv_inst
    elif component_count >= 2 and component_list[0] == b'WELLKNOWN':
        inferred_principal_type = NameType.wellknown
    else:
        inferred_principal_type = NameType.principal

    cdef krb5_error_code err = 0

    cdef krb5_principal_data raw
    if pykrb5_principal_set(&raw, len(realm), <const char*>&realm[0], component_count) == 0:
        raise MemoryError()
    try:
        for pos in range(component_count):
            component = component_list[pos]
            pykrb5_principal_set_component(&raw, pos, len(component), <char*>component)

        out = Principal(context, 0)

        err = krb5_copy_principal(context.raw, &raw, &out.raw)
        if err:
            raise Krb5Error(context, err)

        out.type = inferred_principal_type

        return out
    finally:
        pykrb5_principal_set_free(&raw)
