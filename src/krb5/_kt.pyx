# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from libc.stdint cimport uint32_t, uintptr_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport strlen

from krb5._exceptions import Krb5Error
from krb5._principal import PrincipalParseFlags

from krb5._context cimport Context
from krb5._keyblock cimport KeyBlock
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    # Heimdal and MIT differ in their implementations
    """
    // The funtions do the structure manipulations in the C code as it can reference the struct entries by name rather
    // than an explicitly defined offset in Cython which differ cross implementations.

    void pykrb5_keytab_entry_get(
        krb5_keytab_entry *entry,
        krb5_principal *principal,
        krb5_timestamp *timestamp,
        krb5_kvno *vno,
        krb5_keyblock **key
    )
    {
        if (principal != NULL) *principal = entry->principal;
        if (timestamp != NULL) *timestamp = entry->timestamp;
        if (vno != NULL) *vno = entry->vno;
    #if defined(HEIMDAL_XFREE)
        if (key != NULL) *key = &entry->keyblock;
    #else
        if (key != NULL) *key = &entry->key;
    #endif
    }

    krb5_error_code krb5_kt_add_entry_generic(
        krb5_context context,
        krb5_keytab keytab,
        krb5_principal principal,
        krb5_kvno kvno,
        uint32_t timestamp,
        krb5_keyblock *key
    )
    {
        krb5_keytab_entry entry;

    #if defined(HEIMDAL_XFREE)
        entry.principal = principal;
        entry.vno = kvno;
        entry.keyblock.keytype = key->keytype;
        entry.keyblock.keyvalue = key->keyvalue;
        entry.timestamp = timestamp;
    #else
        entry.magic = 0;
        entry.principal = principal;
        entry.timestamp = timestamp;
        entry.vno = kvno;
        entry.key.magic = key->magic;
        entry.key.enctype = key->enctype;
        entry.key.length = key->length;
        entry.key.contents = key->contents;
    #endif

        return krb5_kt_add_entry(context, keytab, &entry);
    }

    krb5_error_code krb5_kt_get_type_generic(
        krb5_context context,
        krb5_keytab keytab,
        char **prefix,
        size_t prefixsize
    )
    {
    // MIT won't have this defined and our header sets it to -1 if it wasn't defined
    #if KRB5_KT_PREFIX_MAX_LEN == -1
        *prefix = (char *)krb5_kt_get_type(context, keytab);
        return 0;
    #else
        return krb5_kt_get_type(context, keytab, *prefix, prefixsize);
    #endif
    }

    krb5_error_code krb5_kt_free_entry_generic(
        krb5_context context,
        krb5_keytab_entry *entry
    )
    {
    // MIT has deprecated krb5_kt_free_entry in favour of this function
    #if defined(HEIMDAL_XFREE)
        return krb5_kt_free_entry(context, entry);
    #else
        return krb5_free_keytab_entry_contents(context, entry);
    #endif
    }
    """

    krb5_error_code krb5_kt_add_entry_generic(
        krb5_context context,
        krb5_keytab keytab,
        krb5_principal principal,
        krb5_kvno kvno,
        uint32_t timestamp,
        krb5_keyblock *key,
    ) nogil

    krb5_error_code krb5_kt_close(
        krb5_context context,
        krb5_keytab keytab,
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

    krb5_error_code krb5_kt_end_seq_get(
        krb5_context context,
        krb5_keytab keytab,
        krb5_kt_cursor *cursor,
    ) nogil

    krb5_error_code krb5_kt_free_entry_generic(
        krb5_context context,
        krb5_keytab_entry *entry,
    ) nogil

    krb5_error_code krb5_kt_get_entry(
        krb5_context context,
        krb5_keytab keytab,
        krb5_const_principal principal,
        krb5_kvno vno,
        krb5_enctype enctype,
        krb5_keytab_entry *entry,
    ) nogil

    krb5_error_code krb5_kt_get_name(
        krb5_context context,
        krb5_keytab keytab,
        char *name,
        unsigned int namelen,
    ) nogil

    # See inline C code
    krb5_error_code krb5_kt_get_type_generic(
        krb5_context context,
        krb5_keytab keytab,
        char **prefix,
        size_t prefixsize,
    ) nogil

    krb5_error_code krb5_kt_next_entry(
        krb5_context context,
        krb5_keytab keytab,
        krb5_keytab_entry *entry,
        krb5_kt_cursor *cursor,
    ) nogil

    krb5_error_code krb5_kt_read_service_key(
        krb5_context context,
        krb5_pointer keyprocarg,
        krb5_principal principal,
        krb5_kvno vno,
        krb5_enctype enctype,
        krb5_keyblock **key,
    ) nogil

    krb5_error_code krb5_kt_remove_entry(
        krb5_context context,
        krb5_keytab id,
        krb5_keytab_entry *entry
    ) nogil

    krb5_error_code krb5_kt_resolve(
        krb5_context context,
        const char *name,
        krb5_keytab *ktid,
    ) nogil

    krb5_error_code krb5_kt_start_seq_get(
        krb5_context context,
        krb5_keytab keytab,
        krb5_kt_cursor *cursor,
    ) nogil

    void pykrb5_keytab_entry_get(
        krb5_keytab_entry *entry,
        krb5_principal *principal,
        krb5_timestamp *timestamp,
        krb5_kvno *vno,
        krb5_keyblock **key,
    ) nogil

    krb5_error_code KRB5_CONFIG_NOTENUFSPACE
    krb5_error_code KRB5_KT_END
    krb5_error_code KRB5_KT_NAME_TOOLONG
    krb5_error_code KRB5_KT_PREFIX_MAX_LEN


cdef class KeyTab:
    # cdef Context ctx
    # cdef krb5_keytab raw

    def __cinit__(KeyTab self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(KeyTab self):
        if self.raw:
            krb5_kt_close(self.ctx.raw, self.raw)
            self.raw = NULL

    def __iter__(KeyTab self) -> typing.Iterator["KeyTabEntry"]:
        cdef krb5_error_code err = 0
        cdef krb5_kt_cursor cursor

        err = krb5_kt_start_seq_get(self.ctx.raw, self.raw, &cursor)
        if err:
            raise Krb5Error(self.ctx, err)

        try:
            while True:
                entry = KeyTabEntry(self.ctx)
                err = krb5_kt_next_entry(self.ctx.raw, self.raw, &entry.raw, &cursor)
                if err == KRB5_KT_END:
                    break
                elif err:
                    raise Krb5Error(self.ctx, err)

                entry.needs_free = 1
                yield entry

        finally:
            err = krb5_kt_end_seq_get(self.ctx.raw, self.raw, &cursor)
            if err:
                raise Krb5Error(self.ctx, err)

    @property
    def addr(self) -> typing.Optional[int]:
        if self.raw:
            return <uintptr_t>self.raw

    @property
    def name(KeyTab self) -> typing.Optional[bytes]:
        if self.raw:
            # MIT returns the type + name, this strips out the type to ensure
            # consistent behaviour across providers.
            name = kt_get_name(self.ctx, self)
            kt_type = self.kt_type

            if name.startswith(kt_type + b":"):
                name = name[len(kt_type) + 1:]

            return name

    @property
    def kt_type(KeyTab self) -> typing.Optional[bytes]:
        if self.raw:
            return kt_get_type(self.ctx, self)

    def __repr__(KeyTab self) -> str:
        if self.raw:
            kwargs = [f"{k}={v}" for k, v in {
                'kt_type': self.kt_type.decode('utf-8'),
                'name': self.name.decode('utf-8'),
            }.items()]

            return f"KeyTab({', '.join(kwargs)})"

        else:
            return "KeyTab(NULL)"

    def __str__(KeyTab self) -> str:
        if self.raw:
            return f"{self.kt_type.decode('utf-8')}:{self.name.decode('utf-8')}"

        else:
            return "NULL"


cdef class KeyTabEntry:
    # cdef Context ctx
    # cdef krb5_keytab_entry raw
    # cdef int needs_free

    def __cinit__(KeyTabEntry self, Context context):
        self.ctx = context
        self.needs_free = 0

    def __dealloc__(KeyTabEntry self):
        if self.needs_free:
            krb5_kt_free_entry_generic(self.ctx.raw, &self.raw)
            self.needs_free = 0

    def __repr__(KeyTabEntry self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'principal': repr(self.principal),
            'timestamp': self.timestamp,
            'kvno': self.kvno,
            'key': repr(self.key),
        }.items()]

        return f"KeyTabEntry({', '.join(kwargs)})"

    def __str__(KeyTabEntry self) -> str:
        return f"KVNO {self.kvno} {self.principal!s}"

    @property
    def key(KeyTabEntry self) -> KeyBlock:
        kb = KeyBlock(self.ctx, needs_free=0)
        pykrb5_keytab_entry_get(&self.raw, NULL, NULL, NULL, &kb.raw)

        return kb

    @property
    def kvno(KeyTabEntry self) -> int:
        cdef krb5_kvno kvno
        pykrb5_keytab_entry_get(&self.raw, NULL, NULL, &kvno, NULL)

        return kvno

    @property
    def principal(KeyTabEntry self) -> Principal:
        principal = Principal(self.ctx, PrincipalParseFlags.none, needs_free=0)
        pykrb5_keytab_entry_get(&self.raw, &principal.raw, NULL, NULL, NULL)

        return principal

    @property
    def timestamp(KeyTabEntry self) -> int:
        cdef krb5_timestamp timestamp
        pykrb5_keytab_entry_get(&self.raw, NULL, &timestamp, NULL, NULL)

        return timestamp


def kt_add_entry(
    Context context not None,
    KeyTab keytab not None,
    Principal principal not None,
    krb5_kvno kvno,
    uint32_t timestamp,
    KeyBlock keyblock not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_kt_add_entry_generic(context.raw, keytab.raw, principal.raw, kvno, timestamp, keyblock.raw)
    if err:
        raise Krb5Error(context, err)


def kt_default(
    Context context not None,
) -> KeyTab:
    kt = KeyTab(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_default(context.raw, &kt.raw)
    if err:
        raise Krb5Error(context, err)

    return kt


def kt_default_name(
    Context context not None,
) -> bytes:
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


def kt_get_entry(
    Context context not None,
    KeyTab keytab not None,
    Principal principal not None,
    krb5_kvno kvno=0,
    krb5_enctype enctype=0,
) -> KeyTabEntry:
    cdef KeyTabEntry entry = KeyTabEntry(context)
    cdef krb5_error_code err = 0

    err = krb5_kt_get_entry(context.raw, keytab.raw, principal.raw, kvno, enctype, &entry.raw)
    if err:
        raise Krb5Error(context, err)

    return entry


def kt_get_name(
    Context context not None,
    KeyTab keytab not None,
) -> bytes:
    cdef krb5_error_code err = KRB5_KT_NAME_TOOLONG
    buffer_size = 8192
    buffer_length = buffer_size
    cdef char *buffer = <char *>malloc(buffer_length)
    if not buffer:
        raise MemoryError()

    try:
        while err == KRB5_KT_NAME_TOOLONG:
            err = krb5_kt_get_name(context.raw, keytab.raw, buffer, buffer_length)

            # Heimdal does not define KRB5_KT_NAME_TOOLONG so fail on the first try.
            if err and (err != KRB5_KT_NAME_TOOLONG or KRB5_KT_NAME_TOOLONG == 1):
                raise Krb5Error(context, err)

            elif err == KRB5_KT_NAME_TOOLONG:
                buffer_length += buffer_size

                # Use a temp var to ensure buffer is always something valid to be freed
                new_buffer = <char *>realloc(buffer, buffer_length)
                if not new_buffer:
                    raise MemoryError()
                buffer = new_buffer

            else:
                name_len = strlen(buffer)
                return <bytes>buffer[:name_len]

    finally:
        free(buffer)


def kt_get_type(
    Context context not None,
    KeyTab keytab not None,
) -> bytes:
    cdef krb5_error_code err = 0
    cdef char *buffer = NULL

    if KRB5_KT_PREFIX_MAX_LEN == -1:
        # MIT Kerberos just returns a const char* which shouldn't be freed
        krb5_kt_get_type_generic(context.raw, keytab.raw, &buffer, 0)
        return <bytes>buffer

    else:
        # Heimdal requires the caller to allocate and free the memory. Use the defined max len for the prefix.
        buffer_length = KRB5_KT_PREFIX_MAX_LEN
        buffer = <char *>malloc(buffer_length)
        if not buffer:
            raise MemoryError()

        try:
            err = krb5_kt_get_type_generic(context.raw, keytab.raw, &buffer, buffer_length)
            if err:
                raise Krb5Error(context, err)

            type_len = strlen(buffer)
            return <bytes>buffer[:type_len]

        finally:
            free(buffer)


def kt_read_service_key(
    Context context not None,
    const unsigned char[:] name,
    Principal principal not None,
    krb5_kvno kvno = 0,
    krb5_enctype enctype = 0,
) -> KeyBlock:
    kb = KeyBlock(context)

    cdef krb5_error_code err = 0
    cdef krb5_pointer name_ptr = NULL
    if len(name):
        name_ptr = <krb5_pointer>&name[0]
    else:
        raise ValueError("KeyTab must be set")

    err = krb5_kt_read_service_key(context.raw, name_ptr, principal.raw, kvno, enctype, &kb.raw)
    if err:
        raise Krb5Error(context, err)

    return kb


def kt_remove_entry(
    Context context not None,
    KeyTab keytab not None,
    KeyTabEntry entry not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_kt_remove_entry(context.raw, keytab.raw, &entry.raw)
    if err:
        raise Krb5Error(context, err)


def kt_resolve(
    Context context not None,
    const unsigned char[:] name not None,
) -> KeyTab:
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
