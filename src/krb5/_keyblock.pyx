# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdlib cimport free

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # MIT and Heimdal have slightly different functions to init a keyblock
    """
    void pykrb5_keyblock_get(
        krb5_keyblock *key,
        krb5_enctype *enctype,
        size_t *length,
        char **data
    )
    {
    #if defined(HEIMDAL_XFREE)
        if (enctype != NULL) *enctype = key->keytype;
        if (length != NULL) *length = key->keyvalue.length;
        if (data != NULL) *data = key->keyvalue.data;
    #else
        if (enctype != NULL) *enctype = key->enctype;
        if (length != NULL) *length = key->length;
        if (data != NULL) *data = (char *)key->contents;
    #endif
    }

    krb5_error_code krb5_init_keyblock_generic(
        krb5_context context,
        krb5_enctype enctype,
        size_t length,
        const char *data,
        krb5_keyblock **out
    )
    {
    #if defined(HEIMDAL_XFREE)
        // While initialised here, krb5_free_keyblock will free this on deallocation
        krb5_keyblock *keyblock = NULL;
        keyblock = malloc(sizeof(krb5_keyblock));
        if (keyblock == NULL)
        {
            return ENOMEM;
        }

        *out = keyblock;
        return krb5_keyblock_init(context, enctype, data, length, keyblock);
    #else
        krb5_error_code err = 0;

        err = krb5_init_keyblock(context, enctype, length, out);
        if (err == 0 && length > 0)
        {
            memcpy((*out)->contents, data, length);
        }

        return err;
    #endif
    }
    """

    krb5_error_code krb5_init_keyblock_generic(
        krb5_context context,
        krb5_enctype enctype,
        size_t length,
        const char *data,
        krb5_keyblock **out,
    ) nogil

    krb5_error_code krb5_free_keyblock(
        krb5_context context,
        krb5_keyblock *val,
    ) nogil

    void pykrb5_keyblock_get(
        krb5_keyblock *key,
        krb5_enctype *enctype,
        size_t *length,
        char **data,
    ) nogil


cdef class KeyBlock:
    # cdef Context ctx
    # cdef krb5_keyblock *raw
    # cdef int needs_free

    def __cinit__(KeyBlock self, Context context, needs_free=1):
        self.ctx = context
        self.raw = NULL
        self.needs_free = needs_free

    def __dealloc__(KeyBlock self):
        if self.raw != NULL and self.needs_free:
            krb5_free_keyblock(self.ctx.raw, self.raw)
            self.raw = NULL

    def __len__(KeyBlock self) -> int:
        cdef size_t length
        pykrb5_keyblock_get(self.raw, NULL, &length, NULL)

        return length

    def __repr__(KeyBlock self) -> str:
        kwargs = [f"{k}={v}" for k, v in {
            'enctype': self.enctype,
            'length': len(self),
        }.items()]

        return f"KeyBlock({', '.join(kwargs)})"

    def __str__(KeyBlock self) -> str:
        return f"KeyBlock {self.enctype}"

    @property
    def data(KeyBlock self) -> bytes:
        cdef size_t length
        cdef char *data
        pykrb5_keyblock_get(self.raw, NULL, &length, &data)

        if length == 0:
            return b""
        else:
            return data[:length]

    @property
    def enctype(KeyBlock self) -> int:
        cdef krb5_enctype enctype
        pykrb5_keyblock_get(self.raw, &enctype, NULL, NULL)

        return enctype


def init_keyblock(
    Context context not None,
    krb5_enctype enctype,
    const unsigned char[:] key,
) -> KeyBlock:
    kb = KeyBlock(context)
    cdef krb5_error_code err = 0
    cdef size_t length = 0

    cdef const char *key_ptr = NULL
    if key is not None and len(key):
        length = len(key)
        key_ptr = <const char*>&key[0]

    err = krb5_init_keyblock_generic(context.raw, enctype, length, key_ptr, &kb.raw)
    if err:
        raise Krb5Error(context, err)

    return kb
