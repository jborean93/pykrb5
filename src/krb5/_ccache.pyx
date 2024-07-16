# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing

from libc.stdint cimport uintptr_t

from krb5._exceptions import Krb5Error
from krb5._principal import PrincipalParseFlags

from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    krb5_error_code krb5_cc_close(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_default(
        krb5_context context,
        krb5_ccache *cache,
    ) nogil

    const char *krb5_cc_default_name(
        krb5_context context,
    ) nogil

    krb5_error_code krb5_cc_destroy(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_end_seq_get(
        krb5_context context,
        krb5_ccache cache,
        krb5_cc_cursor *cursor,
    ) nogil

    krb5_error_code krb5_cc_initialize(
        krb5_context context,
        krb5_ccache cache,
        krb5_principal principal,
    ) nogil

    const char *krb5_cc_get_name(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_get_principal(
        krb5_context context,
        krb5_ccache cache,
        krb5_principal *principal,
    ) nogil

    const char *krb5_cc_get_type(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_new_unique(
        krb5_context context,
        const char *type,
        const char *hint,
        krb5_ccache *id,
    ) nogil

    krb5_error_code krb5_cc_next_cred(
        krb5_context context,
        krb5_ccache cache,
        krb5_cc_cursor *cursor,
        krb5_creds *cred,
    ) nogil

    krb5_error_code krb5_cc_remove_cred(
        krb5_context context,
        krb5_ccache cache,
        int flags,
        krb5_creds *creds,
    ) nogil

    krb5_error_code krb5_cc_resolve(
        krb5_context context,
        const char *name,
        krb5_ccache *cache,
    ) nogil

    krb5_error_code krb5_cc_retrieve_cred(
        krb5_context context,
        krb5_ccache cache,
        int flags,
        krb5_creds *mcreds,
        krb5_creds *creds,
    ) nogil

    krb5_error_code krb5_cc_set_default_name(
        krb5_context context,
        const char *name,
    ) nogil

    krb5_error_code krb5_cc_store_cred(
        krb5_context context,
        krb5_ccache cache,
        krb5_creds *creds,
    ) nogil

    krb5_error_code krb5_cc_start_seq_get(
        krb5_context context,
        krb5_ccache cache,
        krb5_cc_cursor *cursor,
    ) nogil

    krb5_error_code krb5_cc_switch(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_get_config(
        krb5_context context,
        krb5_ccache id,
        krb5_const_principal principal,
        const char *key,
        krb5_data *data,
    );

    krb5_error_code krb5_cc_set_config(
        krb5_context context,
        krb5_ccache id,
        krb5_const_principal principal,
        const char *key,
        krb5_data *data,
    ) nogil

    int32_t KRB5_TC_MATCH_TIMES
    int32_t KRB5_TC_MATCH_IS_SKEY
    int32_t KRB5_TC_MATCH_FLAGS
    int32_t KRB5_TC_MATCH_TIMES_EXACT
    int32_t KRB5_TC_MATCH_FLAGS_EXACT
    int32_t KRB5_TC_MATCH_AUTHDATA
    int32_t KRB5_TC_MATCH_SRV_NAMEONLY
    int32_t KRB5_TC_MATCH_2ND_TKT
    int32_t KRB5_TC_MATCH_KTYPE
    int32_t KRB5_TC_SUPPORTED_KTYPES


_CredentialsRetrieveFlags_members = [
    ('none', 0),
    ('match_times', KRB5_TC_MATCH_TIMES),
    ('match_is_skey', KRB5_TC_MATCH_IS_SKEY),
    ('match_flags', KRB5_TC_MATCH_FLAGS),
    ('match_times_exact', KRB5_TC_MATCH_TIMES_EXACT),
    ('match_flags_exact', KRB5_TC_MATCH_FLAGS_EXACT),
    ('match_authdata', KRB5_TC_MATCH_AUTHDATA),
    ('match_srv_nameonly', KRB5_TC_MATCH_SRV_NAMEONLY),
    ('match_2nd_tkt', KRB5_TC_MATCH_2ND_TKT),
    ('match_keytype', KRB5_TC_MATCH_KTYPE),
]
# If KRB5_TC_SUPPORTED_KTYPES is not available it will be set to 0 in
# python_krb5.h
if KRB5_TC_SUPPORTED_KTYPES != 0:
    _CredentialsRetrieveFlags_members += [
        ('supported_ktypes', KRB5_TC_SUPPORTED_KTYPES),
    ]
CredentialsRetrieveFlags = enum.IntEnum('CredentialsRetrieveFlags', _CredentialsRetrieveFlags_members)


cdef class CCache:
    # cdef Context ctx
    # cdef krb5_ccache raw

    def __cinit__(CCache self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(CCache self):
        if self.raw:
            krb5_cc_close(self.ctx.raw, self.raw)
            self.raw = NULL

    def __iter__(CCache self) -> typing.Iterator[Creds]:
        cdef krb5_error_code err = 0
        cdef krb5_cc_cursor cursor

        if self.raw == NULL:
            return

        err = krb5_cc_start_seq_get(self.ctx.raw, self.raw, &cursor)
        if err:
            raise Krb5Error(self.ctx, err)

        try:
            while True:
                creds = Creds(self.ctx)
                err = krb5_cc_next_cred(
                    self.ctx.raw,
                    self.raw,
                    &cursor,
                    creds.get_pointer(),
                )
                if err:
                    break

                creds.free_contents = 1
                yield creds

        finally:
            err = krb5_cc_end_seq_get(self.ctx.raw, self.raw, &cursor)
            if err:
                raise Krb5Error(self.ctx, err)

    @property
    def addr(self) -> typing.Optional[int]:
        if self.raw:
            return <uintptr_t>self.raw

    @property
    def name(self) -> typing.Optional[bytes]:
        if self.raw:
            return cc_get_name(self.ctx, self)

    @property
    def principal(self) -> typing.Optional[Principal]:
        if self.raw:
            return cc_get_principal(self.ctx, self)

    @property
    def cache_type(self) -> typing.Optional[bytes]:
        if self.raw:
            return cc_get_type(self.ctx, self)

    def __repr__(CCache self) -> str:
        if self.raw:
            kwargs = [f"{k}={v}" for k, v in {
                'cache_type': self.cache_type.decode('utf-8'),
                'name': self.name.decode('utf-8'),
            }.items()]

            return f"CCache({', '.join(kwargs)})"

        else:
            return "CCache(NULL)"

    def __str__(CCache self) -> str:
        if self.raw:
            return f"{self.cache_type.decode('utf-8')}:{self.name.decode('utf-8')}"

        else:
            return "NULL"


def cc_default(
    Context context not None,
) -> CCache:
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_default(context.raw, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache


def cc_default_name(
    Context context not None,
) -> bytes:
    return <bytes>krb5_cc_default_name(context.raw)


def cc_destroy(
    Context context not None,
    CCache cache not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_cc_destroy(context.raw, cache.raw)
    if err:
        raise Krb5Error(context, err)
    cache.raw = NULL  # Stops dealloc from calling close


def cc_get_name(
    Context context not None,
    CCache cache not None,
) -> bytes:
    return krb5_cc_get_name(context.raw, cache.raw)


def cc_get_principal(
    Context context not None,
    CCache cache not None,
) -> Principal:
    princ = Principal(context, PrincipalParseFlags.none)
    cdef krb5_error_code err = 0

    err = krb5_cc_get_principal(context.raw, cache.raw, &princ.raw)
    if err:
        raise Krb5Error(context, err)

    return princ


def cc_get_type(
    Context context not None,
    CCache cache not None,
) -> bytes:
    return krb5_cc_get_type(context.raw, cache.raw)


def cc_initialize(
    Context context not None,
    CCache cache not None,
    Principal principal not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_cc_initialize(context.raw, cache.raw, principal.raw)
    if err:
        raise Krb5Error(context, err)


def cc_new_unique(
    Context context not None,
    const unsigned char[:] cred_type not None,
    const unsigned char[:] hint = None,
) -> CCache:
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    # TODO: Test that this cannot be NULL
    if not len(cred_type):
        raise ValueError("cred_type must be set to a valid type value not an empty byte string")

    cdef const char *hint_ptr = NULL
    if hint is not None and len(hint):
        hint_ptr = <const char*>&hint[0]

    err = krb5_cc_new_unique(context.raw, <const char*>&cred_type[0], hint_ptr, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache


def cc_remove_cred(
    Context context not None,
    CCache cache not None,
    int flags,
    Creds creds not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_cc_remove_cred(
        context.raw,
        cache.raw,
        flags,
        creds.get_pointer(),
    )
    if err:
        raise Krb5Error(context, err)


def cc_resolve(
    Context context not None,
    const unsigned char[:] name not None,
) -> CCache:
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("name cannot be an empty byte string")

    err = krb5_cc_resolve(context.raw, name_ptr, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache


def cc_retrieve_cred(
    Context context not None,
    CCache cache not None,
    int flags,
    Creds mcreds not None,
) -> Creds:
    creds = Creds(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_retrieve_cred(
        context.raw,
        cache.raw,
        flags,
        mcreds.get_pointer(),
        creds.get_pointer())
    if err:
        raise Krb5Error(context, err)

    creds.free_contents = 1

    return creds


def cc_set_default_name(
    Context context not None,
    const unsigned char[:] name,
) -> None:
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if name is not None and len(name):
        name_ptr = <const char *>&name[0]

    err = krb5_cc_set_default_name(context.raw, name_ptr)
    if err:
        raise Krb5Error(context, err)


def cc_store_cred(
    Context context not None,
    CCache cache not None,
    Creds creds not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_cc_store_cred(context.raw, cache.raw, creds.get_pointer())
    if err:
        raise Krb5Error(context, err)


def cc_switch(
    Context context not None,
    CCache cache not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_cc_switch(context.raw, cache.raw)
    if err:
        raise Krb5Error(context, err)


def cc_get_config(
    Context context not None,
    CCache cache not None,
    Principal principal,
    const unsigned char[:] key not None,
) -> bytes:
    cdef krb5_error_code err = 0

    cdef krb5_principal principal_raw = NULL
    if principal is not None:
        principal_raw = principal.raw

    cdef const char *key_ptr
    if len(key):
        key_ptr = <const char*>&key[0]
    else:
        key_ptr = ""

    cdef krb5_data data
    err = krb5_cc_get_config(context.raw, cache.raw, principal_raw, key_ptr, &data)
    if err:
        raise Krb5Error(context, err)

    cdef size_t length
    cdef char *value
    pykrb5_get_krb5_data(&data, &length, &value)

    if length == 0:
        data_bytes = b""
    else:
        data_bytes = <bytes>value[:length]

    pykrb5_free_data_contents(context.raw, &data)

    return data_bytes


def cc_set_config(
    Context context not None,
    CCache cache not None,
    Principal principal,
    const unsigned char[:] key not None,
    const unsigned char[:] data,
) -> None:
    cdef krb5_error_code err = 0

    cdef krb5_principal principal_raw = NULL
    if principal is not None:
        principal_raw = principal.raw

    cdef const char *key_ptr
    if len(key):
        key_ptr = <const char*>&key[0]
    else:
        key_ptr = ""

    cdef krb5_data data_raw
    cdef krb5_data* data_ptr
    if data is None:
        data_ptr = NULL
    else:
        if len(data) == 0:
            pykrb5_set_krb5_data(&data_raw, 0, "")
        else:
            pykrb5_set_krb5_data(&data_raw, len(data), <char *>&data[0])
        data_ptr = &data_raw

    err = krb5_cc_set_config(context.raw, cache.raw, principal_raw, key_ptr, data_ptr)
    if err:
        raise Krb5Error(context, err)
