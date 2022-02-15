# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_get_init_creds_opt_set_fast_ccache(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_ccache ccache,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_set_fast_flags(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_int32 flags,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_set_fast_ccache_name(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        const char *fast_ccache_name,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_set_out_ccache(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_ccache ccache,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_set_pa(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        const char *attr,
        const char *value,
    ) nogil

    int32_t KRB5_FAST_REQUIRED


class FastFlags(enum.IntEnum):
    none = 0
    required = KRB5_FAST_REQUIRED


def get_init_creds_opt_set_fast_ccache(
    Context context not None,
    GetInitCredsOpt opt not None,
    CCache ccache not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_set_fast_ccache(context.raw, opt.raw, ccache.raw)
    if err:
        raise Krb5Error(context, err)


def get_init_creds_opt_set_fast_flags(
    Context context not None,
    GetInitCredsOpt opt not None,
    krb5_int32 flags,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_set_fast_flags(context.raw, opt.raw, flags)
    if err:
        raise Krb5Error(context, err)


def get_init_creds_opt_set_fast_ccache_name(
    Context context not None,
    GetInitCredsOpt opt not None,
    const unsigned char[:] name not None,
) -> None:
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("CCache name must be set")

    err = krb5_get_init_creds_opt_set_fast_ccache_name(context.raw, opt.raw, name_ptr)
    if err:
        raise Krb5Error(context, err)


def get_init_creds_opt_set_out_ccache(
    Context context not None,
    GetInitCredsOpt opt not None,
    CCache ccache not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_set_out_ccache(context.raw, opt.raw, ccache.raw)
    if err:
        raise Krb5Error(context, err)


def get_init_creds_opt_set_pa(
    Context context not None,
    GetInitCredsOpt opt not None,
    const unsigned char[:] attr not None,
    const unsigned char[:] value not None,
) -> None:
    cdef krb5_error_code err = 0

    cdef char *attr_ptr
    if len(attr):
        attr_ptr = <char *>&attr[0]
    else:
        raise ValueError("attr must be set")

    cdef char *value_ptr
    if len(value):
        value_ptr = <char *>&value[0]
    else:
        raise ValueError("value must be set")

    err = krb5_get_init_creds_opt_set_pa(context.raw, opt.raw, attr_ptr, value_ptr)
    if err:
        raise Krb5Error(context, err)
