# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from libc.stdlib cimport free, malloc

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # Heimdal requires the context arg whereas MIT does not.
    """
    void krb5_get_init_creds_opt_set_canonicalize_generic(krb5_context context,
                                                          krb5_get_init_creds_opt *opt,
                                                          int canonicalize)
    {
    #if defined(HEIMDAL_XFREE)
        krb5_get_init_creds_opt_set_canonicalize(context, opt, (krb5_boolean)canonicalize);
    #else
        krb5_get_init_creds_opt_set_canonicalize(opt, canonicalize);
    #endif
    }
    """

    krb5_error_code krb5_get_init_creds_opt_alloc(
        krb5_context context,
        krb5_get_init_creds_opt **opt,
    ) nogil

    void krb5_get_init_creds_opt_set_anonymous(
        krb5_get_init_creds_opt *opt,
        int anonymous,
    ) nogil

    void krb5_get_init_creds_opt_free(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
    ) nogil

    void krb5_get_init_creds_opt_set_canonicalize_generic(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        int canonicalize,
    ) nogil

    void krb5_get_init_creds_opt_set_etype_list(
        krb5_get_init_creds_opt *opt,
        krb5_enctype *etype_list,
        int etype_list_length,
    ) nogil

    void krb5_get_init_creds_opt_set_forwardable(
        krb5_get_init_creds_opt *opt,
        int forwardable,
    ) nogil

    void krb5_get_init_creds_opt_set_proxiable(
        krb5_get_init_creds_opt *opt,
        int proxiable,
    ) nogil

    void krb5_get_init_creds_opt_set_renew_life(
        krb5_get_init_creds_opt *opt,
        krb5_deltat renew_life,
    ) nogil

    void krb5_get_init_creds_opt_set_salt(
        krb5_get_init_creds_opt *opt,
        krb5_data *salt,
    ) nogil

    void krb5_get_init_creds_opt_set_tkt_life(
        krb5_get_init_creds_opt *opt,
        krb5_deltat tkt_life,
    ) nogil


cdef class GetInitCredsOpt:
    # cdef Context ctx
    # cdef krb5_get_init_creds_opt *raw

    def __cinit__(GetInitCredsOpt self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(GetInitCredsOpt self):
        if self.raw:
            krb5_get_init_creds_opt_free(self.ctx.raw, self.raw)
            self.raw = NULL

    def __str__(GetInitCredsOpt self):
        return "GetInitCredsOpt"


def get_init_creds_opt_alloc(
    Context context not None,
) -> GetInitCredsOpt:
    opt = GetInitCredsOpt(context)
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_alloc(context.raw, &opt.raw)
    if err:
        raise Krb5Error(context, err)

    return opt


def get_init_creds_opt_set_anonymous(
    GetInitCredsOpt opt not None,
    anonymous: bool,
) -> None:
    cdef int value = 1 if anonymous else 0

    krb5_get_init_creds_opt_set_anonymous(opt.raw, value)


def get_init_creds_opt_set_canonicalize(
    GetInitCredsOpt opt not None,
    canonicalize: bool,
) -> None:
    cdef int value = 1 if canonicalize else 0

    krb5_get_init_creds_opt_set_canonicalize_generic(opt.ctx.raw, opt.raw, value)


def get_init_creds_opt_set_etype_list(
    GetInitCredsOpt opt not None,
    etypes: typing.Iterable[int],
) -> None:
    tmp = list(etypes)
    cdef krb5_enctype *buffer = <krb5_enctype *>malloc(len(etypes) * sizeof(krb5_enctype))
    if not buffer:
        raise MemoryError()

    for idx, e in enumerate(tmp):
        buffer[idx] = tmp[idx]

    krb5_get_init_creds_opt_set_etype_list(opt.raw, buffer, len(etypes))


def get_init_creds_opt_set_forwardable(
    GetInitCredsOpt opt not None,
    forwardable: bool,
) -> None:
    cdef int value = 1 if forwardable else 0

    krb5_get_init_creds_opt_set_forwardable(opt.raw, value)


def get_init_creds_opt_set_proxiable(
    GetInitCredsOpt opt not None,
    proxiable: bool,
) -> None:
    cdef int value = 1 if proxiable else 0

    krb5_get_init_creds_opt_set_proxiable(opt.raw, value)


def get_init_creds_opt_set_renew_life(
    GetInitCredsOpt opt not None,
    krb5_deltat renew_life,
) -> None:
    krb5_get_init_creds_opt_set_renew_life(opt.raw, renew_life)


def get_init_creds_opt_set_salt(
    GetInitCredsOpt opt not None,
    const unsigned char[:] salt not None,
) -> None:
    if not len(salt):
        raise ValueError("salt cannot be an empty byte string")

    cdef krb5_data buffer
    pykrb5_set_krb5_data(&buffer, len(salt), <char *>&salt[0])
    krb5_get_init_creds_opt_set_salt(opt.raw, &buffer)


def get_init_creds_opt_set_tkt_life(
    GetInitCredsOpt opt not None,
    krb5_deltat tkt_life,
) -> None:
    krb5_get_init_creds_opt_set_tkt_life(opt.raw, tkt_life)
