# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

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

    void krb5_get_init_creds_opt_free(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
    ) nogil

    void krb5_get_init_creds_opt_set_canonicalize_generic(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        int canonicalize,
    ) nogil

    void krb5_get_init_creds_opt_set_forwardable(
        krb5_get_init_creds_opt *opt,
        int forwardable,
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


def get_init_creds_opt_set_canonicalize(
    GetInitCredsOpt opt not None,
    canonicalize: bool,
) -> None:
    cdef int value = 1 if canonicalize else 0

    krb5_get_init_creds_opt_set_canonicalize_generic(opt.ctx.raw, opt.raw, value)


def get_init_creds_opt_set_forwardable(
    GetInitCredsOpt opt not None,
    forwardable: bool,
) -> None:
    cdef int value = 1 if forwardable else 0

    krb5_get_init_creds_opt_set_forwardable(opt.raw, value)
