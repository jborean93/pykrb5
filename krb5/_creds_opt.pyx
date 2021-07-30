# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "krb5.h":
    krb5_error_code krb5_get_init_creds_opt_alloc(
        krb5_context context,
        krb5_get_init_creds_opt **opt,
    ) nogil

    void krb5_get_init_creds_opt_free(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
    ) nogil

    void krb5_get_init_creds_opt_set_forwardable(
        krb5_get_init_creds_opt *opt,
        int forwardable,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_set_out_ccache(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_ccache ccache,
    ) nogil


cdef class GetInitCredsOpt:
    """Kerberos Initial Credential Options object.

    This class represents an initial credential options object.

    Args:
        context: Krb5 context.
    """
    # cdef Context ctx
    # cdef krb5_get_init_creds_opt *raw

    def __cinit__(GetInitCredsOpt self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(GetInitCredsOpt self):
        if self.raw:
            krb5_get_init_creds_opt_free(self.ctx.raw, self.raw)
            self.raw = NULL


def get_init_creds_opt_alloc(
    Context context not None,
) -> GetInitCredsOpt:
    """Allocate a new initial credential options object.

    Creates a new options structure that control how credential are gotten.

    Args:
        context: Krb5 context.

    Returns:
        GetInitCredsOpt: The initial credential options object.
    """
    opt = GetInitCredsOpt(context)
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_alloc(context.raw, &opt.raw)
    if err:
        raise Krb5Error(context, err)

    return opt


def get_init_creds_opt_set_forwardable(
    GetInitCredsOpt opt not None,
    forwardable: bool,
) -> None:
    """Set forwardable details in the initial credential options.

    Sets whether the credentials are to be forwardable or not.

    Args:
        opt: The initial credential options.
        forwardable: Whether to set or unset the forwardable option.
    """
    cdef int value = 1 if forwardable else 0

    krb5_get_init_creds_opt_set_forwardable(opt.raw, value)


def get_init_creds_opt_set_out_ccache(
    Context context not None,
    GetInitCredsOpt opt not None,
    CCache ccache not None,
) -> None:
    """Set output credential cache in options.

    Sets the output credential cache in the credential option structure.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        ccache: The credential cache to set as the output.
    """
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_set_out_ccache(context.raw, opt.raw, ccache.raw)
    if err:
        raise Krb5Error(context, err)
