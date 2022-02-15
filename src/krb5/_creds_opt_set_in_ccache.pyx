# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_get_init_creds_opt_set_in_ccache(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_ccache ccache,
    ) nogil


def get_init_creds_opt_set_in_ccache(
    Context context not None,
    GetInitCredsOpt opt not None,
    CCache ccache not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_get_init_creds_opt_set_in_ccache(context.raw, opt.raw, ccache.raw)
    if err:
        raise Krb5Error(context, err)
