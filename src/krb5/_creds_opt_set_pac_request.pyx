# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_get_init_creds_opt_set_pac_request(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_boolean req_pac,
    ) nogil


def get_init_creds_opt_set_pac_request(
    Context context not None,
    GetInitCredsOpt opt not None,
    req_pac: bool,
) -> None:
    cdef int value = 1 if req_pac else 0

    krb5_get_init_creds_opt_set_pac_request(context.raw, opt.raw, value)
