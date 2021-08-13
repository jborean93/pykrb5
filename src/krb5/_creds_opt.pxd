# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef class GetInitCredsOpt:
    cdef Context ctx
    cdef krb5_get_init_creds_opt *raw
