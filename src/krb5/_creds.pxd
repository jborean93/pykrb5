# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef class Creds:
    cdef Context ctx
    cdef krb5_creds raw
    cdef int needs_free


cdef class InitCredsContext:
    cdef Context ctx
    cdef krb5_init_creds_context raw


cdef class Krb5Prompt:
    pass
