# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef class KeyTab:
    cdef Context ctx
    cdef krb5_keytab raw


cdef class KeyTabEntry:
    cdef Context ctx
    cdef krb5_keytab_entry raw
    cdef int needs_free
