from kinit._krb5_types cimport *


cdef class Krb5Context:
    cdef krb5_context raw


cdef class Krb5Principal:
    cdef Krb5Context ctx
    cdef krb5_principal raw


cdef class Krb5CCache:
    cdef Krb5Context ctx
    cdef krb5_ccache raw


cdef class Krb5GetInitCredsOpt:
    cdef Krb5Context ctx
    cdef krb5_get_init_creds_opt *raw


cdef class Krb5Creds:
    cdef Krb5Context ctx
    cdef krb5_creds raw
    cdef int needs_free
