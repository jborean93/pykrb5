# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    # Added in MIT krb5 1.10
    krb5_error_code krb5_cc_cache_match(
        krb5_context context,
        krb5_principal client,
        krb5_ccache *cache_out,
    ) nogil



def cc_cache_match(
    Context context not None,
    Principal principal not None,
) -> CCache:
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_cache_match(context.raw, principal.raw, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache
