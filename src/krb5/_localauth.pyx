# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdlib cimport free, malloc

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":

    krb5_error_code krb5_aname_to_localname(
        krb5_context context,
        krb5_const_principal aname,
        int lnsize,
        char *lname_out
    ) nogil

    krb5_error_code KRB5_LNAME_NOTRANS

def aname_to_localname(
    context: Context,
    principal: Principal
) -> str:

    cdef krb5_error_code err = 0
    limit = 256

    cdef char *localname = <char *>malloc(limit + 1)
    if not localname:
        raise MemoryError()

    err = krb5_aname_to_localname(context.raw, principal.raw, limit, localname)
    # The definition of KRB5_LNAME_NOTRANS in the Heimdal header file
    # included in the pykrb5 source appears to be out of date; this is
    # the value that actually gets returned in the test -- so I'm just
    # adding it here for now.
    if err in [KRB5_LNAME_NOTRANS, -1765328227]:
        return None
    elif err != 0:
        free(localname)
        raise Krb5Error(context, err)
    else:
        return localname.decode("utf-8")
