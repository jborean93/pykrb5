# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    """
#if defined(HEIMDAL_XFREE)
#error "Heimdal implementation of krb5_get_validated_creds() does not work"
#endif
    """

    krb5_error_code krb5_get_validated_creds(
        krb5_context context,
        krb5_creds *creds,
        krb5_principal client,
        krb5_ccache ccache,
        const char *in_tkt_service,
    ) nogil


def get_validated_creds(
    Context context not None,
    Principal client not None,
    CCache ccache not None,
    const unsigned char[:] in_tkt_service = None,
) -> Creds:
    creds = Creds(context)
    cdef krb5_error_code err = 0

    cdef const char *in_tkt_service_ptr = NULL
    if in_tkt_service is not None and len(in_tkt_service):
        in_tkt_service_ptr = <const char*>&in_tkt_service[0]

    err = krb5_get_validated_creds(context.raw, &creds.raw, client.raw, ccache.raw, in_tkt_service_ptr)
    if err:
        raise Krb5Error(context, err)

    creds.needs_free = 1

    return creds
