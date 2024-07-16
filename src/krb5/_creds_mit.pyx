# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import typing

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    krb5_error_code krb5_get_validated_creds(
        krb5_context context,
        krb5_creds *creds,
        krb5_principal client,
        krb5_ccache ccache,
        const char *in_tkt_service,
    ) nogil

    krb5_error_code krb5_get_etype_info(
        krb5_context context,
        krb5_principal principal,
        krb5_get_init_creds_opt *opt,
        krb5_enctype *enctype_out,
        krb5_data *salt_out,
        krb5_data *s2kparams_ou,
    ) nogil

EtypeInfo = collections.namedtuple('EtypeInfo', [
    'etype',
    'salt',
    's2kparams',
])

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

    err = krb5_get_validated_creds(
        context.raw,
        creds.get_pointer(),
        client.raw,
        ccache.raw,
        in_tkt_service_ptr)
    if err:
        raise Krb5Error(context, err)

    creds.free_contents = 1

    return creds

def get_etype_info(
    Context context not None,
    Principal principal not None,
    GetInitCredsOpt opt = None,
) -> EtypeInfo:
    cdef krb5_error_code err = 0

    cdef krb5_get_init_creds_opt *options = NULL
    if opt:
        options = opt.raw

    cdef krb5_enctype enctype
    cdef krb5_data salt
    cdef krb5_data s2kparams

    with nogil:
        err = krb5_get_etype_info(
            context.raw,
            principal.raw,
            options,
            &enctype,
            &salt,
            &s2kparams,
        )
    if err:
        raise Krb5Error(context, err)

    cdef size_t length
    cdef char *value

    pykrb5_get_krb5_data(&salt, &length, &value)
    if length == 0:
        if enctype == 0:  # ENCTYPE_NULL
            # If enctype is ENCTYPE_NULL and the salt is empty this means that
            # the KDC provided no etype-info. Return None in this case.
            salt_bytes = None
        else:
            salt_bytes = b""
    else:
        salt_bytes = <bytes>value[:length]
    pykrb5_free_data_contents(context.raw, &salt)

    pykrb5_get_krb5_data(&s2kparams, &length, &value)
    if length == 0:
        # This means that the KDC provided an etype-info without s2kparams
        # (PA-ETYPE-INFO instead of PA-ETYPE-INFO2).
        # Return None instead of b'' in this case so that the value can be
        # passed directly to krb.c_string_to_key()
        s2kparams_bytes = None
    else:
        s2kparams_bytes = <bytes>value[:length]
    pykrb5_free_data_contents(context.raw, &s2kparams)

    return EtypeInfo(enctype, salt_bytes, s2kparams_bytes)
