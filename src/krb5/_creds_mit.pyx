# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import typing

from krb5._exceptions import Krb5Error

from libc.string cimport memcpy

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    """
#if defined(HEIMDAL_XFREE)
#error "Heimdal implementation does not support MIT-specific calls:"
#error " krb5_get_validated_creds()"
#error " krb5_get_etype_info()"
#error " krb5_marshal_credentials()"
#error " krb5_unmarshal_credentials()"
#endif
    """

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

    krb5_error_code krb5_marshal_credentials(
        krb5_context context,
        krb5_creds *creds,
        krb5_data **data
    ) nogil

    krb5_error_code krb5_unmarshal_credentials(
        krb5_context context,
        krb5_data *data,
        krb5_creds **creds,
    ) nogil

    void krb5_free_data(
        krb5_context context,
        krb5_data *val,
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

EtypeInfo = collections.namedtuple('EtypeInfo', [
    'etype',
    'salt',
    's2kparams',
])

def marshal_credentials(Context context not None, Creds creds not None) -> bytes:
    cdef krb5_error_code err = 0
    cdef krb5_data *data = NULL
    cdef size_t length
    cdef char *value

    try:
        err = krb5_marshal_credentials(context.raw, &creds.raw, &data)

        if err:
            raise Krb5Error(context, err)

        pykrb5_get_krb5_data(data, &length, &value)

        if length == 0:
            data_bytes = b""
        else:
            data_bytes = value[:length]

        return data_bytes

    finally:
        if NULL != data:
            krb5_free_data(context.raw, data)

def unmarshal_credentials(Context context not None, const unsigned char[:] data not None) -> Creds:
    cdef krb5_error_code err = 0
    cdef krb5_data data_raw

    creds = Creds(context)

    if len(data) == 0:
        pykrb5_set_krb5_data(&data_raw, 0, "")
    else:
        pykrb5_set_krb5_data(&data_raw, len(data), <char *>&data[0])

    err = krb5_unmarshal_credentials(context.raw, &data_raw, &creds._raw_ptr)

    if creds._raw_ptr:
        # creds_raw was calloc'ed for krb5_creds structure
        # "shallow copy" the structure
        memcpy(&creds.raw, creds._raw_ptr, sizeof(creds.raw))
        # mark "deep copy" for future deallocation
        creds.needs_free = 1

    if err:
        raise Krb5Error(context, err)

    return creds
