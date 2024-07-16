# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

# These APIs were added in MIT 1.20, to be compat with 1.18 we need to define
# them separately.

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

def marshal_credentials(
    Context context not None,
    Creds creds not None,
) -> bytes:
    cdef krb5_error_code err = 0
    cdef krb5_data *data = NULL
    cdef size_t length
    cdef char *value

    try:
        err = krb5_marshal_credentials(context.raw, creds.get_pointer(), &data)

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

def unmarshal_credentials(
    Context context not None,
    const unsigned char[:] data not None,
) -> Creds:
    cdef krb5_error_code err = 0
    cdef krb5_creds* raw_creds = NULL
    cdef krb5_data data_raw

    if len(data) == 0:
        pykrb5_set_krb5_data(&data_raw, 0, "")
    else:
        pykrb5_set_krb5_data(&data_raw, len(data), <char *>&data[0])

    err = krb5_unmarshal_credentials(context.raw, &data_raw, &raw_creds)
    if err:
        raise Krb5Error(context, err)

    creds = Creds(context)
    creds.set_raw_from_lib(raw_creds)

    return creds
