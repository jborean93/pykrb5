# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error
from krb5._keyblock import init_keyblock

from krb5._context cimport Context
from krb5._keyblock cimport KeyBlock
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_c_string_to_key(
        krb5_context context,
        krb5_enctype enctype,
        const krb5_data *string,
        const krb5_data *salt,
        krb5_keyblock *key,
    ) nogil

    krb5_error_code krb5_c_string_to_key_with_params(
        krb5_context context,
        krb5_enctype enctype,
        const krb5_data *string,
        const krb5_data *salt,
        const krb5_data *params,
        krb5_keyblock *key,
    ) nogil


def c_string_to_key(
    Context context not None,
    krb5_enctype enctype,
    const unsigned char[:] string,
    const unsigned char[:] salt,
    const unsigned char[:] s2kparams = None,
) -> KeyBlock:
    cdef krb5_error_code err = 0
    cdef size_t length = 0

    cdef KeyBlock kb = init_keyblock(context, enctype, None)

    cdef krb5_data string_raw
    if len(string) == 0:
        pykrb5_set_krb5_data(&string_raw, 0, "")
    else:
        pykrb5_set_krb5_data(&string_raw, len(string), <char *>&string[0])

    cdef krb5_data salt_raw
    if len(salt) == 0:
        pykrb5_set_krb5_data(&salt_raw, 0, "")
    else:
        pykrb5_set_krb5_data(&salt_raw, len(salt), <char *>&salt[0])

    cdef krb5_data s2kparams_raw
    if s2kparams is None:
        err = krb5_c_string_to_key(context.raw, enctype, &string_raw, &salt_raw, kb.raw)
    else:
        if len(s2kparams) == 0:
           pykrb5_set_krb5_data(&s2kparams_raw, 0, "")
        else:
           pykrb5_set_krb5_data(&s2kparams_raw, len(s2kparams), <char *>&s2kparams[0])

        err = krb5_c_string_to_key_with_params(context.raw, enctype, &string_raw, &salt_raw, &s2kparams_raw, kb.raw)

    if err:
        raise Krb5Error(context, err)

    return kb
