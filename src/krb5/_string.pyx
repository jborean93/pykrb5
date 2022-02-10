# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdlib cimport free

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    # Heimdal and MIT differ in their implementations
    """
    krb5_error_code krb5_enctype_to_string_generic(
        krb5_context context,
        krb5_enctype enctype,
        char **buffer
    )
    {
    // Heimdal takes in a context and sets an output pointer
    #if defined(HEIMDAL_XFREE)
        return krb5_enctype_to_string(context, enctype, buffer);
    #else
        char *tmp = malloc(100);
        if (tmp == NULL)
        {
            return ENOMEM;
        }
        *buffer = tmp;

        return krb5_enctype_to_string(enctype, tmp, 100);
    #endif
    }

    krb5_error_code krb5_string_to_enctype_generic(
        krb5_context context,
        char *string,
        krb5_enctype *enctypep
    )
    {
    // MIT does not have a context overload
    #if defined(HEIMDAL_XFREE)
        return krb5_string_to_enctype(context, string, enctypep);
    #else
        return krb5_string_to_enctype(string, enctypep);
    #endif
    }
    """

    krb5_error_code krb5_enctype_to_string_generic(
        krb5_context context,
        krb5_enctype enctype,
        char **buffer,
    ) nogil

    krb5_error_code krb5_string_to_enctype_generic(
        krb5_context context,
        char *string,
        krb5_enctype *enctypep,
    ) nogil


def enctype_to_string(
    Context context not None,
    krb5_enctype enctype,
) -> str:
    cdef krb5_error_code err = 0
    cdef char *buffer = NULL

    err = krb5_enctype_to_string_generic(context.raw, enctype, &buffer)
    if err:
        raise Krb5Error(context, err)

    try:
        return buffer.decode("utf-8")
    finally:
        free(buffer)


def string_to_enctype(
    Context context not None,
    str string,
) -> int:
    cdef krb5_enctype enctype = 0
    cdef krb5_error_code err = 0
    b_string = string.encode("utf-8")
    cdef char *string_ptr = b_string

    err = krb5_string_to_enctype_generic(context.raw, string_ptr, &enctype)
    if err:
        raise Krb5Error(context, err)

    return enctype
