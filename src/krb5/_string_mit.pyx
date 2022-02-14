# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdlib cimport free, malloc

from krb5._exceptions import Krb5Error

from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    krb5_error_code krb5_enctype_to_name(
        krb5_enctype enctype,
        krb5_boolean shortest,
        char *buffer,
        size_t buflen,
    ) nogil


def enctype_to_name(
    krb5_enctype enctype,
    krb5_boolean shortest = False,
) -> str:
    cdef krb5_error_code err = 0
    cdef void *buffer = malloc(100)
    if buffer == NULL:
        raise MemoryError()

    err = krb5_enctype_to_name(enctype, shortest, <char *>buffer, 100)
    if err:
        raise ValueError("Invalid encryption type")

    try:
        return (<char *>buffer).decode("utf-8")
    finally:
        free(buffer)
