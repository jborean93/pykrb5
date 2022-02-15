# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdint cimport int32_t, uint8_t, uint32_t


cdef extern from "python_krb5.h":
    """
    // The structures are different so cannot be explicitly defined in Cython. Use inline C to set the structs elements
    // by name.
    void pykrb5_set_krb5_data(
        krb5_data *data,
        size_t length,
        char *value
    )
    {
        data->length = length;
        data->data = value;
    }
    """

    ctypedef int32_t krb5_int32
    ctypedef krb5_int32 krb5_error_code
    ctypedef krb5_int32 krb5_deltat
    ctypedef krb5_int32 krb5_enctype
    ctypedef uint8_t krb5_octet
    ctypedef krb5_int32 krb5_timestamp
    ctypedef unsigned int krb5_boolean
    ctypedef unsigned int krb5_kvno

    ctypedef void *krb5_pointer;
    ctypedef krb5_pointer krb5_cc_cursor
    ctypedef krb5_pointer krb5_kt_cursor;

    cdef struct _krb5_context:
        pass
    ctypedef _krb5_context *krb5_context

    cdef struct _krb5_cccol_cursor:
        pass
    ctypedef _krb5_cccol_cursor *krb5_cccol_cursor

    cdef struct krb5_principal_data:
        pass
    ctypedef krb5_principal_data *krb5_principal
    ctypedef const krb5_principal_data *krb5_const_principal

    cdef struct _krb5_ccache:
        pass
    ctypedef _krb5_ccache *krb5_ccache

    cdef struct _krb5_get_init_creds_opt:
        pass
    ctypedef _krb5_get_init_creds_opt krb5_get_init_creds_opt

    cdef struct _krb5_init_creds_context:
        pass
    ctypedef _krb5_init_creds_context *krb5_init_creds_context

    cdef struct _krb5_keyblock:
        pass
    ctypedef _krb5_keyblock krb5_keyblock

    cdef struct _krb5_data:
        pass
    ctypedef _krb5_data krb5_data

    cdef struct _krb5_kt:
        pass
    ctypedef _krb5_kt *krb5_keytab

    cdef struct krb5_keytab_entry_st:
        pass
    ctypedef krb5_keytab_entry_st krb5_keytab_entry

    cdef struct _krb5_creds:
        pass
    ctypedef _krb5_creds krb5_creds

    cdef struct _krb5_prompt:
        char *prompt
        int hidden
        krb5_data *reply
    ctypedef _krb5_prompt krb5_prompt

    ctypedef krb5_error_code(*krb5_prompter_fct)(
        krb5_context context,
        void *data,
        const char *name,
        const char *banner,
        int num_prompts,
        krb5_prompt prompts[],
    )

    void pykrb5_set_krb5_data(
        krb5_data *data,
        size_t length,
        char *value,
    ) nogil
