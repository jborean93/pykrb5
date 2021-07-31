# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from libc.stdint cimport int32_t, uint8_t


cdef extern from "python_krb5.h":
    ctypedef int32_t krb5_int32
    ctypedef krb5_int32 krb5_error_code
    ctypedef krb5_int32 krb5_deltat
    ctypedef krb5_error_code krb5_magic
    ctypedef krb5_int32 krb5_enctype
    ctypedef uint8_t krb5_octet
    ctypedef krb5_int32 krb5_timestamp
    ctypedef unsigned int krb5_boolean
    ctypedef krb5_int32 krb5_flags

    cdef struct _krb5_context:
        pass
    ctypedef _krb5_context *krb5_context

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
        krb5_magic magic
        krb5_enctype enctype
        unsigned int length
        krb5_octet *contexts
    ctypedef _krb5_keyblock krb5_keyblock

    cdef struct _krb5_ticket_times:
        krb5_timestamp authtime
        krb5_timestamp starttime
        krb5_timestamp endtime
        krb5_timestamp renew_till
    ctypedef _krb5_ticket_times krb5_ticket_times

    cdef struct _krb5_address:
        pass
    ctypedef _krb5_address krb5_address

    cdef struct _krb5_data:
        krb5_magic magic
        unsigned int length
        char *data
    ctypedef _krb5_data krb5_data

    cdef struct _krb5_authdata:
        pass
    ctypedef _krb5_authdata krb5_authdata

    cdef struct _krb5_kt:
        pass
    ctypedef _krb5_kt *krb5_keytab

    cdef struct _krb5_creds:
        krb5_magic magic
        krb5_principal client
        krb5_principal server
        krb5_keyblock keyblock
        krb5_ticket_times times
        krb5_boolean is_skey
        krb5_flags ticket_flags
        krb5_address **addresses
        krb5_data ticket
        krb5_data second_ticket
        krb5_authdata **authdata
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
