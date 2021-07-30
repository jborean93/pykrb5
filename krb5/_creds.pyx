# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import typing

from krb5._exceptions import Krb5Error

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *
from krb5._kt cimport KeyTab
from krb5._principal cimport Principal


cdef extern from "krb5.h":
    void krb5_free_cred_contents(
        krb5_context context,
        krb5_creds *val,
    ) nogil

    krb5_error_code krb5_get_init_creds_keytab(
        krb5_context context,
        krb5_creds *creds,
        krb5_principal client,
        krb5_keytab arg_keytab,
        krb5_deltat start_time,
        const char *in_tkt_service,
        krb5_get_init_creds_opt *k5_gic_options,
    ) nogil

    ctypedef krb5_error_code(*krb5_prompter_fct)(
        krb5_context context,
        void *data,
        const char *name,
        const char *banner,
        int num_prompts,
        krb5_prompt prompts[],
    )

    krb5_error_code krb5_get_init_creds_password(
        krb5_context context,
        krb5_creds *creds,
        krb5_principal client,
        const char *password,
        krb5_prompter_fct prompter,
        void *data,
        krb5_deltat start_time,
        const char *in_tkt_service,
        krb5_get_init_creds_opt *k5_gic_options,
    ) nogil


cdef class Creds:
    """Kerberos Credentials object.

    This class represents Kerberos credentials.

    Args:
        context: Krb5 context.
    """
    # cdef Context ctx
    # cdef krb5_creds raw
    # cdef int needs_free

    def __cinit__(CCache self, Context context):
        self.ctx = context
        self.needs_free = 0

    def __dealloc__(CCache self):
        if self.needs_free:
            krb5_free_cred_contents(self.ctx.raw, &self.raw)
            self.needs_free = 0


Krb5Prompt = collections.namedtuple("Krb5Prompt", ["msg", "hidden"])


cdef krb5_error_code prompt_callback(
    krb5_context context,
    void *data,
    const char *name,
    const char *banner,
    int num_prompts,
    krb5_prompt *prompts,
) with gil:
    # FIXME: Properly expose this publicly.
    try:
        py_name = None if name == NULL else <bytes>name
        py_banner = None if banner == NULL else <bytes>banner
        py_prompts = []
        for prompt in prompts[:num_prompts]:
            msg = <bytes>prompt.prompt
            hidden = prompt.hidden != 0
            py_prompts.append(Krb5Prompt(msg, hidden))

        replies = (<object>data)(py_name, py_banner, py_prompts)
        for idx, reply in enumerate(replies):
            prompts[idx].reply.length = len(reply)
            prompts[idx].reply.data = <char *>reply

        return 0

    except Exception as e:
        print(str(e))  # FIXME: Remove
        return 1


def get_init_creds_keytab(
    Context context not None,
    Principal client not None,
    KeyTab keytab not None,
    GetInitCredsOpt k5_gic_options not None,
    int start_time = 0,
    const unsigned char[:] in_tkt_service = None,
) -> Creds:
    """Get initial credentials using a key table.

    Requests the KDC for credential using a client key stored in the key table
    specified.

    Args:
        context: Krb5 context.
        client: The client principal the credentials are for.
        keytab: The keytab to use when getting the credential.
        k5_gic_options: The initial credentials options.
        start_time: Time when the ticket becomes valid, 0 for now.
        in_tkt_service: The service name of the initial credentials.

    Returns:
        Creds: The retrieved credentials.
    """
    creds = Creds(context)
    cdef krb5_error_code err = 0

    cdef const char *in_tkt_service_ptr = NULL
    if in_tkt_service is not None and len(in_tkt_service):
        in_tkt_service_ptr = <const char*>&in_tkt_service[0]

    with nogil:
        err = krb5_get_init_creds_keytab(
            context.raw,
            &creds.raw,
            client.raw,
            keytab.raw,
            start_time,
            in_tkt_service_ptr,
            k5_gic_options.raw,
        )

    if err:
        raise Krb5Error(context, err)

    creds.needs_free = 1

    return creds


def get_init_creds_password(
    Context context not None,
    Principal client not None,
    const unsigned char[:] password,
    GetInitCredsOpt k5_gic_options not None,
    int start_time = 0,
    const unsigned char[:] in_tkt_service = None,
    prompter: typing.Optional[typing.Callable[
        typing.Optional[bytes], typing.Optional[bytes], typing.List[Krb5Prompt]], typing.List[bytes]
    ] = None
) -> Creds:
    """Get initial credential using a password.

    Requests the KDC for credentials using a password.

    Args:
        context: Krb5 context.
        client: The client principal the credentials are for.
        password: The password to use - set to ``None`` to use the prompter.
        k5_gic_options: The initial credentials options.
        start_time: Time when the ticket becomes valid, 0 for now.
        in_tkt_service: The service name of the initial credentials.
        prompter: The callable used to prompt for the password.

    Returns:
        Creds: The retrieved credentials.
    """
    creds = Creds(context)
    cdef krb5_error_code err = 0

    cdef const char *password_ptr = NULL
    if password is not None and len(password):
        password_ptr = <const char*>&password[0]

    cdef void *prompt_data = NULL
    if prompter is not None:
        prompt_data = <void*>prompter

    cdef const char *in_tkt_service_ptr = NULL
    if in_tkt_service is not None and len(in_tkt_service):
        in_tkt_service_ptr = <const char*>&in_tkt_service[0]

    with nogil:
        err = krb5_get_init_creds_password(
            context.raw,
            &creds.raw,
            client.raw,
            password_ptr,
            prompt_callback,
            prompt_data,
            start_time,
            in_tkt_service_ptr,
            k5_gic_options.raw,
        )

    if err:
        raise Krb5Error(context, err)

    creds.needs_free = 1

    return creds
