# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import typing

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *
from krb5._kt cimport KeyTab
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    void krb5_free_cred_contents(
        krb5_context context,
        krb5_creds *val,
    ) nogil

    krb5_error_code krb5_init_creds_get(
        krb5_context context,
        krb5_init_creds_context ctx,
    ) nogil

    krb5_error_code krb5_init_creds_get_creds(
        krb5_context context,
        krb5_init_creds_context ctx,
        krb5_creds *creds,
    ) nogil

    krb5_error_code krb5_init_creds_init(
        krb5_context context,
        krb5_principal client,
        krb5_prompter_fct prompert,
        void *data,
        krb5_deltat start_time,
        krb5_get_init_creds_opt *options,
        krb5_init_creds_context *ctx,
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

    void krb5_init_creds_free(
        krb5_context context,
        krb5_init_creds_context ctx,
    ) nogil

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

    krb5_error_code krb5_init_creds_set_keytab(
        krb5_context context,
        krb5_init_creds_context ctx,
        krb5_keytab keytab,
    ) nogil

    krb5_error_code krb5_init_creds_set_password(
        krb5_context context,
        krb5_init_creds_context ctx,
        const char *password,
    ) nogil


cdef class Creds:
    # cdef Context ctx
    # cdef krb5_creds raw
    # cdef int needs_free

    def __cinit__(Creds self, Context context):
        self.ctx = context
        self.needs_free = 0

    def __dealloc__(Creds self):
        if self.needs_free:
            krb5_free_cred_contents(self.ctx.raw, &self.raw)
            self.needs_free = 0

    def __str__(Creds self) -> str:
        return "Creds"


cdef class InitCredsContext:
    # cdef Context ctx
    # cdef krb5_init_creds_context raw

    def __cinit__(InitCredsContext self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(InitCredsContext self):
        if self.raw:
            krb5_init_creds_free(self.ctx.raw, self.raw)
            self.raw = NULL

    def __str__(InitCredsContext self) -> str:
        return "InitCredsContext"


cdef class Krb5Prompt:
    def init(
        self,
        name: typing.Optional[bytes],
        banner: typing.Optional[bytes],
        num_prompts: int,
    ) -> None:
        pass

    def prompt(
        self,
        msg: bytes,
        hidden: bool,
    ) -> bytes:
        raise NotImplementedError()


cdef krb5_error_code prompt_callback(
    krb5_context context,
    void *data,
    const char *name,
    const char *banner,
    int num_prompts,
    krb5_prompt *prompts,
) with gil:
    try:
        prompter = <Krb5Prompt>data

        py_name = None if name == NULL else <bytes>name
        py_banner = None if banner == NULL else <bytes>banner
        prompter.init(py_name, py_banner, num_prompts)

        replies = []
        for prompt in prompts[:num_prompts]:
            msg = <bytes>prompt.prompt
            hidden = prompt.hidden != 0

            reply = prompter.prompt(msg, hidden)
            if not isinstance(reply, bytes):
                return 1

            replies.append(reply)

        for idx, reply in enumerate(replies):
            pykrb5_set_krb5_data(prompts[idx].reply, len(reply), <char *>reply)

        return 0

    except Exception:
        return 1


def get_init_creds_keytab(
    Context context not None,
    Principal client not None,
    GetInitCredsOpt k5_gic_options not None,
    KeyTab keytab not None,
    int start_time = 0,
    const unsigned char[:] in_tkt_service = None,
) -> Creds:
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
    GetInitCredsOpt k5_gic_options not None,
    const unsigned char[:] password = None,
    int start_time = 0,
    const unsigned char[:] in_tkt_service = None,
    prompter: typing.Optional[Krb5Prompt] = None,
) -> Creds:
    creds = Creds(context)
    cdef krb5_error_code err = 0

    cdef const char *password_ptr = NULL
    if password is not None and len(password):
        password_ptr = <const char*>&password[0]

    cdef krb5_prompter_fct callback = NULL
    cdef void *prompt_data = NULL
    if prompter is not None:
        callback = prompt_callback
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
            callback,
            prompt_data,
            start_time,
            in_tkt_service_ptr,
            k5_gic_options.raw,
        )

    if err:
        raise Krb5Error(context, err)

    creds.needs_free = 1

    return creds


def init_creds_get(
    Context context not None,
    InitCredsContext ctx not None,
) -> None:
    cdef krb5_error_code err = 0

    with nogil:
        err = krb5_init_creds_get(context.raw, ctx.raw)

    if err:
        raise Krb5Error(context, err)


def init_creds_get_creds(
    Context context not None,
    InitCredsContext ctx not None,
) -> Creds:
    creds = Creds(context)
    cdef krb5_error_code err = 0

    err = krb5_init_creds_get_creds(context.raw, ctx.raw, &creds.raw)
    if err:
        raise Krb5Error(context, err)

    creds.needs_free = 1
    return creds


def init_creds_init(
    Context context not None,
    Principal client not None,
    GetInitCredsOpt k5_gic_options = None,
    int start_time = 0,
    prompter: typing.Optional[Krb5Prompt] = None,
) -> InitCredsContext:
    creds_ctx = InitCredsContext(context)
    cdef krb5_error_code err = 0

    cdef krb5_get_init_creds_opt *options = NULL
    if k5_gic_options:
        options = k5_gic_options.raw

    cdef krb5_prompter_fct callback = NULL
    cdef void *prompt_data = NULL
    if prompter is not None:
        callback = prompt_callback
        prompt_data = <void*>prompter

    with nogil:
        err = krb5_init_creds_init(
            context.raw,
            client.raw,
            callback,
            prompt_data,
            start_time,
            options,
            &creds_ctx.raw
        )

    if err:
        raise Krb5Error(context, err)

    return creds_ctx


def init_creds_set_keytab(
    Context context not None,
    InitCredsContext ctx not None,
    KeyTab keytab not None,
) -> None:
    cdef krb5_error_code err = 0

    err = krb5_init_creds_set_keytab(context.raw, ctx.raw, keytab.raw)
    if err:
        raise Krb5Error(context, err)


def init_creds_set_password(
    Context context not None,
    InitCredsContext ctx not None,
    const unsigned char[:] password,
) -> None:
    cdef krb5_error_code err = 0

    cdef const char *password_ptr = NULL
    if password is not None and len(password):
        password_ptr = <const char*>&password[0]
    else:
        raise ValueError("password must be set")

    err = krb5_init_creds_set_password(context.raw, ctx.raw, password_ptr)
    if err:
        raise Krb5Error(context, err)
