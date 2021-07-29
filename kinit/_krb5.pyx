import collections
import enum
import typing

from libc.stdlib cimport malloc

from kinit._krb5_types cimport *


cdef extern from "krb5.h":
    const char *krb5_get_error_message(
        krb5_context ctx,
        krb5_error_code code,
    ) nogil

    void krb5_free_error_message(
        krb5_context ctx,
        const char *msg,
    ) nogil

    krb5_error_code krb5_init_context(
        krb5_context *context,
    ) nogil

    void krb5_free_context(
        krb5_context context,
    ) nogil

    krb5_error_code krb5_parse_name_flags(
        krb5_context context,
        const char *name,
        int flags,
        krb5_principal *principal_out,
    ) nogil

    void krb5_free_principal(
        krb5_context context,
        krb5_principal val,
    ) nogil

    krb5_error_code krb5_cc_default(
        krb5_context context,
        krb5_ccache *cache,
    ) nogil

    krb5_error_code krb5_cc_new_unique(
        krb5_context context,
        const char *type,
        const char *hint,
        krb5_ccache *id,
    ) nogil

    krb5_error_code krb5_cc_close(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    const char *krb5_cc_get_name(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_alloc(
        krb5_context context,
        krb5_get_init_creds_opt **opt,
    ) nogil

    void krb5_get_init_creds_opt_free(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
    ) nogil

    void krb5_get_init_creds_opt_set_forwardable(
        krb5_get_init_creds_opt *opt,
        int forwardable,
    ) nogil

    krb5_error_code krb5_get_init_creds_opt_set_out_ccache(
        krb5_context context,
        krb5_get_init_creds_opt *opt,
        krb5_ccache ccache,
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

    void krb5_free_cred_contents(
        krb5_context context,
        krb5_creds *val,
    ) nogil


cdef class Krb5Context:
    # cdef krb5_context raw

    def __cinit__(Krb5Context self):
        self.raw = NULL

    def __dealloc__(Krb5Context self):
        if self.raw:
            with nogil:
                krb5_free_context(self.raw)
            self.raw = NULL


cdef class Krb5Principal:
    # cdef Krb5Context ctx
    # cdef krb5_principal raw

    def __cinit__(Krb5Principal self, Krb5Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(Krb5Principal self):
        if self.raw:
            with nogil:
                krb5_free_principal(self.ctx.raw, self.raw)
            self.raw = NULL


cdef class Krb5CCache:
    # cdef Krb5Context ctx
    # cdef krb5_ccache raw

    def __cinit__(Krb5CCache self, Krb5Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(Krb5CCache self):
        if self.raw:
            with nogil:
                krb5_cc_close(self.ctx.raw, self.raw)
            self.raw = NULL

    @property
    def name(self) -> typing.Optional[bytes]:
        if self.raw:
            return krb5_cc_get_name(self.ctx.raw, self.raw)


cdef class Krb5GetInitCredsOpt:
    # cdef Krb5Context ctx
    # cdef krb5_get_init_creds_opt *raw

    def __cinit__(Krb5GetInitCredsOpt self, Krb5Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(Krb5GetInitCredsOpt self):
        if self.raw:
            with nogil:
                krb5_get_init_creds_opt_free(self.ctx.raw, self.raw)
            self.raw = NULL


cdef class Krb5Creds:
    # cdef Krb5Context ctx
    # cdef krb5_creds raw
    # cdef int needs_free

    def __cinit__(Krb5CCache self, Krb5Context context):
        self.ctx = context
        self.needs_free = 0

    def __dealloc__(Krb5CCache self):
        if self.needs_free:
            with nogil:
                krb5_free_cred_contents(self.ctx.raw, &self.raw)
            self.needs_free = 0


Krb5Prompt = collections.namedtuple("Krb5Prompt", ["msg", "hidden"])


class PrincipalParseFlags(enum.IntEnum):
    none = 0
    no_realm = KRB5_PRINCIPAL_PARSE_NO_REALM
    require_realm = KRB5_PRINCIPAL_PARSE_REQUIRE_REALM
    enterprise = KRB5_PRINCIPAL_PARSE_ENTERPRISE
    ignore_realm = KRB5_PRINCIPAL_PARSE_IGNORE_REALM


cdef str get_error_message(
    krb5_context ctx,
    krb5_error_code err,
):
    cdef char *err_msg = NULL

    err_msg = krb5_get_error_message(ctx, err)
    try:
        msg = err_msg.decode('utf-8')
        return f"{msg} {err}"

    finally:
        with nogil:
            krb5_free_error_message(ctx, err_msg)


def init_context() -> Krb5Context:
    context = Krb5Context()
    cdef krb5_error_code err = 0

    with nogil:
        krb5_init_context(&context.raw)

    return context


def parse_name_flags(
    Krb5Context context not None,
    const unsigned char[:] name not None,
    flags: PrincipalParseFlags = PrincipalParseFlags.none,
) -> Krb5Principal:
    principal = Krb5Principal(context)
    cdef int raw_flags = flags.value
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if name is not None and len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("Principal must be set")

    with nogil:
        err = krb5_parse_name_flags(context.raw, name_ptr, raw_flags, &principal.raw)

    if err:
        raise Exception(get_error_message(context.raw, err))

    return principal


def cc_default(
    Krb5Context context not None,
) -> Krb5CCache:
    ccache = Krb5CCache(context)
    cdef krb5_error_code err = 0

    with nogil:
        err = krb5_cc_default(context.raw, &ccache.raw)

    if err:
        raise Exception(get_error_message(context.raw, err))

    return ccache


def cc_new_unique(
    Krb5Context context not None,
    const unsigned char[:] cred_type not None,
    const unsigned char[:] hint = None,
) -> Krb5CCache:
    ccache = Krb5CCache(context)
    cdef krb5_error_code err = 0

    cdef const char *hint_ptr = NULL
    if hint is not None and len(hint):
        hint_ptr = <const char*>&hint[0]

    with nogil:
        err = krb5_cc_new_unique(context.raw, <const char*>&cred_type[0], hint_ptr, &ccache.raw)

    if err:
        raise Exception(get_error_message(context.raw, err))

    return ccache


def get_init_creds_opt_alloc(
    Krb5Context context not None,
) -> Krb5GetInitCredsOpt:
    opt = Krb5GetInitCredsOpt(context)
    cdef krb5_error_code err = 0

    with nogil:
        err = krb5_get_init_creds_opt_alloc(context.raw, &opt.raw)

    if err:
        raise Exception(get_error_message(context.raw, err))

    return opt


def get_init_creds_opt_set_forwardable(
    Krb5GetInitCredsOpt opt not None,
    forwardable: bool,
) -> None:
    cdef int value = 1 if forwardable else 0

    krb5_get_init_creds_opt_set_forwardable(opt.raw, value)


def get_init_creds_opt_set_out_ccache(
    Krb5Context context not None,
    Krb5GetInitCredsOpt opt not None,
    Krb5CCache ccache not None,
) -> None:
    cdef krb5_error_code err = 0

    with nogil:
        err = krb5_get_init_creds_opt_set_out_ccache(context.raw, opt.raw, ccache.raw)

    if err:
        raise Exception(get_error_message(context.raw, err))


def get_init_creds_password(
    Krb5Context context not None,
    Krb5Principal client not None,
    const unsigned char[:] password,
    Krb5GetInitCredsOpt k5_gic_options not None,
    int start_time = 0,
    const unsigned char[:] in_tkt_service = None,
    prompter: typing.Optional[typing.Callable[
        typing.Optional[bytes], typing.Optional[bytes], typing.List[Krb5Prompt]], typing.List[bytes]
    ] = None
) -> Krb5Creds:
    creds = Krb5Creds(context)
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
        raise Exception(get_error_message(context.raw, err))

    return creds


cdef krb5_error_code prompt_callback(
    krb5_context context,
    void *data,
    const char *name,
    const char *banner,
    int num_prompts,
    krb5_prompt *prompts,
) with gil:
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
