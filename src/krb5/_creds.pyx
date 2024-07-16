# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import enum
import typing

from krb5._exceptions import Krb5Error
from krb5._keyblock import copy_keyblock
from krb5._principal import copy_principal

from libc.stdlib cimport calloc, free

from krb5._ccache cimport CCache
from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._keyblock cimport KeyBlock
from krb5._krb5_types cimport *
from krb5._kt cimport KeyTab
from krb5._principal cimport Principal


cdef extern from "python_krb5.h":
    """
    void pykrb5_creds_get(
        krb5_creds *creds,
        krb5_principal *client,
        krb5_principal *server,
        krb5_keyblock **keyblock,
        pykrb5_ticket_times *times,
        uint32_t *ticket_flags_raw,
        uint32_t *ticket_flags,
        // krb5_address ***addresses,
        krb5_data *ticket,
        krb5_data *second_ticket
        // krb5_authdata ***authdata,
    )
    {
        if (client != NULL) *client = creds->client;
        if (server != NULL) *server = creds->server;
#if defined(HEIMDAL_XFREE)
        if (keyblock != NULL) *keyblock = &creds->session;
#else
        if (keyblock != NULL) *keyblock = &creds->keyblock;
#endif
        if (times != NULL) *times = creds->times;
#if defined(HEIMDAL_XFREE)
        if (ticket_flags_raw != NULL) *ticket_flags_raw = creds->flags.i;
        if (ticket_flags != NULL) *ticket_flags = creds->flags.i;
#else
        if (ticket_flags_raw != NULL) *ticket_flags_raw = creds->ticket_flags;
        if (ticket_flags != NULL) {
            *ticket_flags = 0;
            // Reverse the order of the bits to get the first bit in the
            // lowermost bit instead of in the uppermost bit.
            for (int i = 0; i < 32; i++) {
                if (creds->ticket_flags & (1 << (31 - i))) *ticket_flags |= (1 << i);
            }
        }
#endif
        // if (addresses != NULL) *addresses = creds->addresses;
        if (ticket != NULL) *ticket = creds->ticket;
        if (second_ticket != NULL) *second_ticket = creds->second_ticket;
        // if (authdata != NULL) *authdata = creds->authdata;
    }
    """

    void pykrb5_creds_get(
        krb5_creds *creds,
        krb5_principal *client,
        krb5_principal *server,
        krb5_keyblock **keyblock,
        pykrb5_ticket_times *times,
        uint32_t *ticket_flags_raw,
        uint32_t *ticket_flags,
        # krb5_address ***addresses,
        krb5_data *ticket,
        krb5_data *second_ticket,
        # krb5_authdata ***authdata,
    ) nogil

    void krb5_free_creds(
        krb5_context context,
        krb5_creds *val,
    ) nogil

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

    krb5_error_code krb5_get_renewed_creds(
        krb5_context context,
        krb5_creds *creds,
        krb5_principal client,
        krb5_ccache ccache,
        const char *in_tkt_service,
    ) nogil


class TicketFlags(enum.IntFlag):
    # https://github.com/krb5/krb5-assignments/blob/master/ticket-flags
    reserved = 1 << 0
    forwardable = 1 << 1
    forwarded = 1 << 2
    proxiable = 1 << 3
    proxy = 1 << 4
    may_postdate = 1 << 5
    postdated = 1 << 6
    invalid = 1 << 7
    renewable = 1 << 8
    initial = 1 << 9
    pre_authent = 1 << 10
    hw_authent = 1 << 11
    transited_policy_checked = 1 << 12
    ok_as_delegate = 1 << 13
    enc_pa_rep = 1 << 15
    anonymous = 1 << 16

    # This is to prevent python >= 3.11 from clearing unknown flags when doing:
    # flags = flags & ~TicketFlags.forwarded
    # (Under python 3.11, ~TicketFlags.forwarded will contain only known flags.)
    _all_flags = (1 << 32) - 1


cdef class Creds:
    # cdef Context ctx
    # cdef int free_contents
    # cdef krb5_creds* _raw
    # cdef int _free_raw

    def __cinit__(Creds self, Context context):
        self.ctx = context
        self.free_contents = 0
        self._raw = NULL
        self._free_raw = 0

    def __dealloc__(Creds self):
        if not self._raw:
            return

        if self._free_raw:
            if self.free_contents:
                krb5_free_cred_contents(self.ctx.raw, self._raw)
                self.free_contents = 0
            free(self._raw)

        else:
            krb5_free_creds(self.ctx.raw, self._raw)

        self._raw = NULL
        self._free_raw = 0

    def __str__(Creds self) -> str:
        return "Creds"

    cdef void* set_raw_from_lib(Creds self, krb5_creds* raw):
        # This is called when the krb5_creds* was allocated by the krb5 lib.
        # We set the internal state so it calls krb5_free_creds properly on
        # deallocation.
        if self._raw:
            # This should never occur but it's here just in case
            raise ValueError("Cannot set raw pointer on already initialized Creds")

        self._raw = raw
        self._free_raw = 0

    cdef krb5_creds *get_pointer(Creds self):
        # If this is being called without _raw being set we want to manage
        # the krb5_creds object in this class.
        if not self._raw:
            self._raw = <krb5_creds*>calloc(sizeof(krb5_creds), 1)
            if not self._raw:
                raise MemoryError("Cannot calloc krb5_creds")
            self._free_raw = 1

        return self._raw

    @property
    def client(Creds self) -> Principal:
        princ = Principal(self.ctx, 0, needs_free=0)
        pykrb5_creds_get(self.get_pointer(), &princ.raw, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

        # Create a copy of the principal to make sure the returned value
        # remains valid even if the Creds object is destroyed
        princ_copy = copy_principal(self.ctx, princ)

        return princ_copy

    @property
    def server(Creds self) -> Principal:
        princ = Principal(self.ctx, 0, needs_free=0)
        pykrb5_creds_get(self.get_pointer(), NULL, &princ.raw, NULL, NULL, NULL, NULL, NULL, NULL)

        # Create a copy of the principal to make sure the returned value
        # remains valid even if the Creds object is destroyed
        princ_copy = copy_principal(self.ctx, princ)

        return princ_copy

    @property
    def keyblock(Creds self) -> KeyBlock:
        kb = KeyBlock(self.ctx, needs_free=0)
        pykrb5_creds_get(self.get_pointer(), NULL, NULL, &kb.raw, NULL, NULL, NULL, NULL, NULL)

        # Create a copy of the keyblock to make sure the returned value
        # remains valid even if the Creds object is destroyed
        kb_copy = copy_keyblock(self.ctx, kb)

        return kb_copy

    @property
    def times(Creds self) -> TicketTimes:
        cdef pykrb5_ticket_times times
        pykrb5_creds_get(self.get_pointer(), NULL, NULL, NULL, &times, NULL, NULL, NULL, NULL)

        return TicketTimes(times.authtime, times.starttime, times.endtime, times.renew_till)

    @property
    def ticket_flags_raw(Creds self) -> int:
        cdef uint32_t flags_raw
        pykrb5_creds_get(self.get_pointer(), NULL, NULL, NULL, NULL, &flags_raw, NULL, NULL, NULL)

        return flags_raw

    @property
    def ticket_flags(Creds self) -> TicketFlags:
        cdef uint32_t flags
        pykrb5_creds_get(self.get_pointer(), NULL, NULL, NULL, NULL, NULL, &flags, NULL, NULL)

        return TicketFlags(flags)

    @property
    def ticket(Creds self) -> bytes:
        cdef krb5_data ticket
        pykrb5_creds_get(self.get_pointer(), NULL, NULL, NULL, NULL, NULL, NULL, &ticket, NULL)

        cdef size_t length
        cdef char *value
        pykrb5_get_krb5_data(&ticket, &length, &value)

        if length == 0:
            return b""
        else:
            return value[:length]

    @property
    def second_ticket(Creds self) -> bytes:
        cdef krb5_data second_ticket
        pykrb5_creds_get(self.get_pointer(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, &second_ticket)

        cdef size_t length
        cdef char *value
        pykrb5_get_krb5_data(&second_ticket, &length, &value)

        if length == 0:
            return b""
        else:
            return value[:length]

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
) noexcept with gil:
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
    cdef krb5_creds* raw_creds = creds.get_pointer()

    cdef const char *in_tkt_service_ptr = NULL
    if in_tkt_service is not None and len(in_tkt_service):
        in_tkt_service_ptr = <const char*>&in_tkt_service[0]

    with nogil:
        err = krb5_get_init_creds_keytab(
            context.raw,
            raw_creds,
            client.raw,
            keytab.raw,
            start_time,
            in_tkt_service_ptr,
            k5_gic_options.raw,
        )

    if err:
        raise Krb5Error(context, err)

    creds.free_contents = 1

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
    cdef krb5_creds* raw_creds = creds.get_pointer()

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
            raw_creds,
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

    creds.free_contents = 1

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

    err = krb5_init_creds_get_creds(context.raw, ctx.raw, creds.get_pointer())
    if err:
        raise Krb5Error(context, err)

    creds.free_contents = 1
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

def get_renewed_creds(
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

    err = krb5_get_renewed_creds(
        context.raw,
        creds.get_pointer(),
        client.raw,
        ccache.raw,
        in_tkt_service_ptr,
    )
    if err:
        raise Krb5Error(context, err)

    creds.free_contents = 1

    return creds

TicketTimes = collections.namedtuple('TicketTimes', [
    'authtime',
    'starttime',
    'endtime',
    'renew_till',
])
