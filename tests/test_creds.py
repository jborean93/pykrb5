# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import time
import typing

import k5test
import pytest

import krb5


class MockPrompt(krb5.Krb5Prompt):
    def __init__(self, responses: typing.List[bytes]) -> None:
        self.init_calls: typing.List[typing.Tuple[typing.Optional[bytes], typing.Optional[bytes], int]] = []
        self.prompt_calls: typing.List[typing.Tuple[bytes, bool]] = []
        self._responses = responses

    def init(
        self,
        name: typing.Optional[bytes],
        banner: typing.Optional[bytes],
        num_prompts: int,
    ) -> None:
        self.init_calls.append((name, banner, num_prompts))

    def prompt(self, msg: bytes, hidden: bool) -> bytes:
        self.prompt_calls.append((msg, hidden))
        return self._responses.pop(0)


def test_get_init_creds_keytab(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.host_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    kt = krb5.kt_default(ctx)

    creds = krb5.get_init_creds_keytab(ctx, princ, opt, kt)
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"

    assert creds.client.name == realm.host_princ.encode()
    assert creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"
    assert len(creds.keyblock.data) > 0
    assert str(creds.times).startswith("TicketTimes(authtime=")
    # creds.ticket_flags
    # creds.addresses
    assert len(creds.ticket) > 0
    assert creds.second_ticket == b""
    # creds.authdata


def test_get_init_creds_password(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)

    creds = krb5.get_init_creds_password(ctx, princ, opt, realm.password("user").encode())
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"


def test_get_init_creds_password_prompt(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    prompter = MockPrompt([realm.password("user").encode()])

    creds = krb5.get_init_creds_password(ctx, princ, opt, prompter=prompter)
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"

    assert len(prompter.init_calls) == 1
    assert prompter.init_calls[0] == (None, None, 1)
    assert len(prompter.prompt_calls) == 1

    expected = (
        f"Password for {realm.user_princ}" if realm.provider == "mit" else f"{realm.user_princ}'s Password: "
    ).encode()
    assert prompter.prompt_calls[0] == (expected, True)


def test_get_init_creds_password_prompt_failure(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    prompter = MockPrompt([])

    with pytest.raises(krb5.Krb5Error):
        krb5.get_init_creds_password(ctx, princ, opt, prompter=prompter)

    assert len(prompter.init_calls) == 1
    assert prompter.init_calls[0] == (None, None, 1)
    assert len(prompter.prompt_calls) == 1


def test_get_creds_keytab(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.host_princ.encode())
    creds_ctx = krb5.init_creds_init(ctx, princ)

    assert isinstance(creds_ctx, krb5.InitCredsContext)
    assert str(creds_ctx) == "InitCredsContext"

    kt = krb5.kt_resolve(ctx, realm.keytab.encode())
    krb5.init_creds_set_keytab(ctx, creds_ctx, kt)
    krb5.init_creds_get(ctx, creds_ctx)

    creds = krb5.init_creds_get_creds(ctx, creds_ctx)
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"


def test_get_creds_keytab_wrong_principal(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    creds_ctx = krb5.init_creds_init(ctx, princ)

    assert isinstance(creds_ctx, krb5.InitCredsContext)
    assert str(creds_ctx) == "InitCredsContext"

    kt = krb5.kt_resolve(ctx, realm.keytab.encode())

    expected = "no suitable keys for" if realm.provider == "mit" else "Failed to find"
    with pytest.raises(krb5.Krb5Error, match=expected):
        krb5.init_creds_set_keytab(ctx, creds_ctx, kt)


def test_init_creds_set_password(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    creds_ctx = krb5.init_creds_init(ctx, princ)

    assert isinstance(creds_ctx, krb5.InitCredsContext)
    assert str(creds_ctx) == "InitCredsContext"

    krb5.init_creds_set_password(ctx, creds_ctx, realm.password("user").encode())
    krb5.init_creds_get(ctx, creds_ctx)

    creds = krb5.init_creds_get_creds(ctx, creds_ctx)
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"


def test_init_creds_set_password_invalid(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    creds_ctx = krb5.init_creds_init(ctx, princ)

    assert isinstance(creds_ctx, krb5.InitCredsContext)
    assert str(creds_ctx) == "InitCredsContext"

    krb5.init_creds_set_password(ctx, creds_ctx, b"invalid")

    # Too many different error messages - just expect an error
    with pytest.raises(krb5.Krb5Error):
        krb5.init_creds_get(ctx, creds_ctx)


def test_renew_creds(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    # Ask for a renewable ticket
    krb5.get_init_creds_opt_set_renew_life(opt, 1024)
    creds = krb5.get_init_creds_password(ctx, princ, opt, realm.password("user").encode())

    assert creds.client.name == realm.user_princ.encode()
    assert creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, cc, princ)
    krb5.cc_store_cred(ctx, cc, creds)

    new_creds = krb5.get_renewed_creds(ctx, creds.client, cc)
    assert new_creds.client.name == realm.user_princ.encode()
    assert new_creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"

    new_creds = krb5.get_renewed_creds(ctx, creds.client, cc, b"krbtgt/KRBTEST.COM@KRBTEST.COM")
    assert new_creds.client.name == realm.user_princ.encode()
    assert new_creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"


@pytest.mark.requires_api("get_validated_creds")
def test_validate_creds(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    # Get postdated ticket, ticket will be valid after 1s
    creds = krb5.get_init_creds_password(ctx, princ, opt, realm.password("user").encode(), start_time=1)
    # Ticket flags for creds should have TKT_FLG_POSTDATED and TKT_FLG_INVALID set

    assert creds.client.name == realm.user_princ.encode()
    assert creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, cc, princ)
    krb5.cc_store_cred(ctx, cc, creds)

    start_time = time.time()
    while True:
        try:
            new_creds = krb5.get_validated_creds(ctx, creds.client, cc)
            break
        except krb5.Krb5Error as e:
            # Retry within the first 5s when the error is
            # KRB5KRB_AP_ERR_TKT_NYV ("Ticket not yet valid"). The ticket should
            # normally be valid after 0-1s.
            if (time.time() - start_time < 5) and e.err_code == -1765328351:
                # Retry
                time.sleep(0.1)
            else:
                raise
    assert new_creds.client.name == realm.user_princ.encode()
    assert new_creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"
    # Ticket flags for new_creds should have TKT_FLG_POSTDATED set and TKT_FLG_INVALID cleared

    new_creds = krb5.get_validated_creds(ctx, creds.client, cc, b"krbtgt/KRBTEST.COM@KRBTEST.COM")
    assert new_creds.client.name == realm.user_princ.encode()
    assert new_creds.server.name == b"krbtgt/KRBTEST.COM@KRBTEST.COM"
    # Ticket flags for new_creds should have TKT_FLG_POSTDATED set and TKT_FLG_INVALID cleared
