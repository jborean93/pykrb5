# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

import k5test
import pytest

import krb5


def test_get_init_creds_keytab(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.host_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    kt = krb5.kt_default(ctx)

    creds = krb5.get_init_creds_keytab(ctx, princ, kt, opt)
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"


def test_get_init_creds_password(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)

    creds = krb5.get_init_creds_password(ctx, princ, realm.password("user").encode(), opt)
    assert isinstance(creds, krb5.Creds)
    assert str(creds) == "Creds"


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
