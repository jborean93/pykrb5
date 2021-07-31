# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

import k5test
import pytest

import krb5


def test_init_context() -> None:
    context = krb5.init_context()
    assert context is not None
    assert isinstance(context, krb5.Context)
    assert str(context) == "Krb5Context"


def test_set_default_realm(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    default = krb5.get_default_realm(ctx)
    assert default == realm.realm.encode()

    krb5.set_default_realm(ctx, b"NEW.REALM")
    default = krb5.get_default_realm(ctx)
    assert default == b"NEW.REALM"

    krb5.set_default_realm(ctx, None)
    default = krb5.get_default_realm(ctx)
    assert default == realm.realm.encode()


@pytest.mark.requires_api("init_secure_context")
def test_init_secure_context() -> None:
    context = krb5.init_secure_context()
    assert context is not None
    assert isinstance(context, krb5.Context)
    assert str(context) == "Krb5Context"
