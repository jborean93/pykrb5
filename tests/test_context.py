# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import time

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


def test_set_real_time() -> None:
    ctx = krb5.init_context()

    diff = krb5.timeofday(ctx) - time.time()
    assert diff > -5
    assert diff < 5

    now = krb5.us_timeofday(ctx)
    diff = now[0] * 1000000 + now[1] - int(time.time() * 1e6)
    assert diff > -5000000
    assert diff < 5000000

    krb5.set_real_time(ctx, int(time.time()) + 100, 0)
    diff = krb5.timeofday(ctx) - time.time()
    assert diff > 95
    assert diff < 105

    krb5.set_real_time(ctx, int(time.time()), -1)
    diff = krb5.timeofday(ctx) - time.time()
    assert diff > -5
    assert diff < 5


@pytest.mark.requires_api("get_time_offsets")
def test_get_time_offsets() -> None:
    ctx = krb5.init_context()

    sec, usec = krb5.get_time_offsets(ctx)
    assert sec == 0
    assert usec == 0

    krb5.set_real_time(ctx, int(time.time()) + 100, 0)
    sec, usec = krb5.get_time_offsets(ctx)
    assert sec > 95
    assert sec < 105

    krb5.set_real_time(ctx, int(time.time()), -1)
    sec, usec = krb5.get_time_offsets(ctx)
    assert sec > -5
    assert sec < 5


@pytest.mark.requires_api("init_secure_context")
def test_init_secure_context() -> None:
    context = krb5.init_secure_context()
    assert context is not None
    assert isinstance(context, krb5.Context)
    assert str(context) == "Krb5Context"
