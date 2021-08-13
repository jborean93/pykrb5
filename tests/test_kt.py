# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pathlib

import k5test
import pytest

import krb5


def test_kt_default(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_default(ctx)
    assert isinstance(kt, krb5.KeyTab)
    assert isinstance(kt.addr, int)
    assert kt.name == realm.keytab.encode()
    assert kt.kt_type == b"FILE"

    assert repr(kt) == f"KeyTab(kt_type=FILE, name={realm.keytab})"
    assert str(kt) == f"FILE:{realm.keytab}"


def test_kt_default_name(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    actual = krb5.kt_default_name(ctx)
    assert actual == realm.keytab.encode()


def test_kt_get_name(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    actual = krb5.kt_get_name(ctx, kt)

    if realm.provider == "mit":
        assert actual == f"FILE:{tmp_path / 'keytab'}".encode()
    else:
        assert actual == f"{tmp_path / 'keytab'}".encode()


def test_kt_get_full_name(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    assert krb5.kt_get_full_name(ctx, kt) == f"FILE:{tmp_path / 'keytab'}".encode()


def test_kt_get_type(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    assert krb5.kt_get_type(ctx, kt) == b"FILE"


def test_kt_resolve(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    assert isinstance(kt, krb5.KeyTab)
    assert kt.kt_type == b"FILE"
    assert kt.name == f"{tmp_path / 'keytab'}".encode()
    assert str(kt) == f"FILE:{tmp_path / 'keytab'}"
    assert repr(kt) == f"KeyTab(kt_type=FILE, name={tmp_path / 'keytab'})"


@pytest.mark.requires_api("kt_client_default")
def test_kt_client_default(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_client_default(ctx)
    assert isinstance(kt, krb5.KeyTab)
    assert isinstance(kt.addr, int)
    assert kt.name == realm.client_keytab.encode()
    assert kt.kt_type == b"FILE"

    assert repr(kt) == f"KeyTab(kt_type=FILE, name={realm.client_keytab})"
    assert str(kt) == f"FILE:{realm.client_keytab}"


@pytest.mark.requires_api("kt_dup")
def test_kt_dup(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    kt_name = kt.name
    kt_addr = kt.addr

    copied_kt = krb5.kt_dup(ctx, kt)
    del kt
    assert isinstance(copied_kt, krb5.KeyTab)
    assert copied_kt.kt_type == b"FILE"
    assert copied_kt.name == kt_name
    assert copied_kt.addr != kt_addr
