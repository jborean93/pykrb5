# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import os.path
import pathlib

import k5test
import pytest

import krb5


def test_cc_default(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_default(ctx)
    assert isinstance(cc, krb5.CCache)
    assert isinstance(cc.addr, int)
    assert cc.name == realm.ccache.encode()
    assert cc.cache_type == b"FILE"
    assert isinstance(cc.principal, krb5.Principal)
    assert str(cc.principal) == realm.user_princ

    assert repr(cc) == f"CCache(cache_type=FILE, name={realm.ccache})"
    assert str(cc) == f"FILE:{realm.ccache}"


def test_cc_default_name(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    actual = krb5.cc_default_name(ctx)
    assert actual == realm.ccache.encode()


def test_cc_destroy(tmpdir: pathlib.Path) -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_resolve(ctx, f"FILE:{tmpdir / 'ccache'}".encode())
    krb5.cc_initialize(ctx, cc, krb5.parse_name_flags(ctx, b"name@REALM"))
    assert os.path.isfile(tmpdir / "ccache")

    krb5.cc_destroy(ctx, cc)
    assert not os.path.exists(tmpdir / "ccache")
    assert repr(cc) == "CCache(NULL)"
    assert str(cc) == "NULL"
    assert cc.cache_type is None
    assert cc.name is None
    assert cc.principal is None


def test_cc_get_name(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    file_cc = krb5.cc_resolve(ctx, f"FILE:{tmp_path / 'ccache'}".encode())
    assert krb5.cc_get_name(ctx, file_cc) == f"{tmp_path / 'ccache'}".encode()

    mem_cc = krb5.cc_new_unique(ctx, b"MEMORY")
    assert krb5.cc_get_name(ctx, mem_cc) == mem_cc.name


def test_cc_get_principal() -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, cc, krb5.parse_name_flags(ctx, b"name@REALM"))
    assert isinstance(cc.principal, krb5.Principal)
    assert str(cc.principal) == "name@REALM"


def test_cc_get_type(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    file_cc = krb5.cc_resolve(ctx, f"FILE:{tmp_path / 'ccache'}".encode())
    assert krb5.cc_get_type(ctx, file_cc) == b"FILE"

    mem_cc = krb5.cc_new_unique(ctx, b"MEMORY")
    assert krb5.cc_get_type(ctx, mem_cc) == b"MEMORY"


def test_cc_initialize(tmpdir: pathlib.Path) -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_resolve(ctx, f"FILE:{tmpdir / 'ccache'}".encode())
    assert not os.path.exists(tmpdir / "ccache")

    krb5.cc_initialize(ctx, cc, krb5.parse_name_flags(ctx, b"name@REALM"))
    assert os.path.isfile(tmpdir / "ccache")


def test_cc_new_unique() -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    assert isinstance(cc, krb5.CCache)
    assert cc.cache_type == b"MEMORY"
    assert isinstance(cc.name, bytes)
    assert str(cc) == f"MEMORY:{cc.name.decode()}"
    assert repr(cc) == f"CCache(cache_type={cc.cache_type.decode()}, name={cc.name.decode()})"

    with pytest.raises(krb5.Krb5Error):
        cc.principal


def test_cc_resolve(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_resolve(ctx, f"FILE:{tmp_path / 'ccache'}".encode())
    assert isinstance(cc, krb5.CCache)
    assert cc.cache_type == b"FILE"
    assert cc.name == f"{tmp_path / 'ccache'}".encode()
    assert str(cc) == f"FILE:{tmp_path / 'ccache'}"
    assert repr(cc) == f"CCache(cache_type=FILE, name={tmp_path / 'ccache'})"

    with pytest.raises(krb5.Krb5Error):
        cc.principal


def test_cc_store_cred(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    creds = krb5.get_init_creds_password(ctx, princ, opt, realm.password("user").encode())

    cc = krb5.cc_resolve(ctx, f"{tmp_path / 'ccache'}".encode())
    krb5.cc_initialize(ctx, cc, princ)
    krb5.cc_store_cred(ctx, cc, creds)
    assert os.path.isfile(tmp_path / "ccache")


@pytest.mark.requires_api("cc_dup")
def test_cc_dup() -> None:
    ctx = krb5.init_context()

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, cc, krb5.parse_name_flags(ctx, b"user@REALM"))
    cc_name = cc.name
    cc_addr = cc.addr

    copied_cc = krb5.cc_dup(ctx, cc)
    del cc
    assert isinstance(copied_cc, krb5.CCache)
    assert copied_cc.cache_type == b"MEMORY"
    assert copied_cc.name == cc_name
    assert str(copied_cc.principal) == "user@REALM"
    assert copied_cc.addr != cc_addr
