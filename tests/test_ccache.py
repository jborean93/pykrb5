# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import os.path
import pathlib
import sys

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
    assert list(cc) == []
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
    assert list(cc) == []


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
    assert len(list(cc)) > 0


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


def test_cc_set_default_name() -> None:
    ctx = krb5.init_context()
    default_name = krb5.cc_default_name(ctx)

    princ = krb5.parse_name_flags(ctx, b"user@REALM")
    assert princ.name is not None

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_set_default_name(ctx, b"MEMORY:" + (cc.name or b""))
    assert krb5.cc_default_name(ctx) == b"MEMORY:" + (cc.name or b"")

    krb5.cc_initialize(ctx, cc, princ)
    actual_cc = krb5.cc_default(ctx)
    assert actual_cc.cache_type == b"MEMORY"
    assert actual_cc.name == cc.name
    assert actual_cc.principal is not None
    assert actual_cc.principal.name == princ.name

    krb5.cc_set_default_name(ctx, None)
    assert krb5.cc_default_name(ctx) == default_name


def test_cc_switch(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    # Heimdal has a bug where it thinks the sub collection ccache doesn't start with tkt (even when it does). I believe
    # this has been fixed but there are no releases of Heimdal that would contain this bugfix so we skip the test.
    # https://github.com/heimdal/heimdal/commit/7bf4d76e75e904dd65a0fbb90c9cad981245f714
    if realm.provider.lower() == "heimdal":
        pytest.skip("Doesnt work on macOS (no DIR support) and current Heimdal releases have a bug")

    ctx = krb5.init_context()
    admin_princ = krb5.parse_name_flags(ctx, realm.admin_princ.encode())
    user_princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())

    admin_ccache = krb5.cc_resolve(ctx, b"DIR:" + bytes(tmp_path))
    krb5.cc_initialize(ctx, admin_ccache, admin_princ)

    user_ccache = krb5.cc_resolve(ctx, b"DIR::" + bytes(tmp_path / "tkt-user"))
    krb5.cc_initialize(ctx, user_ccache, user_princ)

    krb5.cc_switch(ctx, user_ccache)

    actual = krb5.cc_resolve(ctx, b"DIR:" + bytes(tmp_path))
    assert actual.cache_type == b"DIR"
    assert actual.name == b":" + bytes(tmp_path / "tkt-user")
    assert actual.principal
    assert actual.principal.name == user_princ.name
    assert list(actual) == []

    krb5.cc_switch(ctx, admin_ccache)

    actual = krb5.cc_resolve(ctx, b"DIR:" + bytes(tmp_path))
    assert actual.cache_type == b"DIR"
    assert actual.name == b":" + bytes(tmp_path / "tkt")
    assert actual.principal
    assert actual.principal.name == admin_princ.name
    assert list(actual) == []


@pytest.mark.requires_api("cc_support_switch")
def test_cc_supports_switch_invalid_type() -> None:
    with pytest.raises(ValueError, match="cache_type cannot be an empty byte string"):
        krb5.cc_support_switch(krb5.init_context(), b"")


@pytest.mark.parametrize(
    "cache_type, expected",
    [
        (b"FILE", False),
        # macOS doesn't support the DIR type so this returns False
        (b"DIR", False if sys.platform == "darwin" else True),
    ],
    ids=["FILE", "DIR"],
)
@pytest.mark.requires_api("cc_support_switch")
def test_cc_supports_switch(cache_type: bytes, expected: bool) -> None:
    actual = krb5.cc_support_switch(krb5.init_context(), cache_type)
    assert actual is expected


@pytest.mark.requires_api("cc_cache_match")
def test_cc_cache_match(realm: k5test.K5Realm, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Heimdal has a bug trying to iterate through a DIR collection ccache. This has been fixed on the master branch but
    # there are no releases that would contain this bugfix so we skip the test.
    # https://github.com/heimdal/heimdal/commit/7bf4d76e75e904dd65a0fbb90c9cad981245f714
    if realm.provider.lower() == "heimdal":
        pytest.skip("Doesnt work on macOS (no DIR support) and current Heimdal releases have a bug")

    monkeypatch.setenv("KRB5CCNAME", "DIR:" + str(tmp_path))
    ctx = krb5.init_context()
    admin_princ = krb5.parse_name_flags(ctx, realm.admin_princ.encode())
    user_princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)

    admin_ccache = krb5.cc_default(ctx)
    krb5.cc_initialize(ctx, admin_ccache, admin_princ)
    admin_creds = krb5.get_init_creds_password(ctx, admin_princ, opt, realm.password("admin").encode())
    krb5.cc_store_cred(ctx, admin_ccache, admin_creds)

    user_ccache = krb5.cc_resolve(ctx, b"DIR::" + bytes(tmp_path) + b"/tkt-user")
    krb5.cc_initialize(ctx, user_ccache, user_princ)
    user_creds = krb5.get_init_creds_password(ctx, user_princ, opt, realm.password("user").encode())
    krb5.cc_store_cred(ctx, user_ccache, user_creds)

    admin_actual = krb5.cc_cache_match(ctx, admin_princ)
    assert admin_actual.cache_type == b"DIR"
    assert admin_actual.name == b":" + bytes(tmp_path) + b"/tkt"
    assert admin_actual.principal
    assert admin_actual.principal.name == admin_princ.name

    user_actual = krb5.cc_cache_match(ctx, user_princ)
    assert user_actual.cache_type == b"DIR"
    assert user_actual.name == b":" + bytes(tmp_path) + b"/tkt-user"
    assert user_actual.principal
    assert user_actual.principal.name == user_princ.name
