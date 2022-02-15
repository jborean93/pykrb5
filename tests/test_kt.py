# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import copy
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


def test_kt_enumerate(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())

    msg_pattern = "Key table file '.*' not found" if realm.provider == "mit" else "No such file or directory"
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        list(kt)

    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    key_block = krb5.init_keyblock(ctx, 17, b"\x00" * 16)
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, key_block)

    entries = list(kt)
    assert len(entries) == 1
    assert entries[0].principal.name == b"user@DOMAIN.COM"
    assert entries[0].kvno == 1
    assert isinstance(entries[0].timestamp, int)
    copied_princ = copy.copy(entries[0].principal)

    krb5.kt_remove_entry(ctx, kt, entries[0])
    del entries[0]

    entries = list(kt)
    assert entries == []

    # Tests that the copied principal outlives the kt/entry
    del kt
    assert copied_princ.name == b"user@DOMAIN.COM"


def test_kt_get_entry_empty(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")

    msg_pattern = "Key table file '.*' not found" if realm.provider == "mit" else "No such file or directory"
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_get_entry(ctx, kt, princ)


def test_kt_get_entry(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    key_block = krb5.init_keyblock(ctx, 17, b"\xff" * 16)
    assert key_block.enctype == 17
    assert key_block.data == b"\xff" * 16

    krb5.kt_add_entry(ctx, kt, princ, 1, 0, key_block)

    entry = krb5.kt_get_entry(ctx, kt, princ)
    assert entry.principal.name == princ.name
    assert entry.kvno == 1
    assert entry.key.enctype == 17
    assert entry.key.data == key_block.data

    krb5.kt_remove_entry(ctx, kt, entry)
    assert list(kt) == []

    msg_pattern = "No key table entry found" if realm.provider == "mit" else "Failed to find .* in keytab .*"
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_get_entry(ctx, kt, princ)


def test_kt_get_entry_multiple_kvno(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    key_block = krb5.init_keyblock(ctx, 17, b"\x00" * 16)
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, key_block)
    krb5.kt_add_entry(ctx, kt, princ, 2, 0, key_block)

    entry = krb5.kt_get_entry(ctx, kt, princ)
    assert entry.principal.name == princ.name
    assert entry.kvno == 2

    entry = krb5.kt_get_entry(ctx, kt, princ, kvno=1)
    assert entry.principal.name == princ.name
    assert entry.kvno == 1

    msg_pattern = (
        "Key version number for principal in key table is incorrect"
        if realm.provider == "mit"
        else "Failed to find .* in keytab .*"
    )
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_get_entry(ctx, kt, princ, kvno=3)


def test_kt_get_entry_multiple_enctype(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, krb5.init_keyblock(ctx, 17, b"\x00" * 16))
    krb5.kt_add_entry(ctx, kt, princ, 2, 0, krb5.init_keyblock(ctx, 18, b"\x00" * 32))

    entry = krb5.kt_get_entry(ctx, kt, princ)
    assert entry.principal.name == princ.name
    assert entry.kvno == 2
    assert entry.key.enctype == 18

    entry = krb5.kt_get_entry(ctx, kt, princ, enctype=17)
    assert entry.principal.name == princ.name
    assert entry.kvno == 1
    assert entry.key.enctype == 17

    msg_pattern = "No key table entry found" if realm.provider == "mit" else "Failed to find .* in keytab .*"
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_get_entry(ctx, kt, princ, enctype=16)


def test_kt_read_service_key_empty(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")

    msg_pattern = "Key table file '.*' not found" if realm.provider == "mit" else "No such file or directory"
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_read_service_key(ctx, kt.name, princ)


def test_kt_read_service_key(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    key_block = krb5.init_keyblock(ctx, 17, b"\xff" * 16)
    assert key_block.enctype == 17
    assert key_block.data == b"\xff" * 16

    krb5.kt_add_entry(ctx, kt, princ, 1, 0, key_block)

    key = krb5.kt_read_service_key(ctx, kt.name, princ)
    assert key.enctype == 17
    assert key.data == b"\xff" * 16


def test_kt_read_service_key_multiple_kvno(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, krb5.init_keyblock(ctx, 17, b"\x00" * 16))
    krb5.kt_add_entry(ctx, kt, princ, 2, 0, krb5.init_keyblock(ctx, 18, b"\x11" * 32))

    key = krb5.kt_read_service_key(ctx, kt.name, princ)
    assert key.enctype == 18
    assert key.data == b"\x11" * 32

    key = krb5.kt_read_service_key(ctx, kt.name, princ, kvno=1)
    assert key.enctype == 17
    assert key.data == b"\x00" * 16

    msg_pattern = (
        "Key version number for principal in key table is incorrect"
        if realm.provider == "mit"
        else "Failed to find .* in keytab .*"
    )
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_read_service_key(ctx, kt.name, princ, kvno=3)


def test_kt_read_service_key_multiple_enctype(realm: k5test.K5Realm, tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, krb5.init_keyblock(ctx, 17, b"\x00" * 16))
    krb5.kt_add_entry(ctx, kt, princ, 2, 0, krb5.init_keyblock(ctx, 18, b"\x11" * 32))

    key = krb5.kt_read_service_key(ctx, kt.name, princ)
    assert key.enctype == 18
    assert key.data == b"\x11" * 32

    key = krb5.kt_read_service_key(ctx, kt.name, princ, enctype=17)
    assert key.enctype == 17
    assert key.data == b"\x00" * 16

    msg_pattern = "No key table entry found" if realm.provider == "mit" else "Failed to find .* in keytab .*"
    with pytest.raises(krb5.Krb5Error, match=msg_pattern):
        krb5.kt_read_service_key(ctx, kt.name, princ, enctype=16)


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


@pytest.mark.requires_api("kt_have_content")
def test_kt_have_content(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()

    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())

    assert krb5.kt_have_content(ctx, kt) is False

    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    key_block = krb5.init_keyblock(ctx, 17, b"\x00" * 16)
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, key_block)

    assert krb5.kt_have_content(ctx, kt)

    entry = list(kt)[0]
    krb5.kt_remove_entry(ctx, kt, entry)

    assert krb5.kt_have_content(ctx, kt) is False
