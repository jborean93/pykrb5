# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

import krb5


def test_init_keyblock_empty() -> None:
    ctx = krb5.init_context()
    kb = krb5.init_keyblock(ctx, 0, None)

    assert len(kb) == 0
    assert kb.enctype == 0
    assert kb.data == b""
    assert str(kb) == "KeyBlock 0"
    assert repr(kb) == "KeyBlock(enctype=0, length=0)"


def test_init_keyblock_data() -> None:
    ctx = krb5.init_context()
    kb = krb5.init_keyblock(ctx, 17, b"\xff" * 16)

    assert len(kb) == 16
    assert kb.enctype == 17
    assert kb.data == b"\xff" * 16
    assert str(kb) == "KeyBlock 17"
    assert repr(kb) == "KeyBlock(enctype=17, length=16)"


@pytest.mark.requires_api("c_string_to_key")
def test_c_string_to_key() -> None:
    ctx = krb5.init_context()

    salt = b"EXAMPLE.COMtestuser"
    password = b"Some Password"

    kb = krb5.c_string_to_key(ctx, 17, salt, password)
    assert kb.enctype == 17
    assert len(kb) == 16
    assert kb.data == b"\xd2\x153\xcd\xd9\x7fR\xe6\x11U]7\xac\x12[\xf6"

    kb = krb5.c_string_to_key(ctx, 17, salt, password, b"\x00\x00\x10\x00")
    assert kb.enctype == 17
    assert len(kb) == 16
    assert kb.data == b"\xd2\x153\xcd\xd9\x7fR\xe6\x11U]7\xac\x12[\xf6"

    kb = krb5.c_string_to_key(ctx, 18, salt, password, b"\x00\x00\x10\x00")
    assert kb.enctype == 18
    assert len(kb) == 32
    assert kb.data == b"\x0b\x12\x05\xb0\xc4\xe7\x0e\xf1\xbf\xf5\xeaJ\x1a\x80?~@m\x7f\xcakPk\x08\xa6\x99\x15\xd6s\r&("

    kb = krb5.c_string_to_key(ctx, 18, salt, password, b"\x00\x01\x23\x45")
    assert kb.enctype == 18
    assert len(kb) == 32
    assert (
        kb.data
        == b"\x11\xcc\x10\x0e\xff$\xc1SL^d\x00\xe2\x83\x08\xefxM\x12\x92\x18:\x1c\x9b\xd2w\xf5\xfd\xb9\x13\xe5\xd1"
    )
